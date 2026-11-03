#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
############################################################################
#
# This file is part of the collectd 'Precision Time Protocol' Service Monitor.
#
############################################################################

import collectd
import configparser
from dataclasses import dataclass
from dataclasses import field
import gps
import time
import traceback

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = "ptp plugin"

GPSD_TCP_PORT = "2947"

# Upper bound, in seconds, on how long a single gpsd read is allowed to run.
# gps.gps() is an unbounded blocking iterator: when the receiver has no fix it
# keeps streaming TPV/SKY reports indefinitely, and -- worse -- its __next__()
# blocks inside a socket read with no deadline of its own, so if gpsd goes
# quiet mid-read the iterator never returns. Because this read runs inside the
# single collectd python.ptp read thread, an unbounded read stalls the whole
# plugin for minutes, blowing the 30s read interval and starving every other
# PTP instance's state/clockClass refresh. get_gps_data() wraps the live
# session in _bounded_session(), which uses gps.waiting()/read() so the socket
# is only ever waited on in GPSD_READ_POLL_STEP_SECONDS slices and the deadline
# is honoured even when no report arrives. get_gps_data_by_session() keeps an
# independent deadline guard at the top of its loop as a defence in depth (and
# so the bound is exercised by the unit tests, which drive it with plain
# iterables). A read that times out returns what it has gathered so far
# (fail-safe: lock_state stays 0), to be retried on the next poll.
GPSD_READ_TIMEOUT_SECONDS = 5

# Granularity of the socket wait inside _bounded_session(). Small enough that
# the effective overshoot past GPSD_READ_TIMEOUT_SECONDS is sub-second, large
# enough to avoid a busy spin.
GPSD_READ_POLL_STEP_SECONDS = 0.5


@dataclass
class SignalQualityDb:
    min: float = 0
    max: float = 0
    avg: float = 0


@dataclass
class GpsData:
    gpsd_running: int = 0
    lock_state: int = 0
    satellite_count: int = 0
    signal_quality_db: SignalQualityDb = field(default_factory=SignalQualityDb)


def parse_gnss_monitor_config(config_file_path):
    # https://docs.python.org/3/library/configparser.html
    # You can access the parameters like so:
    # config['global']['parameter_name']
    config = configparser.ConfigParser(delimiters=" ")
    config.read(config_file_path)
    return config


def set_nmea_device(device_path):
    # Put GPS into NMEA mode
    # Equivalent to: gpsctl --nmea <device_path>
    #
    # gpsd daemon changes GPS device to binary mode, and the device output is no
    # longer NMEA sentence. This function can be used to revert back to NMEA mode
    # before shutting down gpsd daemon.
    #
    # This function is for reference purpose and has not been used yet.
    try:
        session = gps.gps(host="localhost", port=GPSD_TCP_PORT)
    except Exception as exc:
        message = (
            f"{PLUGIN} Could not connect to localhost:{GPSD_TCP_PORT} error: {exc}"
        )
        collectd.error(message)
        return
    device_command = (
        '?DEVICE={"path":"' + device_path + '", "driver": "NMEA0183", "native": 0}'
    )
    session.send(device_command)
    message = f"{PLUGIN} {device_path} set to driver:NMEA0183 and native:0"
    collectd.info(message)
    session.close()


def get_device_paths(devices):
    # Input: [{'class': 'DEVICE', 'path': '/dev/gnss0', ..}]
    # Where path is optional
    device_paths = []
    for device_dict in devices:
        if "path" in device_dict:
            device_paths.append(device_dict["path"])
    return device_paths


def trunc(num, precision):
    x = 10 ** precision
    return int(num * x) / x


def get_signal_to_noise_ratio(satellites):
    # Input: [{'PRN': 5, 'el': 31.0, 'az': 86.0, 'ss': 45.0, 'used': True, 'gnssid': 0,
    # 'svid': 5, 'health': 1},..]
    # ss is optional key, Signal to Noise ratio in dBHz
    # used key is always present, satellites may be flagged used if the solution has
    # corrections from them, but not all drivers make this information available
    snr = SignalQualityDb(min=0, max=0, avg=0)
    signal_to_noise_data = []
    for satellite in satellites:
        if satellite["used"] and "ss" in satellite:
            signal_to_noise_data.append(satellite["ss"])
    if signal_to_noise_data:
        snr.min = min(signal_to_noise_data)
        snr.max = max(signal_to_noise_data)
        snr.avg = trunc(sum(signal_to_noise_data) / len(signal_to_noise_data), 3)
    return snr


def get_gps_data_by_session(session, device_path):
    # Details are in:
    # https://gpsd.io/client-howto.html#_how_the_gpsd_wire_protocol_works
    # https://gpsd.gitlab.io/gpsd/gpsd_json.html
    data = GpsData(
        gpsd_running=1,
        lock_state=0,
        satellite_count=0,
        signal_quality_db=SignalQualityDb(min=0, max=0, avg=0),
    )
    try:
        # - TPV and SKY report are independent information and could come in any order.
        # - A GPS receiver might have satellite visibility data (a SKY report) but still not
        #   be able to calculate a usable position, hence sending a TPV report with mode: 0.
        # - SKY report won't follow TPV, when GPS receiver is not functional.
        tpv_report_scanned = False
        sky_report_scanned = False
        # Bound the read so a receiver with no fix (which streams reports
        # endlessly) or a device for which no matching report ever arrives
        # cannot block this loop indefinitely. gps.gps() has no deadline of its
        # own, so we enforce one here with a monotonic clock.
        deadline = time.monotonic() + GPSD_READ_TIMEOUT_SECONDS
        for report in session:
            if time.monotonic() >= deadline:
                message = (
                    f"{PLUGIN} {device_path} gpsd read timed out after "
                    f"{GPSD_READ_TIMEOUT_SECONDS}s; returning partial data: {data}"
                )
                collectd.warning(message)
                break
            if report["class"] in ["VERSION", "WATCH", "DEVICE"]:
                continue
            elif report["class"] == "DEVICES" and device_path not in get_device_paths(
                report["devices"]
            ):
                message = f"{PLUGIN} {device_path} is not being monitored by GPSD"
                collectd.error(message)
                break
            # device key is optional in TPV class
            elif (
                report["class"] == "TPV"
                and "device" in report
                and report["device"] == device_path
            ):
                # mode is always present on TPV class.
                # NMEA mode: 0=unknown, 1=no fix, 2=2D, 3=3D.
                # Until the sensor achieves satellite lock, the fixes (reports) will be
                # "mode 1" - no valid data (mode 2 is a 2D fix, mode 3 is a 3D fix).
                if report["mode"] in [0, 1]:
                    message = f"{PLUGIN} {device_path} have not achieved satellite lock: {report}"
                    collectd.debug(message)
                    data.lock_state = 0
                    # Do not change satellite_count and signal_quality_db in case
                    # SKY already scanned
                    break
                else:
                    data.lock_state = 1
                    if sky_report_scanned and data.satellite_count > 0:
                        break

                # Set TPV report scanned flag
                tpv_report_scanned = True

            # device key is optional in SKY class
            elif (
                report["class"] == "SKY"
                and "device" in report
                and report["device"] == device_path
            ):
                # In gpsd >= 3.25, multiple SKY reports may be emitted per
                # cycle (one per GNSS constellation). Only some contain the
                # uSat and satellites fields. Only update our data when the
                # fields are present — never zero out a previously good value.
                if "uSat" in report:
                    data.satellite_count = report["uSat"]
                if "satellites" in report:
                    snr = get_signal_to_noise_ratio(report["satellites"])
                    # Only update if we got actual data (avoid overwriting
                    # a good reading with an empty constellation report).
                    if snr.avg > 0 or data.signal_quality_db.avg == 0:
                        data.signal_quality_db = snr

                # All reports collected, No more polling required.
                # Only break if we have meaningful satellite data, since
                # gpsd 3.25 may send empty constellation reports first.
                if tpv_report_scanned and data.satellite_count > 0:
                    break

                # Set SKY report scanned flag
                sky_report_scanned = True

    except Exception as exc:
        # In case of parsing error, should be reported instead of throwing exception
        message = f"{PLUGIN} Programming error occured: {type(exc)}:{exc}"
        collectd.error(message)
        collectd.error(traceback.format_exc())
        data = GpsData(
            gpsd_running=1,
            lock_state=0,
            satellite_count=0,
            signal_quality_db=SignalQualityDb(min=0, max=0, avg=0),
        )

    return data


def _bounded_session(session, timeout_seconds=GPSD_READ_TIMEOUT_SECONDS,
                     poll_step_seconds=GPSD_READ_POLL_STEP_SECONDS):
    """Yield gpsd reports from a live gps.gps() session under a hard deadline.

    The stock gps.gps() iterator calls read(), which blocks inside a socket
    read with no timeout; if gpsd stops sending (e.g. a receiver with no fix),
    __next__() never returns and the caller hangs. This generator instead polls
    the socket with waiting(), which is a select() with a timeout, so control
    returns at least every poll_step_seconds and the monotonic deadline is
    always enforced. It stops once the deadline passes, on disconnect
    (read() < 0), or on a read error, letting the consumer return whatever it
    has gathered so far.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        # waiting() is select()-based; returns False if no data arrived within
        # the slice, in which case we loop and re-check the deadline.
        if not session.waiting(poll_step_seconds):
            continue
        try:
            status = session.read()
        except Exception as exc:
            collectd.error(f"{PLUGIN} gpsd read() failed: {type(exc)}:{exc}")
            return
        if status is not None and status < 0:
            # Negative status == error/disconnect from gpsd.
            return
        report = getattr(session, "data", None)
        if report:
            yield report


def get_gps_data(device_path):
    # Whenever there is client connection, only then gpsd polls
    # on serial devices, otherwise it won't keep looking for sensor
    # data to save energy. So here we are opening and closing client
    # connection, and not keeping session open forever.
    # Here we also ask to WATCH per device
    try:
        session = gps.gps(host="localhost", port=GPSD_TCP_PORT)
    except Exception as exc:
        message = (
            f"{PLUGIN} Could not connect to localhost:{GPSD_TCP_PORT} error: {exc}"
        )
        collectd.error(message)
        return GpsData(
            gpsd_running=0,
            lock_state=0,
            satellite_count=0,
            signal_quality_db=SignalQualityDb(min=0, max=0, avg=0),
        )

    # Use a single stream() call with combined flags and device path.
    # In gpsd >= 3.25 (Debian Trixie), calling stream() multiple times
    # overwrites the previous configuration rather than augmenting it.
    # Combining WATCH_ENABLE | WATCH_JSON with devpath in one call works
    # correctly on both gpsd 3.22 (Bullseye) and 3.25 (Trixie).
    session.stream(
        flags=gps.WATCH_ENABLE | gps.WATCH_JSON | gps.WATCH_DEVICE,
        devpath=device_path,
    )

    # Iterate the session through _bounded_session() rather than directly, so a
    # quiet or endlessly-streaming gpsd (no-fix receiver) cannot block this read
    # -- and therefore the whole python.ptp plugin -- past the deadline.
    data = get_gps_data_by_session(_bounded_session(session), device_path)

    session.close()
    return data
