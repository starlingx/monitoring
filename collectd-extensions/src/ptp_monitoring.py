#
# Copyright (c) 2025 Wind River Systems, Inc.
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
import gps
import traceback

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = "ptp plugin"

GPSD_TCP_PORT = "2947"


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
    signal_quality_db: SignalQualityDb = SignalQualityDb()


def parse_monitoring_config(config_file_path):
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
        for report in session:
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
                    # reset satellite_count and signal_quality_db
                    data.satellite_count = 0
                    data.signal_quality_db = SignalQualityDb(min=0, max=0, avg=0)
                    break
                else:
                    data.lock_state = 1
            # device key is optional in SKY class
            elif (
                report["class"] == "SKY"
                and "device" in report
                and report["device"] == device_path
            ):
                # uSat key is optional in SKY class, Number of satellites used in navigation solution
                if "uSat" in report:
                    data.satellite_count = report["uSat"]
                # satellites key is optional in SKY class, List of satellite objects in skyview
                if "satellites" in report:
                    data.signal_quality_db = get_signal_to_noise_ratio(
                        report["satellites"]
                    )

                # All reports collected, No more polling required.
                break
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

    session.stream(flags=gps.WATCH_JSON)
    session.stream(flags=gps.WATCH_DEVICE, devpath=device_path)

    data = get_gps_data_by_session(session, device_path)

    session.close()
    return data
