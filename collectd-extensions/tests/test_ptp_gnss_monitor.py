#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

# bypass 'import collectd' as it's C-based daemon, and cannot be directly imported.
mock_collectd = sys.modules.setdefault("collectd", MagicMock())
sys.modules.setdefault("gps", MagicMock())
from src import ptp_gnss_monitor as ptp_monitoring


class TestPtpMonitoring(unittest.TestCase):
    def setUp(self):
        mock_collectd.reset_mock()

    def test_parse_monitoring_config(self):
        config_file_path = (
            "./tests/test_input_files/gnss-monitor-ptp.conf"
        )

        expected_devices = "/dev/gnss0 /dev/gnss1"
        expected_satellite_count = "12"
        expected_signal_quality_db = "30"

        config = ptp_monitoring.parse_gnss_monitor_config(config_file_path)
        self.assertEqual(config["global"]["devices"], expected_devices)
        self.assertEqual(config["global"]["satellite_count"], expected_satellite_count)
        self.assertEqual(
            config["global"]["signal_quality_db"], expected_signal_quality_db
        )

    def test_get_gps_data_by_session_empty_devices(self):
        device_path = "/dev/gnss0"
        session = [
            {
                "class": "VERSION",
                "release": "3.22",
                "rev": "3.22",
                "proto_major": 3,
                "proto_minor": 14,
            },
            {"class": "DEVICES", "devices": []},
            {
                "class": "WATCH",
                "enable": True,
                "json": True,
                "nmea": False,
                "raw": 0,
                "scaled": False,
                "timing": False,
                "split24": False,
                "pps": False,
            },
        ]
        data = ptp_monitoring.get_gps_data_by_session(session, device_path)
        expected_data = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=0,
            satellite_count=0,
            signal_quality_db=ptp_monitoring.SignalQualityDb(min=0, max=0, avg=0),
        )
        expected_error_log = (
            f"{ptp_monitoring.PLUGIN} {device_path} is not being monitored by GPSD"
        )
        mock_collectd.error.assert_called_with(expected_error_log)
        self.assertEqual(
            data,
            expected_data,
            msg=f"actual {data} not equal to expected {expected_data} ",
        )

    def test_get_gps_data_by_session_mode_1(self):
        # NMEA mode: 0=unknown, 1=no fix, 2=2D, 3=3D.
        # Until the sensor achieves satellite lock, the fixes (reports) will be
        # "mode 1" - no valid data
        device_path = "/dev/gnss0"
        session = [
            {
                "class": "VERSION",
                "release": "3.22",
                "rev": "3.22",
                "proto_major": 3,
                "proto_minor": 14,
            },
            {
                "class": "DEVICES",
                "devices": [
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss0",
                        "activated": "2025-06-13T12:52:15.463Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss1",
                        "activated": "2025-06-13T12:52:19.637Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                ],
            },
            {
                "class": "WATCH",
                "enable": True,
                "json": True,
                "nmea": False,
                "raw": 0,
                "scaled": False,
                "timing": False,
                "split24": False,
                "pps": False,
            },
            {
                "class": "DEVICE",
                "path": "/dev/gnss0",
                "driver": "NMEA0183",
                "activated": "2025-06-13T12:52:19.637Z",
                "native": 0,
                "bps": 9600,
                "parity": "N",
                "stopbits": 0,
                "cycle": 1.0,
            },
            {"class": "TPV", "device": "/dev/gnss0", "mode": 1},
            {"class": "TPV", "device": "/dev/gnss0", "mode": 1},
            {"class": "TPV", "device": "/dev/gnss0", "mode": 1},
            {
                "class": "DEVICE",
                "path": "/dev/gnss1",
                "driver": "NMEA0183",
                "activated": "2025-06-13T12:52:20.168Z",
                "native": 0,
                "bps": 9600,
                "parity": "N",
                "stopbits": 0,
                "cycle": 1.0,
            },
            {"class": "TPV", "device": "/dev/gnss1", "mode": 1},
            {
                "class": "DEVICE",
                "path": "/dev/gnss0",
                "driver": "u-blox",
                "subtype": "SW EXT CORE 1.00 (3fda8e),HW 00190000",
                "subtype1": (
                    "ROM BASE 0x118B2060,FWVER=TIM 2.20,PROTVER=29.20,MOD=ZED-F9T,"
                    "GPS;GLO;GAL;BDS,SBAS;QZSS,NAVIC"
                ),
                "activated": "2025-06-13T12:52:20.716Z",
                "flags": 1,
                "native": 1,
                "bps": 9600,
                "parity": "N",
                "stopbits": 0,
                "cycle": 1.0,
                "mincycle": 0.02,
            },
            {"class": "TPV", "device": "/dev/gnss0", "mode": 1},
        ]
        data = ptp_monitoring.get_gps_data_by_session(session, device_path)
        expected_data = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=0,
            satellite_count=0,
            signal_quality_db=ptp_monitoring.SignalQualityDb(min=0, max=0, avg=0),
        )
        expected_debug_log = (
            f"{ptp_monitoring.PLUGIN} {device_path} "
            f"have not achieved satellite lock: {session[4]}"
        )
        mock_collectd.debug.assert_called_with(expected_debug_log)
        self.assertEqual(
            data,
            expected_data,
            msg=f"actual {data} not equal to expected {expected_data} ",
        )

    def test_get_gps_data_by_session_valid(self):
        device_path = "/dev/gnss0"
        session = [
            {
                "class": "VERSION",
                "release": "3.22",
                "rev": "3.22",
                "proto_major": 3,
                "proto_minor": 14,
            },
            {
                "class": "DEVICES",
                "devices": [
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss0",
                        "activated": "2025-06-13T12:52:15.463Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss1",
                        "activated": "2025-06-13T12:52:19.637Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                ],
            },
            {
                "class": "WATCH",
                "enable": True,
                "json": True,
                "nmea": False,
                "raw": 0,
                "scaled": False,
                "timing": False,
                "split24": False,
                "pps": False,
            },
            {
                "class": "DEVICE",
                "path": "/dev/gnss0",
                "driver": "NMEA0183",
                "activated": "2025-06-13T12:52:19.637Z",
                "native": 0,
                "bps": 9600,
                "parity": "N",
                "stopbits": 0,
                "cycle": 1.0,
            },
            {"class": "TPV", "device": "/dev/gnss0", "mode": 2},
            {"class": "TPV", "device": "/dev/gnss0", "mode": 3},
            {
                "class": "SKY",
                "device": "/dev/gnss0",
                "time": "2019-04-10T20:27:52.000Z",
                "xdop": 0.69,
                "ydop": 0.68,
                "vdop": 1.33,
                "tdop": 0.88,
                "hdop": 0.97,
                "gdop": 1.86,
                "pdop": 1.64,
                "nSat": 4,
                "uSat": 3,
                "satellites": [
                    {
                        "PRN": 5,
                        "el": 31.0,
                        "az": 86.0,
                        "ss": 45.2,
                        "used": True,
                        "gnssid": 0,
                        "svid": 5,
                        "health": 1,
                    },
                    {
                        "PRN": 10,
                        "el": 10.0,
                        "az": 278.0,
                        "ss": 40.0,
                        "used": False,
                        "gnssid": 0,
                        "svid": 10,
                        "health": 1,
                    },
                    {
                        "PRN": 13,
                        "el": 44.0,
                        "az": 53.0,
                        "ss": 47.4,
                        "used": True,
                        "gnssid": 0,
                        "svid": 13,
                        "health": 1,
                    },
                    {
                        "PRN": 15,
                        "el": 80.0,
                        "az": 68.0,
                        "ss": 48.8,
                        "used": True,
                        "gnssid": 0,
                        "svid": 15,
                        "health": 1,
                    },
                ],
            },
        ]
        snr = [45.2, 47.4, 48.8]
        avg = sum(snr) / len(snr)
        trunc_avg = int(avg * 1000) / 1000
        expected_signal_quality_db = ptp_monitoring.SignalQualityDb(
            min=min(snr), max=max(snr), avg=trunc_avg
        )
        expected_data = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=1,
            satellite_count=3,
            signal_quality_db=expected_signal_quality_db,
        )

        data = ptp_monitoring.get_gps_data_by_session(session, device_path)
        mock_collectd.assert_not_called()
        self.assertEqual(
            data,
            expected_data,
            msg=f"actual {data} not equal to expected {expected_data} ",
        )

    def test_get_gps_data_by_session_sky_before_tpv_mode_2_valid(self):
        # out of order test: SKY before TPV (with mode:2)
        device_path = "/dev/gnss0"
        session = [
            {
                "class": "VERSION",
                "release": "3.22",
                "rev": "3.22",
                "proto_major": 3,
                "proto_minor": 14,
            },
            {
                "class": "DEVICES",
                "devices": [
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss0",
                        "activated": "2025-06-13T12:52:15.463Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss1",
                        "activated": "2025-06-13T12:52:19.637Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                ],
            },
            {
                "class": "WATCH",
                "enable": True,
                "json": True,
                "nmea": False,
                "raw": 0,
                "scaled": False,
                "timing": False,
                "split24": False,
                "pps": False,
            },
            {
                "class": "DEVICE",
                "path": "/dev/gnss0",
                "driver": "NMEA0183",
                "activated": "2025-06-13T12:52:19.637Z",
                "native": 0,
                "bps": 9600,
                "parity": "N",
                "stopbits": 0,
                "cycle": 1.0,
            },
            {
                "class": "SKY",
                "device": "/dev/gnss0",
                "time": "2019-04-10T20:27:52.000Z",
                "xdop": 0.69,
                "ydop": 0.68,
                "vdop": 1.33,
                "tdop": 0.88,
                "hdop": 0.97,
                "gdop": 1.86,
                "pdop": 1.64,
                "nSat": 4,
                "uSat": 3,
                "satellites": [
                    {
                        "PRN": 5,
                        "el": 31.0,
                        "az": 86.0,
                        "ss": 45.2,
                        "used": True,
                        "gnssid": 0,
                        "svid": 5,
                        "health": 1,
                    },
                    {
                        "PRN": 10,
                        "el": 10.0,
                        "az": 278.0,
                        "ss": 40.0,
                        "used": False,
                        "gnssid": 0,
                        "svid": 10,
                        "health": 1,
                    },
                    {
                        "PRN": 13,
                        "el": 44.0,
                        "az": 53.0,
                        "ss": 47.4,
                        "used": True,
                        "gnssid": 0,
                        "svid": 13,
                        "health": 1,
                    },
                    {
                        "PRN": 15,
                        "el": 80.0,
                        "az": 68.0,
                        "ss": 48.8,
                        "used": True,
                        "gnssid": 0,
                        "svid": 15,
                        "health": 1,
                    },
                ],
            },
            {"class": "TPV", "device": "/dev/gnss0", "mode": 2},
        ]
        snr = [45.2, 47.4, 48.8]
        avg = sum(snr) / len(snr)
        trunc_avg = int(avg * 1000) / 1000
        expected_signal_quality_db = ptp_monitoring.SignalQualityDb(
            min=min(snr), max=max(snr), avg=trunc_avg
        )
        expected_data = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=1,
            satellite_count=3,
            signal_quality_db=expected_signal_quality_db,
        )

        data = ptp_monitoring.get_gps_data_by_session(session, device_path)
        mock_collectd.assert_not_called()
        self.assertEqual(
            data,
            expected_data,
            msg=f"actual {data} not equal to expected {expected_data} ",
        )

    def test_get_gps_data_by_session_sky_before_tpv_mode_1_valid(self):
        # out of order test: SKY before TPV (with mode:1)
        device_path = "/dev/gnss0"
        session = [
            {
                "class": "VERSION",
                "release": "3.22",
                "rev": "3.22",
                "proto_major": 3,
                "proto_minor": 14,
            },
            {
                "class": "DEVICES",
                "devices": [
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss0",
                        "activated": "2025-06-13T12:52:15.463Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                    {
                        "class": "DEVICE",
                        "path": "/dev/gnss1",
                        "activated": "2025-06-13T12:52:19.637Z",
                        "native": 0,
                        "bps": 9600,
                        "parity": "N",
                        "stopbits": 0,
                        "cycle": 1.0,
                    },
                ],
            },
            {
                "class": "WATCH",
                "enable": True,
                "json": True,
                "nmea": False,
                "raw": 0,
                "scaled": False,
                "timing": False,
                "split24": False,
                "pps": False,
            },
            {
                "class": "DEVICE",
                "path": "/dev/gnss0",
                "driver": "NMEA0183",
                "activated": "2025-06-13T12:52:19.637Z",
                "native": 0,
                "bps": 9600,
                "parity": "N",
                "stopbits": 0,
                "cycle": 1.0,
            },
            {
                "class": "SKY",
                "device": "/dev/gnss0",
                "time": "2019-04-10T20:27:52.000Z",
                "xdop": 0.69,
                "ydop": 0.68,
                "vdop": 1.33,
                "tdop": 0.88,
                "hdop": 0.97,
                "gdop": 1.86,
                "pdop": 1.64,
                "nSat": 4,
                "uSat": 3,
                "satellites": [
                    {
                        "PRN": 5,
                        "el": 31.0,
                        "az": 86.0,
                        "ss": 45.2,
                        "used": True,
                        "gnssid": 0,
                        "svid": 5,
                        "health": 1,
                    },
                    {
                        "PRN": 10,
                        "el": 10.0,
                        "az": 278.0,
                        "ss": 40.0,
                        "used": False,
                        "gnssid": 0,
                        "svid": 10,
                        "health": 1,
                    },
                    {
                        "PRN": 13,
                        "el": 44.0,
                        "az": 53.0,
                        "ss": 47.4,
                        "used": True,
                        "gnssid": 0,
                        "svid": 13,
                        "health": 1,
                    },
                    {
                        "PRN": 15,
                        "el": 80.0,
                        "az": 68.0,
                        "ss": 48.8,
                        "used": True,
                        "gnssid": 0,
                        "svid": 15,
                        "health": 1,
                    },
                ],
            },
            {"class": "TPV", "device": "/dev/gnss0", "mode": 1},
        ]
        snr = [45.2, 47.4, 48.8]
        avg = sum(snr) / len(snr)
        trunc_avg = int(avg * 1000) / 1000
        expected_signal_quality_db = ptp_monitoring.SignalQualityDb(
            min=min(snr), max=max(snr), avg=trunc_avg
        )
        expected_data = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=0,
            satellite_count=3,
            signal_quality_db=expected_signal_quality_db,
        )

        data = ptp_monitoring.get_gps_data_by_session(session, device_path)
        mock_collectd.assert_not_called()
        self.assertEqual(
            data,
            expected_data,
            msg=f"actual {data} not equal to expected {expected_data} ",
        )

    def test_get_gps_data_by_session_with_garbage_data(self):
        device_path = "/dev/gnss0"
        session = [
            {
                "GARBAGE-class": "VERSION",
                "release": "3.22",
                "rev": "3.22",
                "proto_major": 3,
                "proto_minor": 14,
            },
        ]
        data = ptp_monitoring.get_gps_data_by_session(session, device_path)
        expected_data = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=0,
            satellite_count=0,
            signal_quality_db=ptp_monitoring.SignalQualityDb(min=0, max=0, avg=0),
        )
        expected_error_log_1 = (
            f"{ptp_monitoring.PLUGIN} Programming error occured: <class 'KeyError'>:'class'"
        )
        expected_error_log_substring_2 = "Traceback (most recent call last)"
        self.assertEqual(mock_collectd.error.call_count, 2)
        call_arg_1 = mock_collectd.error.call_args_list[0].args[0]
        self.assertEqual(call_arg_1, expected_error_log_1)
        call_arg_2 = mock_collectd.error.call_args_list[1].args[0]
        self.assertIn(expected_error_log_substring_2, call_arg_2)
        print(call_arg_2)
        self.assertEqual(
            data,
            expected_data,
            msg=f"actual {data} not equal to expected {expected_data} ",
        )

    def test_gps_data_instance_isolation(self):
        """Test that multiple GpsData instances are independent"""
        # Create first instance
        data1 = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=1,
            satellite_count=5,
            signal_quality_db=ptp_monitoring.SignalQualityDb(min=40.0, max=50.0, avg=45.0),
        )

        # Create second instance
        data2 = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=0,
            satellite_count=3,
            signal_quality_db=ptp_monitoring.SignalQualityDb(min=30.0, max=40.0, avg=35.0),
        )

        # Verify initial values
        self.assertEqual(data1.satellite_count, 5)
        self.assertEqual(data2.satellite_count, 3)
        self.assertEqual(data1.signal_quality_db.avg, 45.0)
        self.assertEqual(data2.signal_quality_db.avg, 35.0)

        # Modify first instance
        data1.satellite_count = 10
        data1.signal_quality_db.avg = 55.0

        # Verify second instance is unaffected
        self.assertEqual(
            data2.satellite_count, 3,
            "data2.satellite_count should remain unchanged"
        )
        self.assertEqual(
            data2.signal_quality_db.avg, 35.0,
            "data2.signal_quality_db.avg should remain unchanged"
        )

        # Verify first instance was modified
        self.assertEqual(data1.satellite_count, 10)
        self.assertEqual(data1.signal_quality_db.avg, 55.0)


class TestGpsdReadTimeout(unittest.TestCase):
    """Verify get_gps_data_by_session cannot block indefinitely.

    gps.gps() is an unbounded blocking iterator; when the receiver has no fix
    it streams reports forever. get_gps_data_by_session() must bound the read
    with a wall-clock deadline so it cannot stall the single collectd
    python.ptp read thread (blowing the 30s read interval). These tests drive
    the function with endless iterators and assert it returns.
    """

    def setUp(self):
        mock_collectd.reset_mock()

    @staticmethod
    def _endless_no_fix_stream(device_path):
        """Simulate a receiver with no fix.

        A never-ending stream of reports that never satisfies a break
        condition (SKY with no satellite data, for a device we are not
        waiting on so no mode-1 TPV break fires).
        """
        while True:
            yield {
                "class": "SKY",
                "device": device_path,
                # No uSat / satellites keys: an empty constellation report,
                # which never trips the "satellite_count > 0" break.
            }

    def test_endless_stream_times_out_and_returns_partial(self):
        """An endless no-fix stream must return instead of hanging.

        Once the deadline is crossed it must yield fail-safe data with
        lock_state == 0.
        """
        device_path = "/dev/gnss0"
        # Make the deadline deterministic: first monotonic() call (deadline
        # computation) returns 0, the next (loop check) returns a value past
        # the configured timeout so the very first iteration times out.
        times = [0, ptp_monitoring.GPSD_READ_TIMEOUT_SECONDS + 1]

        def fake_monotonic():
            return times.pop(0) if times else ptp_monitoring.GPSD_READ_TIMEOUT_SECONDS + 1

        with patch.object(ptp_monitoring.time, "monotonic", side_effect=fake_monotonic):
            data = ptp_monitoring.get_gps_data_by_session(
                self._endless_no_fix_stream(device_path), device_path
            )

        expected_data = ptp_monitoring.GpsData(
            gpsd_running=1,
            lock_state=0,
            satellite_count=0,
            signal_quality_db=ptp_monitoring.SignalQualityDb(min=0, max=0, avg=0),
        )
        self.assertEqual(
            data,
            expected_data,
            msg=f"actual {data} not equal to expected {expected_data} ",
        )
        # The timeout path must log a warning naming the device.
        self.assertTrue(mock_collectd.warning.called)
        warn_arg = mock_collectd.warning.call_args.args[0]
        self.assertIn(device_path, warn_arg)
        self.assertIn("timed out", warn_arg)

    def test_endless_stream_without_mocked_clock_still_returns(self):
        """Belt-and-suspenders check under the real monotonic clock.

        With the real clock, an endless stream must still return within a
        small multiple of the timeout (proves the loop actually terminates,
        not just under a mocked clock).
        """
        device_path = "/dev/gnss0"
        import time as _time

        start = _time.monotonic()
        data = ptp_monitoring.get_gps_data_by_session(
            self._endless_no_fix_stream(device_path), device_path
        )
        elapsed = _time.monotonic() - start

        self.assertEqual(data.lock_state, 0)
        # Must finish shortly after the deadline, never hang.
        self.assertLess(
            elapsed,
            ptp_monitoring.GPSD_READ_TIMEOUT_SECONDS + 5,
            msg=f"read did not terminate promptly (elapsed {elapsed:.2f}s)",
        )

    def test_short_valid_stream_does_not_trip_timeout(self):
        """A normal short stream must not trip the timeout.

        A stream that reaches a valid fix must return the real data and must
        NOT emit a timeout warning (no regression / no spurious warnings on
        the healthy path).
        """
        device_path = "/dev/gnss0"
        session = [
            {"class": "TPV", "device": "/dev/gnss0", "mode": 3},
            {
                "class": "SKY",
                "device": "/dev/gnss0",
                "uSat": 1,
                "satellites": [
                    {
                        "PRN": 5,
                        "el": 31.0,
                        "az": 86.0,
                        "ss": 45.0,
                        "used": True,
                        "gnssid": 0,
                        "svid": 5,
                        "health": 1,
                    },
                ],
            },
        ]
        data = ptp_monitoring.get_gps_data_by_session(session, device_path)
        self.assertEqual(data.lock_state, 1)
        self.assertEqual(data.satellite_count, 1)
        self.assertFalse(
            mock_collectd.warning.called,
            msg="healthy short read should not log a timeout warning",
        )


class _FakeSession:
    """Minimal stand-in for gps.gps() for _bounded_session tests.

    waiting() returns the next value from a scripted list (then False
    forever); read() returns the next status (then 0) and exposes the
    next scripted report as .data, mimicking gps.gps().read().
    """

    def __init__(self, waiting_values=None, reports=None, read_statuses=None):
        self._waiting = list(waiting_values or [])
        self._reports = list(reports or [])
        self._statuses = list(read_statuses or [])
        self.data = None
        self.waiting_calls = 0
        self.read_calls = 0

    def waiting(self, timeout=0):
        self.waiting_calls += 1
        return self._waiting.pop(0) if self._waiting else False

    def read(self):
        self.read_calls += 1
        status = self._statuses.pop(0) if self._statuses else 0
        self.data = self._reports.pop(0) if self._reports else None
        return status


class TestBoundedSession(unittest.TestCase):
    """Tests for _bounded_session().

    _bounded_session() must never block past the deadline, regardless of
    whether gpsd is quiet, disconnects, or streams normally.
    """

    def setUp(self):
        mock_collectd.reset_mock()

    def test_quiet_socket_terminates_at_deadline(self):
        """A quiet socket must terminate the generator at the deadline.

        If waiting() never reports data (quiet gpsd / no fix), the generator
        must stop at the deadline instead of blocking forever -- the exact
        live-lab hang this fix targets.
        """
        session = _FakeSession(waiting_values=[])  # always False
        times = iter([0.0, 0.1, 0.2] + [ptp_monitoring.GPSD_READ_TIMEOUT_SECONDS + 1] * 50)

        def fake_monotonic():
            try:
                return next(times)
            except StopIteration:
                return ptp_monitoring.GPSD_READ_TIMEOUT_SECONDS + 1

        with patch.object(ptp_monitoring.time, "monotonic", side_effect=fake_monotonic):
            reports = list(
                ptp_monitoring._bounded_session(
                    session, timeout_seconds=5, poll_step_seconds=0.01
                )
            )
        self.assertEqual(reports, [])
        # read() must never have been called -- there was never data ready.
        self.assertEqual(session.read_calls, 0)

    def test_disconnect_stops_generator(self):
        """A negative read() status (gpsd disconnect) stops iteration."""
        session = _FakeSession(
            waiting_values=[True, True],
            reports=[{"class": "TPV"}, None],
            read_statuses=[0, -1],
        )
        with patch.object(ptp_monitoring.time, "monotonic", side_effect=lambda: 0.1):
            reports = list(
                ptp_monitoring._bounded_session(
                    session, timeout_seconds=5, poll_step_seconds=0.01
                )
            )
        # First (status 0, has data) is yielded; second (status -1) stops it.
        self.assertEqual(reports, [{"class": "TPV"}])

    def test_normal_reports_are_yielded(self):
        """Reports that arrive before the deadline are yielded in order."""
        session = _FakeSession(
            waiting_values=[True, True],
            reports=[{"class": "TPV", "mode": 3}, {"class": "SKY", "uSat": 4}],
            read_statuses=[0, 0],
        )
        # Advancing clock: 0 seeds the deadline, the next two reads land before
        # it, then jump past the deadline so the loop exits once the two
        # scripted reports are consumed (a constant mock would spin forever
        # since waiting() returns False after its scripted values).
        times = iter([0.0, 0.1, 0.2] + [ptp_monitoring.GPSD_READ_TIMEOUT_SECONDS + 1] * 50)

        def fake_monotonic():
            try:
                return next(times)
            except StopIteration:
                return ptp_monitoring.GPSD_READ_TIMEOUT_SECONDS + 1

        with patch.object(ptp_monitoring.time, "monotonic", side_effect=fake_monotonic):
            reports = list(
                ptp_monitoring._bounded_session(
                    session, timeout_seconds=5, poll_step_seconds=0.01
                )
            )
        self.assertEqual(
            reports,
            [{"class": "TPV", "mode": 3}, {"class": "SKY", "uSat": 4}],
        )

    def test_end_to_end_no_fix_does_not_hang(self):
        """Real monotonic clock plus a quiet session must return promptly.

        Proves the deadline actually fires, not just under a mock.
        """
        import time as _time

        session = _FakeSession(waiting_values=[])  # always False
        start = _time.monotonic()
        reports = list(
            ptp_monitoring._bounded_session(
                session, timeout_seconds=1, poll_step_seconds=0.01
            )
        )
        elapsed = _time.monotonic() - start
        self.assertEqual(reports, [])
        self.assertLess(elapsed, 5, msg=f"generator did not terminate promptly ({elapsed:.2f}s)")
