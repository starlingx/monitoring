#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import unittest
from unittest.mock import MagicMock

# bypass 'import collectd' as it's C-based daemon, and cannot be directly imported.
sys.modules["collectd"] = mock_collectd = MagicMock()
sys.modules["gps"] = MagicMock()
from src import ptp_gnss_monitor as ptp_monitoring


class TestPtpMonitoring(unittest.TestCase):
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

    def test_get_gps_data_by_session_with_garbase_data(self):
        device_path = "/dev/gnss0"
        session = [
            {
                "GARBASE-class": "VERSION",
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
