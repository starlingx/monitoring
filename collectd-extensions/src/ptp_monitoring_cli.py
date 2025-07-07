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

import sys


class Collectd():
    def info(self, message):
        print(f"Info: {message}")

    def debug(self, message):
        print(f"Debug: {message}")

    def error(self, message):
        print(f"Error: {message}")

# bypass 'import collectd' as it's C-based daemon, and cannot be directly imported.
sys.modules["collectd"] = Collectd()

import ptp_monitoring as pm

if __name__ == "__main__":
    for device_path in ["/dev/gnss0", "/dev/gnss1", "/dev/gnssx"]:
        data = pm.get_gps_data(device_path)
        message = f"{device_path}'s gps_data: {data}"
        print(message)
        # set back to NMEA mode
        # pm.set_nmea_device(device_path)

    ## Program Output:
    # /dev/gnss0's gps_data: GpsData(gpsd_running=1, lock_state=1, satellite_count=9,
    #         signal_quality_db=SignalQualityDb(min=45.0, max=48.0, avg=45.111))
    # /dev/gnss1 have not achieved satellite lock: <dictwrapper: {'class': 'TPV',
    #         'device': '/dev/gnss1', 'mode': 1, 'leapseconds': 18}>
    # /dev/gnss1's gps_data: GpsData(gpsd_running=1, lock_state=0, satellite_count=0,
    #          signal_quality_db=SignalQualityDb(min=0, max=0, avg=0))
    # /dev/gnssx is not being monitored by GPSD
    # /dev/gnssx's gps_data: GpsData(gpsd_running=1, lock_state=0, satellite_count=0,
    #          signal_quality_db=SignalQualityDb(min=0, max=0, avg=0))
