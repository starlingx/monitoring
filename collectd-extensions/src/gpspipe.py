#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
############################################################################
#
# This file is part of the collectd 'Precision Time Protocol' Service Monitor.
# This mimics gpspipe cli of gpsd-clients package. There are too many dependent
# packages to be installed for gpsd-clients, so instead of adding too many
# packages, we are creating this python file to mimic gpspipe behaviour.
############################################################################

import argparse
import gps


def nmea_output(host, port, device_path):
    try:
        session = gps.gps(host=host, port=port)
    except Exception as exc:
        message = (
            f"gpspipe: could not connect to gpsd {host}:{port}, {exc}"
        )
        print(message)
        return

    # session.stream() as following didnot work, it still enabling json output instead
    # of nmea output
    # session.stream(flags=gps.WATCH_NMEA)
    # session.stream(flags=gps.WATCH_DEVICE, devpath=device_path)
    # Because of this, here using session.send() and session.read(), which works.

    watch_command = '?WATCH={"enable":true,"json":false,"nmea":true,"raw": 0,"scaled":false,\
            "timing":false,"split24":false,"pps":false,"device":"%s"}' % (device_path)
    session.send(watch_command)
    # When the gpsd daemon terminates, session.read() will return non-zero, and then
    # the loop will terminate
    while 0 == session.read():
        # Each call to session.read() will fill session.response with the message
        # just received from gpsd.
        print(session.response, flush=True)

    session.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='gpspipe - tool to connect to gpsd and \
        retrieve sentences')
    parser.add_argument('-r', '--nmea', type=str, required=True, help='host:port:device \
        Cause NMEA sentences to be output. This may be NMEA, pseudo NMEA built from binary \
        data, or some combination of both.')
    args = parser.parse_args()
    nmea_args = args.nmea.split(":")
    if len(nmea_args) != 3:
        print(f"-r --nmea value {args.nmea} is not in format of host:port:device_path "
              "e.g. localhost:2947:/dev/gnss0")
    else:
        host = nmea_args[0]
        port = nmea_args[1]
        device = nmea_args[2]
        nmea_output(host, port, device)
