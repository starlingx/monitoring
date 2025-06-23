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
import os
import collectd
import subprocess
from enum import Enum

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = 'ptp plugin'

# Tools used by plugin
ETHTOOL = '/usr/sbin/ethtool'

# Device's sysfs paths
uevent_path = '/sys/class/net/%s/device/uevent'
gnss_path = '/sys/class/net/%s/device/gnss'
switch_id_path = '/sys/class/net/%s/phys_switch_id'
gnrd_switch_id_path = '/sys/module/zl3073x_core/parameters/clock_id'

# Device's uevent fields
DRIVER = 'DRIVER'
PCI_CLASS = 'PCI_CLASS'
PCI_ID = 'PCI_ID'
PCI_SUBSYS_ID = 'PCI_SUBSYS_ID'
PCI_SLOT_NAME = 'PCI_SLOT_NAME'
MODALIAS = 'MODALIAS'

# Timestamping modes
TIMESTAMP_MODE__HW = 'hardware'
TIMESTAMP_MODE__SW = 'software'
TIMESTAMP_MODE__LEGACY = 'legacy'


class Interface:

    """Class that stores interface data for PTP plugin"""

    def __init__(self, name):
        self.name = name
        self.base_port = self._build_base_port()
        self.ts_supported_modes = self._read_suported_modes()
        self.uevent = self._read_uevent()
        self.nmea = self._read_nmea_serial_port_name()
        if self.get_family() in ['Granite Rapid-D', 'Connorsville']:
            self.switch_id = self._read_microchip_gnss_clock_id()
        else:
            self.switch_id = self._read_phy_switch_id()

    def base_port(interface):
        """Interface's base port name"""

        """A network device card can have multiple ports,
        get the name of the 1st port available.

        Returns : the name of the 1st port of a NIC"""
        if interface.startswith('eno'):
            # replace last number per 1
            base_port = interface[:-1] + '1'
        else:
            # replace last number per 0
            base_port = interface[:-1] + '0'
        return base_port

    def _build_base_port(self):
        return Interface.base_port(self.name)

    def _read_suported_modes(self):
        """Read interface's supported timestamping modes."""

        """Invoke ethtool -T <interface name> and load its
        time stamping capabilities.

            hardware, software or legacy.

        Interface Capabilities Ouput Examples:

        vbox prints this as it only supports software timestamping
            software-transmit       (SOF_TIMESTAMPING_TX_SOFTWARE)
            software-receive        (SOF_TIMESTAMPING_RX_SOFTWARE)

        full support output looks like this
            hardware-transmit       (SOF_TIMESTAMPING_TX_HARDWARE)
            software-transmit       (SOF_TIMESTAMPING_TX_SOFTWARE)
            hardware-receive        (SOF_TIMESTAMPING_RX_HARDWARE)
            software-receive        (SOF_TIMESTAMPING_RX_SOFTWARE)
            hardware-raw-clock      (SOF_TIMESTAMPING_RAW_HARDWARE)

        Only legacy support output looks like this
            hardware-raw-clock      (SOF_TIMESTAMPING_RAW_HARDWARE)

        Provisionable PTP Modes are
            hardware    -> hardware-transmit/receive
            software    -> software-transmit/receive
            legacy      -> hardware-raw-clock

        Returns : a list of supported modes"""
        hw_tx = hw_rx = sw_tx = sw_rx = False
        modes = []
        data = subprocess.check_output(
            [ETHTOOL, '-T', self.name]).decode().split('\n')
        if data:
            collectd.debug(f"{PLUGIN} \'ethtool -T {self.name}\' "
                           f"output {data}")
            check_for_modes = False
            for i in range(0, len(data)):
                if 'Capabilities' in data[i]:

                    # start of capabilities list
                    check_for_modes = True

                elif check_for_modes is True:

                    if 'PTP Hardware Clock' in data[i]:
                        # no more modes after this label
                        break
                    elif 'hardware-transmit' in data[i]:
                        hw_tx = True
                    elif 'hardware-receive' in data[i]:
                        hw_rx = True
                    elif 'software-transmit' in data[i]:
                        sw_tx = True
                    elif 'software-receive' in data[i]:
                        sw_rx = True
                    elif 'hardware-raw-clock' in data[i]:
                        modes.append(TIMESTAMP_MODE__LEGACY)

            if sw_tx is True and sw_rx is True:
                modes.append(TIMESTAMP_MODE__SW)

            if hw_tx is True and hw_rx is True:
                modes.append(TIMESTAMP_MODE__HW)

            if modes:
                collectd.debug(f"{PLUGIN} {self.name} PTP capabilities: {modes}")

        else:
            collectd.info(f"{PLUGIN} \'ethtool -T {self.name}\' failed.")
            modes = None

        return modes

    def _read_uevent(self):
        """Read device's uevent data"""

        """Read device's uevent file provided by the driver via sysfs.

        Device's uevent data examples:

        Westport Channel NIC:
            DRIVER=ice
            PCI_CLASS=20000
            PCI_ID=8086:1593
            PCI_SUBSYS_ID=8086:0005
            PCI_SLOT_NAME=0000:1a:00.0
            MODALIAS=pci:v00008086d00001593sv00008086sd00000005bc02sc00i00

        Returns : a dict of the uevent data"""
        data = {}
        filename = uevent_path % self.name
        if os.path.exists(filename):
            with open(filename, 'r') as infile:
                for line in infile:
                    if '=' in line:
                        field, value = line.strip('\n').split('=')
                        data[field] = value

        if data:
            collectd.debug(f"{PLUGIN} {self.name} uevent data {data}")
        else:
            collectd.info(f"{PLUGIN} {self.name} no uevent data")
            return None

        return data

    def _read_nmea_serial_port_name(self):
        """Read device's GNSS NMEA serial port name"""

        """Read GNSS uevent file provided by the driver via sysfs.

        GNSS's uevent data examples:

        Westport Channel NIC:
            MAJOR=241
            MINOR=0
            DEVNAME=gnss0
            GNSS_TYPE=UBX

        Columbiaville family of cards doesn't provide a NMEA serial port.

        Return: NMEA serial port name or None"""
        dirs = {}
        serial = None
        filepath = None
        path = gnss_path % self.name

        # list dirs in GNSS path
        if os.path.isdir(path):
            try:
                dirs = os.listdir(path)
            except (FileNotFoundError, PermissionError) as err:
                collectd.debug(f"{PLUGIN} {self.name} List dir {path} failed, "
                               f"reason: {err}")

        # get valid GNSS uevent file path
        if len(dirs) > 0:
            collectd.debug(f"{PLUGIN} {self.name} List dir {path} "
                           f"output {dirs}")
            for dir in dirs:
                if os.path.isdir(os.path.join(path, dir)):
                    filepath = os.path.join(path, dir, 'uevent')
                    if os.path.exists(filepath):
                        collectd.debug(f"{PLUGIN} {self.name} GNSS uevent file "
                                       f"path {filepath}")
                        break

        # get serial port name
        if filepath and os.path.exists(filepath):
            with open(filepath, 'r') as infile:
                for line in infile:
                    if 'DEVNAME=' in line:
                        _, serial = line.strip('\n').split('=')
                        collectd.debug(f"{PLUGIN} {self.name} NMEA serial port name "
                                       f"{serial}")
                        break
                else:
                    collectd.info(f"{PLUGIN} {self.name} no field \'DEVNAME\' "
                                  f"in GNSS uevent file {filepath}")
        else:
            collectd.info(f"{PLUGIN} {self.name} no GNSS uevent file in "
                          f"path {path}")

        return serial

    def _read_phy_switch_id(self):
        """Read interfaces's phy switch id"""

        """Read interfaces phy switch id file, provided by the
        ice driver via sysfs.

        Example of an Westport Channel NIC phy: 507c6fffff21b770

        Return: Phy switch id"""

        data = None
        switch_id = None
        filepath = switch_id_path % self.name
        if os.path.exists(filepath):
            with open(filepath, 'r') as infile:
                data = infile.read().strip('\n')

        if data:
            collectd.debug(f"{PLUGIN} {self.name} phy switch id "
                           f"data {data}")
            # prepend '0x' hexadecimal prefix
            data = '0x' + data
            # convert to decimal
            try:
                switch_id = int(data, 16)
            except ValueError as err:
                collectd.info(f"{PLUGIN} {self.name} phy switch id convertion to decimal failed, "
                              f"reason {err}")

        if switch_id:
            collectd.debug(f"{PLUGIN} {self.name} phy switch id {switch_id}")
        return switch_id

    def _read_microchip_gnss_clock_id(self):
        """Read Microchip's GNSS module clock id"""

        """Read Microchip's GNSS module clock id file provided
        by the zl3073x_core driver via sysfs.

        The clock_id file contains the id in decimal format,
        for example:

        4179056

        Return: clock id"""

        data = None
        clock_id = None
        try:
            if os.path.exists(gnrd_switch_id_path):
                with open(gnrd_switch_id_path, 'r') as infile:
                    data = infile.read().strip('\n')
        except (FileNotFoundError, PermissionError) as err:
            collectd.info(f"{PLUGIN} {self.name} Read GNSS module clock id failed, "
                          f"reason {err}")

        if data:
            collectd.debug(f"{PLUGIN} {self.name} clock id data: {data}")
            try:
                clock_id = int(data)
            except ValueError as err:
                collectd.info(f"{PLUGIN} {self.name} data convertion to int failed, "
                              f"reason {err}")

        if clock_id:
            collectd.debug(f"{PLUGIN} {self.name} clock id {clock_id}")
        return clock_id

    def get_base_port(self):
        """Get the name of the 1st interface of the NIC"""
        return self.base_port

    def get_ts_supported_modes(self):
        """Get interface's supported timestamping modes."""
        return self.ts_supported_modes

    def get_pci_id(self):
        """Get PCI id"""
        pci_id = None
        if self.uevent:
            pci_id = self.uevent.get('PCI_ID', None)
        return pci_id

    def get_pci_subsys_id(self):
        """Get PCI subsys id"""
        pci_subsys_id = None
        if self.uevent:
            pci_subsys_id = self.uevent.get('PCI_SUBSYS_ID', None)
        return pci_subsys_id

    def get_pci_slot(self):
        """Get device's PCI slot"""
        pci_slot = None
        if self.uevent:
            pci_slot = self.uevent.get('PCI_SLOT_NAME', None)
        return pci_slot

    def get_nmea(self):
        """Get interface's NMEA serial port name"""
        return self.nmea

    def get_switch_id(self):
        """Get interface's PHY switch id (aka clock-id)"""
        return self.switch_id

    def get_family(self):
        """Get network interface family"""
        family = 'unknown'
        pci_id = self.get_pci_id()
        pci_subsys_id = self.get_pci_subsys_id()

        family_dict = {
            '8086:12D3': {
                '8086:0005': 'Connorsville'
            },
            '8086:1591': {
                '1374:02D6': 'Silicom STS2'
            },
            '8086:1592': {
                '8086:000F': 'Logan Beach'
            },
            '8086:1593': {
                '8086:0005': 'Salem Channel',
                '8086:000F': 'Westport Channel'
            },
            '8086:579E': {
                '8086:0000': 'Granite Rapid-D'
            }
        }

        if pci_id in family_dict.keys() and \
           pci_subsys_id in family_dict[pci_id].keys():
            family = family_dict[pci_id][pci_subsys_id]

        return family
