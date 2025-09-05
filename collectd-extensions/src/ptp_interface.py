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
from __future__ import annotations
from dataclasses import dataclass
from dataclasses import field
from glob import glob
import os
import collectd
import subprocess

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = 'ptp plugin'

# Tools used by plugin
ETHTOOL = '/usr/sbin/ethtool'

# Device's sysfs paths
device_path = '/sys/class/net/%s/device/'
uevent_path = device_path + 'uevent'
gnss_path = device_path + 'gnss'
ptp_path = device_path + 'ptp'
switch_id_path = '/sys/class/net/%s/phys_switch_id'
pci_net_device_path = '/sys/bus/pci/devices/%s/net/'
gnrd_switch_id_path = '/sys/module/zl3073x/parameters/clock_id'

# Timestamping modes
TIMESTAMP_MODE__HW = 'hardware'
TIMESTAMP_MODE__SW = 'software'
TIMESTAMP_MODE__LEGACY = 'legacy'


@dataclass(frozen=True)
class Uevent:

    driver: str = field(hash=False, default=None)
    pci_class: str = field(hash=False, default=None)
    pci_id: str = field(hash=False, default=None)
    pci_subsys_id: str = field(hash=False, default=None)
    pci_slot_name: str = field(hash=False, default=None)
    modalias: str = field(hash=False, default=None)

    @classmethod
    def load(cls, file: str) -> Uevent:
        """Parse device's uevent data, and creates an Uevent object.

        Examples of uevent files:

        Westport Channel NIC:
            DRIVER=ice
            PCI_CLASS=20000
            PCI_ID=8086:1593
            PCI_SUBSYS_ID=8086:0005
            PCI_SLOT_NAME=0000:1a:00.0
            MODALIAS=pci:v00008086d00001593sv00008086sd00000005bc02sc00i00

        Connorsville NIC:
            DRIVER=ice
            PCI_CLASS=20000
            PCI_ID=8086:12D3
            PCI_SUBSYS_ID=8086:0005
            PCI_SLOT_NAME=0000:6c:00.0
            MODALIAS=pci:v00008086d000012D3sv00008086sd00000005bc02sc00i00

        file: Full path to device's uevent file.
        """

        if not file:
            raise ValueError("Uevent file must be informed.")

        if not os.path.exists(file):
            raise ValueError("Given uevent file doesn't exist")

        data = {}
        with open(file, 'r', encoding='utf-8') as infile:
            for line in infile:
                if '=' in line:
                    field, value = line.strip('\n').split('=')
                    data[field] = value

        return cls(
            driver=data['DRIVER'],
            pci_class=data['PCI_CLASS'],
            pci_id=data['PCI_ID'],
            pci_subsys_id=data['PCI_SUBSYS_ID'],
            pci_slot_name=data['PCI_SLOT_NAME'],
            modalias=data['MODALIAS']
        )


def read_uevent(interface):
    """Read device's uevent data

    Read device's uevent file provided by the driver via sysfs.

    Returns : uevent data object
    """
    uevent = None
    if interface:
        filename = uevent_path % interface
        try:
            uevent = Uevent.load(filename)
        except (ValueError, FileNotFoundError, PermissionError) as err:
            collectd.info(f"{PLUGIN} {interface} Read uevent {filename} failed, "
                          f"reason: {err}")
    return uevent


class Interface:

    """Class that stores interface data for PTP plugin"""

    def __init__(self, name):
        self.name = name
        self.uevent = read_uevent(self.name)
        self.base_port = self._build_base_port()
        self.ts_supported_modes = self._read_suported_modes()
        self.nmea = self._read_nmea_serial_port_name()
        if self.get_family() in ['Granite Rapid-D', 'Connorsville']:
            self.switch_id = self._read_microchip_gnss_clock_id()
        else:
            self.switch_id = self._read_phy_switch_id()

    def base_port(interface):
        """Interface's base port name"""

        """A network device card can have multiple ports,
        which shares the a single PTP hardware clock (PHC).
        Get the name of the interface which holds the PHC.

        Returns : the name of the base port"""
        # List the path to the interface in the same NIC,
        # which holds the PHC.
        prefix = interface[:-1] + '*'
        paths = glob(ptp_path % prefix)
        if len(paths) == 0:
            collectd.info(f"{PLUGIN} {interface} Failed to find path "
                          f"{ptp_path % prefix}.")
            return interface

        # Return the name of the interface in the 1st path available.
        path = next(iter(paths))
        return path.split(os.sep)[4]

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
            try:
                with open(filepath, 'r') as infile:
                    data = infile.read().strip('\n')
            except (FileNotFoundError, PermissionError, OSError) as err:
                collectd.debug(f"{PLUGIN} {self.name} Read phy_switch_id file failed, "
                               f"reason: {err}")

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
        by the zl3073x driver via sysfs.

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
            pci_id = self.uevent.pci_id
        return pci_id

    def get_pci_subsys_id(self):
        """Get PCI subsys id"""
        pci_subsys_id = None
        if self.uevent:
            pci_subsys_id = self.uevent.pci_subsys_id
        return pci_subsys_id

    def get_pci_slot(self):
        """Get device's PCI slot"""
        pci_slot = None
        if self.uevent:
            pci_slot = self.uevent.pci_slot_name
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

        family_dict = {
            '8086:12D3': 'Connorsville',
            '8086:1591': 'Silicom STS2',
            '8086:1592': 'Logan Beach',
            '8086:1593': 'Salem Channel/Westport Channel',
            '8086:579E': 'Granite Rapid-D'
        }

        if pci_id in family_dict.keys():
            family = family_dict[pci_id]

        return family
