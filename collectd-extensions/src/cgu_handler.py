#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import collectd
from pynetlink import NetlinkDPLL
from pynetlink import NetlinkException
from pynetlink import PinDirection
from pynetlink import PinState

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = 'ptp plugin'


class CguHandler:

    """Class that implements methods to access CGU information"""

    def __init__(self):
        self._pins = None
        self._devices = None
        self._initialize_netlink_dpll()

    def _initialize_netlink_dpll(self):
        """Initialize Netlink DPLL instance"""

        try:
            self._dpll = NetlinkDPLL()
        except Exception as err:
            collectd.error(f"{PLUGIN} Failed to initialize Netlink communication, "
                           f"reason: {err}")

    def read_cgu(self):
        """Read CGU information using netlink interface"""

        try:
            if self._dpll:
                self._devices = self._dpll.get_all_devices()
                self._pins = self._dpll.get_all_pins()
            else:
                collectd.warning(f"{PLUGIN} Netlink DPLL not initialized.")
        except (NetlinkException, ValueError) as err:
            collectd.warning(f"{PLUGIN} Failed to read data from Netlink, "
                             f"reason: {err}")

    def search_pins(self, clock_id, pin_name):
        """Search for pins in the pin info

        Args:
            clock_id (str):         The device's clock ID.
            pin_name (str):         The pin name.

        Returns:
            list: List of pins matching the search criteria.
        """

        return list(
            set(
                filter(
                    lambda pin:
                    pin.dev_clock_id == clock_id and
                    pin.pin_board_label == pin_name,
                    self._pins
                )
            )
        )

    def get_current_pin_reference(self, device):
        """Search the pin disciplining the device's locking state"""

        pins = set()
        if self._pins:
            pins = set(
                filter(
                    lambda pin:
                    pin.dev_id == device.dev_id and
                    pin.pin_direction == PinDirection.INPUT and
                    pin.pin_state == PinState.CONNECTED,
                    self._pins
                )
            )
            pins = sorted(
                pins,
                key=lambda pin: (pin.pin_priority is None, pin.pin_priority)
            )
        if len(pins) > 0:
            return list(pins)[0]
        else:
            return None

    def cgu_output_to_dict(self):
        """Translate the CGU information in standard dict."""

        dict = {}
        if self._devices:
            for device in self._devices:
                if device.dev_clock_id not in dict.keys():
                    dict[device.dev_clock_id] = {}
                device_type = str(device.dev_type).upper() + ' DPLL'
                dict[device.dev_clock_id][device_type] = {}
                dict[device.dev_clock_id][device_type]['Status'] = \
                    device.lock_status
                dict[device.dev_clock_id][device_type]['Current reference'] = \
                    self.get_current_pin_reference(device)
        collectd.debug(f"{PLUGIN} CGU output dictionary {dict}")
        return dict

    def cgu_get_current_device_state(self, clock_id, device_type):
        """Get current device state"""

        pin = None
        device = None
        if self._devices:
            devices = self._devices
            if clock_id:
                devices = set(
                    filter(
                        lambda device:
                        device.dev_clock_id == clock_id,
                        devices
                    )
                )
            if device_type:
                devices = set(
                    filter(
                        lambda device:
                        device.dev_type == device_type,
                        devices
                    )
                )
            if len(devices) > 0:
                device = list(devices)[0]
        if device:
            pin = self.get_current_pin_reference(device)
        if device and pin:
            collectd.debug(f"{PLUGIN} Current device clock_id {clock_id} "
                           f"type {device_type} status {device.lock_status} "
                           f"pin {pin.pin_board_label}")
        return device, pin
