#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""collectd plugin: SyncE QL controller with FM alarm integration.

Monitors DPLL EEC lock status via pynetlink and drives synce4l QL
via the socket API. Raises FM alarm on SyncE source loss (HOLDOVER/
UNLOCKED), clears on recovery (LOCKED).

State-to-QL mapping:
  LOCKED / LOCKED_HO_ACQ -> pass-through (no override), alarm clear
  HOLDOVER               -> QL-SSU-A (0x04), alarm raised (major)
  UNLOCKED / FREERUN     -> QL-DNU  (0x0f), alarm raised (critical)
"""

import collectd
import socket
import struct

from fm_api import constants as fm_constants
from fm_api import fm_api
import plugin_common as pc

from pynetlink import NetlinkDPLL
from pynetlink import DeviceType
from pynetlink import LockStatus

PLUGIN = 'synce plugin'
PLUGIN_READ_INTERVAL = 5


# Instantiate the common plugin control object
obj = pc.PluginObject(PLUGIN, "")


# FM Alarm
PLUGIN_ALARMID = '100.119'
ALARM_ENTITY_TYPE = 'synce'
ALARM_REASON_HOLDOVER = 'SyncE source unavailable; DPLL in holdover'
ALARM_REASON_FREERUN = 'SyncE source lost; DPLL in freerun/unlocked'
ALARM_REPAIR = ('Check SyncE source connectivity. '
                'Verify ESMC RX on the configured interface.')

# TLV protocol (synce4l external API)
_HDR = struct.Struct('<HH')
_MSG_DEV_NAME = 1
_MSG_SRC_NAME = 2
_MSG_SET_QL = 6
_MSG_END_MARKER = 8


class SynceController:
    """Reads DPLL state, sets synce4l QL accordingly, raises/clears FM alarms."""

    def __init__(self):
        self._dpll = None
        self._api = None
        self._last_ql = None
        self._alarm_raised = False
        self._alarm_severity = None
        self._config_logged = False

        # Config values — remain None until configured
        self.socket_path = None
        self.device = None
        self.interface = None
        self.source = 'GNSS'
        self.holdover_ql = 0x04
        self.freerun_ql = 0x0f

    def config(self):
        pass

    def init(self):
        if obj.config_complete() is False:
            return False
        obj.hostname = obj.gethostname()
        obj.init_completed()
        obj.base_eid = f"host={obj.hostname}.{ALARM_ENTITY_TYPE}"
        self._alarm_eid = f"{obj.base_eid}.interface={self.interface}.synce=source-loss"
        collectd.debug(f"{PLUGIN} on {obj.hostname} with entity id '{obj.base_eid}'")

        try:
            # Non-singleton avoids stale-socket read errors over time
            self._dpll = NetlinkDPLL(True)
            devices = self._dpll.get_all_devices()
            if not any(d.dev_type == DeviceType.EEC for d in devices):
                collectd.info(f"{PLUGIN} no EEC DPLL device found, disabling")
                self._dpll = None
                return
            self._api = fm_api.FaultAPIs()
            collectd.info(f"{PLUGIN} initialized, socket={self.socket_path} "
                          f"device={self.device} interface={self.interface}")
        except Exception as e:
            collectd.error(f"{PLUGIN} init failed: {e}")

    def read(self):
        if not all([self._dpll, self.socket_path, self.device,
                    self.interface]):
            if not self._config_logged:
                collectd.info(f"{PLUGIN} disabled: incomplete config")
                self._config_logged = True
            return

        status = self._get_dpll_status()
        collectd.debug(f"{PLUGIN} DPLL status: {status}")
        if status is None:
            return

        ql = self._status_to_ql(status)
        if ql is None:
            # locked - pass-through, no override
            if self._last_ql is not None:
                collectd.info(f"{PLUGIN} DPLL locked, clearing QL override")
                self._last_ql = None
            self._clear_alarm()
            return

        if ql != self._last_ql:
            state_name = getattr(status, 'name', str(status))
            collectd.info(f"{PLUGIN} DPLL state={state_name}, "
                          f"setting QL=0x{ql:02x}")
            if self._set_ql(ql):
                self._last_ql = ql
            self._raise_alarm(status)

    def _get_dpll_status(self):
        """Get EEC DPLL lock status (first EEC device)."""
        try:
            devices = self._dpll.get_all_devices()
            for d in devices:
                if d.dev_type == DeviceType.EEC:
                    return d.lock_status
            return None
        except Exception as e:
            collectd.warning(f"{PLUGIN} DPLL read failed: {type(e).__name__}: {e}")
            return None

    def _status_to_ql(self, status):
        """Map DPLL lock status to QL value. None = pass-through."""
        if status in (LockStatus.LOCKED, LockStatus.LOCKED_AND_HOLDOVER):
            return None  # pass-through
        elif status == LockStatus.HOLDOVER:
            return self.holdover_ql
        else:
            # UNLOCKED, UNDEFINED, etc.
            return self.freerun_ql

    def _set_ql(self, ql):
        """Send SET_QL to synce4l via socket."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect(self.socket_path)

                msg = (self._enc_str(_MSG_DEV_NAME, self.device) +
                       self._enc_str(_MSG_SRC_NAME, self.source) +
                       self._enc(_MSG_SET_QL, struct.pack('B', ql)) +
                       self._enc(_MSG_END_MARKER))

                sock.sendall(msg)
                sock.recv(4096)
                return True
        except Exception as e:
            collectd.warning(f"{PLUGIN} SET_QL failed (socket_path={self.socket_path},"
                             f"device={self.device},source={self.source}): {e}")
            return False

    def _raise_alarm(self, status):
        """Raise FM alarm for SyncE source loss. Re-raises on severity change."""
        if not self._api:
            return
        if status == LockStatus.HOLDOVER:
            reason = ALARM_REASON_HOLDOVER
            fm_severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        else:
            reason = ALARM_REASON_FREERUN
            fm_severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL

        if self._alarm_raised and self._alarm_severity == fm_severity:
            return  # already raised at correct severity

        eid = self._alarm_eid
        try:
            fault = fm_api.Fault(
                alarm_id=PLUGIN_ALARMID,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=eid,
                severity=fm_severity,
                reason_text=reason,
                alarm_type=fm_constants.FM_ALARM_TYPE_1,  # communication
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_29,  # loss-of-signal
                proposed_repair_action=ALARM_REPAIR,
                service_affecting=True,
                suppression=True)

            alarm_uuid = self._api.set_fault(fault)
            if alarm_uuid:
                collectd.info(f"{PLUGIN} alarm raised: {PLUGIN_ALARMID} "
                              f"{eid} severity={fm_severity}")
                self._alarm_raised = True
                self._alarm_severity = fm_severity
            else:
                collectd.warning(f"{PLUGIN} set_fault returned: {alarm_uuid}")
        except Exception as e:
            collectd.error(f"{PLUGIN} raise alarm failed: {e}")

    def _clear_alarm(self):
        """Clear FM alarm when SyncE source recovers."""
        if not self._alarm_raised or not self._api:
            return

        eid = self._alarm_eid
        try:
            self._api.clear_fault(PLUGIN_ALARMID, eid)
            collectd.info(f"{PLUGIN} alarm cleared: {PLUGIN_ALARMID} {eid}")
            self._alarm_raised = False
            self._alarm_severity = None
        except Exception as e:
            collectd.error(f"{PLUGIN} clear alarm failed: {e}")

    @staticmethod
    def _enc(msg_type, value=b''):
        return _HDR.pack(msg_type, len(value)) + value

    @staticmethod
    def _enc_str(msg_type, s):
        payload = s.encode() + b'\x00'
        return _HDR.pack(msg_type, len(payload)) + payload


# Module-level instance and collectd callbacks
_ctrl = SynceController()


def init_func():
    _ctrl.config()
    _ctrl.init()


def read_func():
    _ctrl.read()


collectd.register_init(init_func)
collectd.register_read(read_func, PLUGIN_READ_INTERVAL)
