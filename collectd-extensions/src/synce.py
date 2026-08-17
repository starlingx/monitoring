#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""collectd plugin: SyncE QL controller with FM alarm integration.

Monitors DPLL EEC lock status via pynetlink and drives synce4l QL
via the socket API. Raises FM alarm on SyncE source loss (HOLDOVER/
UNLOCKED), clears on recovery (LOCKED). Also raises FM alarm when
synce4l service is enabled but not running (stopped/failed/killed).

Supports multiple synce4l instances — one controller per discovered
instance with a matching section in instance-monitoring.conf. Each
instance is monitored independently with its own alarm entity IDs,
DPLL state tracking, and QL management.

Implements a configurable holdover timer: when the DPLL enters HOLDOVER,
the plugin sets holdover_ql and starts a countdown. If the source does
not recover before the timer expires, the plugin transitions to freerun_ql
and escalates the alarm from major to critical.

State-to-QL mapping:
  LOCKED / LOCKED_HO_ACQ -> pass-through (no override), alarm clear
  HOLDOVER               -> QL-SSU-A (0x04), alarm raised (major)
  HOLDOVER (timer expired)-> QL-DNU  (0x0f), alarm escalated (critical)
  UNLOCKED / FREERUN     -> QL-DNU  (0x0f), alarm raised (critical)
"""

import collectd
import socket
import struct
import subprocess
import time
import configparser
from glob import glob
import re

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


# Config files
PTPINSTANCE_PATH = '/etc/linuxptp/ptpinstance/'
PTPINSTANCE_SYNCE4L_CONF_FILE_PATTERN = PTPINSTANCE_PATH + 'synce4l-*.conf'
PTPINSTANCE_INSTANCE_MONITORING_CONF_FILE = PTPINSTANCE_PATH + "instance-monitoring.conf"

# systemctl
SYSTEMCTL = '/usr/bin/systemctl'

# FM Alarm
PLUGIN_ALARMID = '100.119'
ALARM_ENTITY_TYPE = 'synce'
ALARM_REASON_HOLDOVER = 'SyncE source unavailable; DPLL in holdover'
ALARM_REASON_FREERUN = 'SyncE source lost; DPLL in freerun/unlocked'
ALARM_REASON_NOT_RUNNING = 'SyncE service {} is enabled but not running'
ALARM_REPAIR_SOURCE_LOSS = ('Check SyncE source connectivity. '
                            'Verify ESMC RX on the configured interface.')
ALARM_REPAIR_NOT_RUNNING = ('Start service with: systemctl start {}. '
                            'If issue persists, check synce4l '
                            'configuration and logs.')

# TLV protocol (synce4l external API)
_HDR = struct.Struct('<HH')
_MSG_DEV_NAME = 1
_MSG_SRC_NAME = 2
_MSG_SET_QL = 6
_MSG_END_MARKER = 8


class SynceController:
    """Reads DPLL state, sets synce4l QL accordingly, raises/clears FM alarms.

    One instance of this class is created per synce4l instance that has
    a matching section in instance-monitoring.conf.
    """

    def __init__(self, instance_name, synce4l_conf_file, monitoring_config):
        """Initialize controller for a specific synce4l instance.

        :param instance_name: synce4l instance name (e.g. 'synce1')
        :param synce4l_conf_file: path to synce4l-<name>.conf
        :param monitoring_config: ConfigParser with instance-monitoring.conf
        """
        self.instance_name = instance_name
        self._dpll = None
        self._api = None
        self._last_ql = None
        self._source_loss_alarm_raised = False
        self._source_loss_alarm_severity = None
        self._process_alarm_raised = False
        self._config_logged = False

        # Holdover timer state
        self._holdover_start = None  # monotonic timestamp of HOLDOVER entry
        self._holdover_expired = False

        # Default instance-monitoring.conf config values
        # - required
        self.socket_path = None
        self.device = None
        self.interface = None
        self.clock_id = None
        # - optional
        self.source = 'GNSS'
        self.holdover_ql = 0x04
        self.freerun_ql = 0x0f
        self.static_ql = 0x02  # PRC — advertised when locked, no incoming SyncE
        self.holdover_timer = 14400  # seconds before escalating to freerun (4h)

        # Alarm entity IDs (set during init after hostname is known)
        self._source_loss_alarm_eid = None
        self._process_alarm_eid = None

        # Load configuration
        self._parse_clock_id(synce4l_conf_file)
        self._load_monitoring_config(monitoring_config)

    @property
    def _log_prefix(self):
        """Log prefix identifying this instance in collectd logs."""
        return f"{PLUGIN} [{self.instance_name}]"

    def _parse_clock_id(self, synce4l_conf_file):
        """Parse clock_id from synce4l config file (device section is [<name>])."""
        synce_config = configparser.ConfigParser(delimiters=' ')
        try:
            synce_config.read(synce4l_conf_file)
            device_section = f'<{self.instance_name}>'
            if synce_config.has_option(device_section, 'clock_id'):
                self.clock_id = int(synce_config[device_section]['clock_id'])
        except Exception as e:
            collectd.warning(f"{self._log_prefix} failed to parse "
                             f"clock_id from {synce4l_conf_file}: {e}")

        if self.clock_id is None:
            collectd.warning(f"{self._log_prefix} clock_id not found "
                             f"in {synce4l_conf_file}; DPLL matching will be "
                             f"unavailable")

    def _load_monitoring_config(self, config):
        """Read synce monitoring params from instance-monitoring.conf."""

        if self.instance_name not in config.sections():
            collectd.warning(f"{self._log_prefix} section not found "
                             f"in {PTPINSTANCE_INSTANCE_MONITORING_CONF_FILE}")
            return

        section = config[self.instance_name]
        self.device = self.instance_name
        collectd.info(f"{self._log_prefix} device={self.device}")

        if 'smc_socket_path' in section:
            self.socket_path = section['smc_socket_path']
            collectd.info(f"{self._log_prefix} "
                          f"socket_path={self.socket_path}")
        if 'source' in section:
            self.source = section['source'].split(',')[0]
            collectd.info(f"{self._log_prefix} source={self.source}")
        if 'interface' in section:
            self.interface = section['interface']
            collectd.info(f"{self._log_prefix} "
                          f"interface={self.interface}")
        if 'holdover_ql' in section:
            self.holdover_ql = int(section['holdover_ql'], 0)
            collectd.info(f"{self._log_prefix} "
                          f"holdover_ql={self.holdover_ql:#x}")
        if 'freerun_ql' in section:
            self.freerun_ql = int(section['freerun_ql'], 0)
            collectd.info(f"{self._log_prefix} "
                          f"freerun_ql={self.freerun_ql:#x}")
        if 'static_ql' in section:
            self.static_ql = int(section['static_ql'], 0)
            collectd.info(f"{self._log_prefix} "
                          f"static_ql={self.static_ql:#x}")
        if 'holdover_timer' in section:
            self.holdover_timer = int(section['holdover_timer'])
            collectd.info(f"{self._log_prefix} "
                          f"holdover_timer={self.holdover_timer}s")

        collectd.info(f"{self._log_prefix} monitoring config loaded")

    def init(self):
        """Initialize FM API and DPLL netlink connection.

        Must be called after obj.hostname is available (after obj.init_completed).
        """
        self._source_loss_alarm_eid = (f"{obj.base_eid}.interface={self.interface}"
                                       f".synce=source-loss")
        self._process_alarm_eid = (f"{obj.base_eid}.instance={self.instance_name}"
                                   f".synce=not-running")

        try:
            self._api = fm_api.FaultAPIs()
            # Non-singleton avoids stale-socket read errors over time
            self._dpll = NetlinkDPLL(True)
            devices = self._dpll.get_all_devices()
            if not any(d.dev_type == DeviceType.EEC for d in devices):
                collectd.info(f"{self._log_prefix} "
                              f"no EEC DPLL device found, disabling")
                self._dpll = None
                return
            collectd.info(f"{self._log_prefix} initialized, "
                          f"socket={self.socket_path} device={self.device} "
                          f"interface={self.interface}")
        except Exception as e:
            collectd.error(f"{self._log_prefix} init failed: {e}")

    def read(self):
        """Main monitoring loop — called every PLUGIN_READ_INTERVAL seconds."""
        if not all([self.socket_path, self.device, self.interface,
                    self.instance_name]):
            if not self._config_logged:
                missing = [f for f, v in [
                    ('socket_path', self.socket_path),
                    ('device', self.device),
                    ('interface', self.interface),
                ] if not v]
                collectd.warning(f"{self._log_prefix} disabled: "
                                 f"missing config: {', '.join(missing)}")
                self._config_logged = True
            return

        service = f"synce4l@{self.instance_name}.service"

        # Check if service is enabled (user may have intentionally disabled)
        if not self._is_service_enabled(service):
            self._clear_process_alarm()
            self._clear_source_loss_alarm()
            return

        # Check if service is running
        if not self._is_service_active(service):
            self._raise_process_alarm(service)
            self._clear_source_loss_alarm()
            return

        self._clear_process_alarm()

        # DPLL monitoring requires hardware
        if not all([self._dpll, self.clock_id]):
            return

        status = self._get_dpll_status()
        collectd.debug(f"{self._log_prefix} DPLL status: {status}")
        if status is None:
            return

        ql = self._status_to_ql(status)
        if ql is None:
            # locked with SyncE source - pass-through, no override
            if self._last_ql is not None:
                collectd.info(f"{self._log_prefix} DPLL locked "
                              f"(SyncE source), clearing QL override")
                self._last_ql = None
            self._cancel_holdover_timer()
            self._clear_source_loss_alarm()
            return

        # Holdover timer: on HOLDOVER entry start timer, on expiry escalate
        if status == LockStatus.HOLDOVER:
            if self._holdover_start is None:
                # Entering holdover — start timer
                self._holdover_start = time.monotonic()
                self._holdover_expired = False
                collectd.info(f"{self._log_prefix} HOLDOVER "
                              f"entered, timer started "
                              f"({self.holdover_timer}s)")
            elif (not self._holdover_expired and
                  time.monotonic() - self._holdover_start >=
                  self.holdover_timer):
                # Timer expired — escalate to freerun
                self._holdover_expired = True
                collectd.info(f"{self._log_prefix} holdover "
                              f"timer expired after {self.holdover_timer}s, "
                              f"escalating to freerun "
                              f"QL={self.freerun_ql:#x}")
            # Use freerun_ql if timer expired, otherwise holdover_ql
            if self._holdover_expired:
                ql = self.freerun_ql
        else:
            # UNLOCKED/FREERUN — immediate freerun, no timer needed
            self._cancel_holdover_timer()

        if ql != self._last_ql:
            state_name = getattr(status, 'name', str(status))
            collectd.info(f"{self._log_prefix} DPLL "
                          f"state={state_name}, setting QL={ql:#x}")
            if self._set_ql(ql):
                self._last_ql = ql

        # Alarm: major for holdover (timer not expired), critical otherwise
        if status in (LockStatus.LOCKED, LockStatus.LOCKED_AND_HOLDOVER):
            self._cancel_holdover_timer()
            self._clear_source_loss_alarm()
        elif status == LockStatus.HOLDOVER and not self._holdover_expired:
            self._raise_source_loss_alarm(status)
        else:
            self._raise_source_loss_alarm(LockStatus.UNLOCKED)

    def _cancel_holdover_timer(self):
        """Cancel holdover timer on recovery or direct freerun."""
        if self._holdover_start is not None:
            elapsed = time.monotonic() - self._holdover_start
            if self._holdover_expired:
                collectd.info(f"{self._log_prefix} holdover "
                              f"timer cleared after {elapsed:.0f}s "
                              f"(was expired)")
            else:
                collectd.info(f"{self._log_prefix} holdover "
                              f"timer cancelled after {elapsed:.0f}s")
            self._holdover_start = None
            self._holdover_expired = False

    def _is_service_enabled(self, service):
        """Check if synce4l service is enabled via systemctl."""
        try:
            result = subprocess.check_output(
                [SYSTEMCTL, 'is-enabled', service],
                stderr=subprocess.DEVNULL).decode().strip()
            return result == 'enabled'
        except subprocess.CalledProcessError:
            return False

    def _is_service_active(self, service):
        """Check if synce4l service is active (running) via systemctl."""
        try:
            result = subprocess.check_output(
                [SYSTEMCTL, 'is-active', service],
                stderr=subprocess.DEVNULL).decode().strip()
            return result == 'active'
        except subprocess.CalledProcessError:
            return False

    def _raise_process_alarm(self, service):
        """Raise FM alarm when synce4l service is enabled but not running."""
        if self._process_alarm_raised or not self._api:
            return
        try:
            fault = fm_api.Fault(
                alarm_id=PLUGIN_ALARMID,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=self._process_alarm_eid,
                severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                reason_text=ALARM_REASON_NOT_RUNNING.format(service),
                alarm_type=fm_constants.FM_ALARM_TYPE_1,
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN,
                proposed_repair_action=ALARM_REPAIR_NOT_RUNNING.format(
                    service),
                service_affecting=True,
                suppression=True)
            alarm_uuid = self._api.set_fault(fault)
            if alarm_uuid:
                collectd.info(f"{self._log_prefix} process "
                              f"alarm raised: {PLUGIN_ALARMID} "
                              f"{self._process_alarm_eid}")
                self._process_alarm_raised = True
            else:
                collectd.warning(f"{self._log_prefix} "
                                 f"set_fault (process) returned: "
                                 f"{alarm_uuid}")
        except Exception as e:
            collectd.error(f"{self._log_prefix} raise process "
                           f"alarm failed: {e}")

    def _clear_process_alarm(self):
        """Clear process alarm when synce4l service resumes running."""
        if not self._process_alarm_raised or not self._api:
            return
        try:
            self._api.clear_fault(PLUGIN_ALARMID, self._process_alarm_eid)
            collectd.info(f"{self._log_prefix} process alarm "
                          f"cleared: {PLUGIN_ALARMID} "
                          f"{self._process_alarm_eid}")
            self._process_alarm_raised = False
        except Exception as e:
            collectd.error(f"{self._log_prefix} clear process "
                           f"alarm failed: {e}")

    def _get_dpll_status(self):
        """Get EEC DPLL lock status for our clock_id."""
        try:
            devices = self._dpll.get_all_devices()
            for d in devices:
                if d.dev_type == DeviceType.EEC and d.dev_clock_id == self.clock_id:
                    return d.lock_status
            return None
        except Exception as e:
            collectd.warning(f"{self._log_prefix} DPLL read "
                             f"failed: {type(e).__name__}: {e}")
            return None

    def _status_to_ql(self, status):
        """Map DPLL lock status to QL value. None = pass-through."""
        if status in (LockStatus.LOCKED, LockStatus.LOCKED_AND_HOLDOVER):
            # If source is SyncE, pass-through (let synce4l use incoming QL)
            # Otherwise, advertise static_ql (locked to GNSS/PTP, no incoming SyncE)
            if self.source.upper() == 'SYNCE':
                return None
            return self.static_ql
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
            collectd.warning(f"{self._log_prefix} SET_QL failed "
                             f"(socket_path={self.socket_path},"
                             f"device={self.device},source={self.source}): {e}")
            return False

    def _raise_source_loss_alarm(self, status):
        """Raise FM alarm for SyncE source loss. Re-raises on severity change."""
        if not self._api:
            return
        if status == LockStatus.HOLDOVER:
            reason = ALARM_REASON_HOLDOVER
            fm_severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        else:
            reason = ALARM_REASON_FREERUN
            fm_severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL

        if self._source_loss_alarm_raised and self._source_loss_alarm_severity == fm_severity:
            return  # already raised at correct severity

        eid = self._source_loss_alarm_eid
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
                proposed_repair_action=ALARM_REPAIR_SOURCE_LOSS,
                service_affecting=True,
                suppression=True)

            alarm_uuid = self._api.set_fault(fault)
            if alarm_uuid:
                collectd.info(f"{self._log_prefix} alarm raised:"
                              f" {PLUGIN_ALARMID} {eid} "
                              f"severity={fm_severity}")
                self._source_loss_alarm_raised = True
                self._source_loss_alarm_severity = fm_severity
            else:
                collectd.warning(f"{self._log_prefix} set_fault "
                                 f"returned: {alarm_uuid}")
        except Exception as e:
            collectd.error(f"{self._log_prefix} raise alarm "
                           f"failed: {e}")

    def _clear_source_loss_alarm(self):
        """Clear FM alarm when SyncE source recovers."""
        if not self._source_loss_alarm_raised or not self._api:
            return

        eid = self._source_loss_alarm_eid
        try:
            self._api.clear_fault(PLUGIN_ALARMID, eid)
            collectd.info(f"{self._log_prefix} alarm cleared: "
                          f"{PLUGIN_ALARMID} {eid}")
            self._source_loss_alarm_raised = False
            self._source_loss_alarm_severity = None
        except Exception as e:
            collectd.error(f"{self._log_prefix} clear alarm "
                           f"failed: {e}")

    @staticmethod
    def _enc(msg_type, value=b''):
        return _HDR.pack(msg_type, len(value)) + value

    @staticmethod
    def _enc_str(msg_type, s):
        payload = s.encode() + b'\x00'
        return _HDR.pack(msg_type, len(payload)) + payload


def _discover_instances():
    """Discover all synce4l instances with matching monitoring config.

    Returns a dict of instance_name -> SynceController for each synce4l
    config file that has a corresponding section in instance-monitoring.conf.
    """
    controllers = {}

    filenames = glob(PTPINSTANCE_SYNCE4L_CONF_FILE_PATTERN)
    if not filenames:
        collectd.info(f"{PLUGIN} no synce4l conf files found")
        return controllers

    config = configparser.ConfigParser(delimiters=' ')
    config.read(PTPINSTANCE_INSTANCE_MONITORING_CONF_FILE)

    if not config.sections():
        collectd.info(f"{PLUGIN} {PTPINSTANCE_INSTANCE_MONITORING_CONF_FILE} "
                      f"not found or has no sections")
        return controllers

    for f in sorted(filenames):
        try:
            name = re.search(r'synce4l-(.*?)\.conf', f).group(1)
        except AttributeError:
            continue
        if name in config.sections():
            ctrl = SynceController(name, f, config)
            controllers[name] = ctrl
            collectd.info(f"{PLUGIN} discovered instance: {name}")

    if not controllers:
        collectd.warning(f"{PLUGIN} no synce4l instance has a matching "
                         f"section in "
                         f"{PTPINSTANCE_INSTANCE_MONITORING_CONF_FILE}")

    return controllers


# Module-level controllers dict — populated during init
_controllers = {}


def init_func():
    """Initialize all synce4l instance controllers."""
    global _controllers

    # Do nothing until config is complete.
    if obj.config_complete() is False:
        return

    obj.hostname = obj.gethostname()
    obj.base_eid = f"host={obj.hostname}.{ALARM_ENTITY_TYPE}"

    _controllers = _discover_instances()

    # Clear ALL stale synce alarms from previous session (clean slate).
    # Handles removed instances whose alarms would otherwise persist.
    try:
        api = fm_api.FaultAPIs()
        alarms = api.get_faults_by_id(PLUGIN_ALARMID)
        if alarms:
            for alarm in alarms:
                eid = alarm.entity_instance_id
                if eid and '.synce=' in eid:
                    api.clear_fault(PLUGIN_ALARMID, eid)
                    collectd.info(f"{PLUGIN} cleared startup alarm: {eid}")
    except Exception as ex:
        collectd.warning(f"{PLUGIN} startup alarm sweep failed: {ex}")

    # Initialize each controller (FM API, DPLL connection)
    for name, ctrl in _controllers.items():
        ctrl.init()

    if _controllers:
        collectd.info(f"{PLUGIN} initialized {len(_controllers)} instance(s): "
                      f"{list(_controllers.keys())}")
    else:
        collectd.info(f"{PLUGIN} no instances to monitor")

    obj.init_completed()


def read_func():
    """Read callback — monitor all discovered synce4l instances."""
    if obj.init_complete is False:
        init_func()
        return
    for name, ctrl in _controllers.items():
        ctrl.read()


collectd.register_init(init_func)
collectd.register_read(read_func, PLUGIN_READ_INTERVAL)
