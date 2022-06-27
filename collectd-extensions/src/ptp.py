#
# Copyright (c) 2019-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
############################################################################
#
# This file is the collectd 'Precision Time Protocol' Service Monitor.
#
# Algorithm:
#
# while not config ; check again
# while not init ; retry
# if startup
#   clear all ptp alarms
# if ptp enabled
#   if ptp not running
#     raise 'process' alarm
#  else
#     read grand master and current skew
#     if not controller and is grand master
#       raise 'no lock' alarm
#     if skew is out-of-tolerance
#       raise out-of-tolerance alarm
#
#
#  manage alarm state throught
#     retry on alarm state change failures
#     only make raise/clear alarm calls on severity state changes
#
############################################################################
import os
from collections import OrderedDict
import collectd
import subprocess
import tsconfig.tsconfig as tsc
import plugin_common as pc
import re
from fm_api import constants as fm_constants
from fm_api import fm_api
from glob import glob
from oslo_utils import timeutils

debug = False

# Fault manager API Object
api = fm_api.FaultAPIsV2()

PLUGIN_ALARMID = "100.119"

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = 'ptp plugin'

# Service name
PTP = 'Precision Time Protocol (PTP)'

# PTP Interface Monitoring Interval in seconds
PLUGIN_AUDIT_INTERVAL = 30

# Sample Data 'type' and 'instance' database field values.
PLUGIN_TYPE = 'time_offset'
PLUGIN_TYPE_INSTANCE = 'nsec'

# Plugin configuration file
#
# This plugin looks for the timestamping mode in the ptp4l config file.
#   time_stamping           hardware
#

PLUGIN_CONF_TIMESTAMPING = 'time_stamping'


def _get_os_release():
    os_release = '/etc/os-release'
    id = 'unknown'

    try:
        with open(os_release, 'r') as f:
            for l in f:
                if l.startswith('ID='):
                    id = l.rsplit('=')[1].replace('\n', '')
                    break

    except Exception as e:
        collectd.error(
            '%s failed to open %s (%s)' % (PLUGIN, os_release, str(e)))

    return id


def _get_ptpinstance_path():
    os_type = _get_os_release()
    if os_type == '\"centos\"':
        return '/etc/ptpinstance/'
    elif os_type == 'debian':
        return '/etc/linuxptp/ptpinstance/'
    else:
        collectd.error("%s unsupported OS type '%s'" % (PLUGIN, os_type))
        return ''


PTPINSTANCE_PATH = _get_ptpinstance_path()
PTPINSTANCE_CLOCK_CONF_FILE_PATTERN = PTPINSTANCE_PATH + 'clock-*.conf'
PTPINSTANCE_PTP4L_CONF_FILE_PATTERN = PTPINSTANCE_PATH + 'ptp4l-*.conf'
PTPINSTANCE_TS2PHC_CONF_FILE_PATTERN = PTPINSTANCE_PATH + 'ts2phc-*.conf'

PTP_INSTANCE_TYPE_PTP4L = 'ptp4l'
PTP_INSTANCE_TYPE_PHC2SYS = 'phc2sys'
PTP_INSTANCE_TYPE_TS2PHC = 'ts2phc'
PTP_INSTANCE_TYPE_CLOCK = 'clock'

# Tools used by plugin
SYSTEMCTL = '/usr/bin/systemctl'
ETHTOOL = '/usr/sbin/ethtool'
PLUGIN_STATUS_QUERY_EXEC = '/usr/sbin/pmc'
PHC_CTL = '/usr/sbin/phc_ctl'

# Query PTP service administrative (enabled/disabled) state
#
# > systemctl is-enabled ptp4l
# enabled
# > systemctl disable ptp4l
# > systemctl is-enabled ptp4l
# disabled

SYSTEMCTL_IS_ENABLED_OPTION = 'is-enabled'
SYSTEMCTL_IS_ENABLED_RESPONSE = 'enabled'
SYSTEMCTL_IS_DISABLED_RESPONSE = 'disabled'

# Query PTP service activity (active=running / inactive) state
#
# > systemctl is-active ptp4l
# active
# > systemctl stop ptp4l
# > systemctl is-active ptp4l
# inactive

SYSTEMCTL_IS_ACTIVE_OPTION = 'is-active'
SYSTEMCTL_IS_ACTIVE_RESPONSE = 'active'
SYSTEMCTL_IS_INACTIVE_RESPONSE = 'inactive'

# Alarm Cause codes ; used to specify what alarm EID to assert or clear.
ALARM_CAUSE__NONE = 0
ALARM_CAUSE__PROCESS = 1
ALARM_CAUSE__OOT = 2
ALARM_CAUSE__NO_LOCK = 3
ALARM_CAUSE__UNSUPPORTED_HW = 4
ALARM_CAUSE__UNSUPPORTED_SW = 5
ALARM_CAUSE__UNSUPPORTED_LEGACY = 6
ALARM_CAUSE__GNSS_SIGNAL_LOSS = 7
ALARM_CAUSE__1PPS_SIGNAL_LOSS = 8


# Run Phase
RUN_PHASE__INIT = 0
RUN_PHASE__DISABLED = 1
RUN_PHASE__NOT_RUNNING = 2
RUN_PHASE__SAMPLING = 3

# Clock Sync Out-Of-Tolerance thresholds
OOT_MINOR_THRESHOLD = int(1000)
OOT_MAJOR_THRESHOLD = int(1000000)

# DPLL device status info
ICE_DEBUG_FS = '/sys/kernel/debug/ice/'

# clock states
CLOCK_STATE_INVALID = 'invalid'
CLOCK_STATE_FREERUN = 'freerun'
CLOCK_STATE_LOCKED = 'locked'
CLOCK_STATE_LOCKED_HO_ACK = 'locked_ho_ack'
CLOCK_STATE_HOLDOVER = 'holdover'
CLOCK_STATE_UNLOCKED = 'unlocked'

# Synce Clock Generation Unit (CGU) input pin names
CGU_PIN_SDP22 = 'CVL-SDP22'
CGU_PIN_SDP20 = 'CVL-SDP20'
CGU_PIN_RCLKA = 'C827_0-RCLKA'
CGU_PIN_RCLKB = 'C827_0-RCLKB'
CGU_PIN_SMA1 = 'SMA1'
CGU_PIN_SMA2 = 'SMA2/U.FL2'
CGU_PIN_GNSS_1PPS = 'GNSS-1PPS'
VALID_CGU_PIN_NAMES = [
    CGU_PIN_SDP22,
    CGU_PIN_SDP20,
    CGU_PIN_RCLKA,
    CGU_PIN_RCLKB,
    CGU_PIN_SMA1,
    CGU_PIN_SMA2,
    CGU_PIN_GNSS_1PPS]

# PTP Clock Class
CLOCK_CLASS_6 = '6'       # T-GM connected to PRTC in locked mode
CLOCK_CLASS_7 = '7'       # T-GM in holdover, within holdover specification
CLOCK_CLASS_140 = '140'   # T-GM in holdover, out of holdover specification
CLOCK_CLASS_248 = '248'   # T-GM in free-run mode

# Time interval for holdover within spec (seconds)
HOLDOVER_THRESHOLD = 3600

# Leap second in nanoseconds
LEAP_SECOND = float(37000000000)

# regex pattern match
re_dict = re.compile(r'^(\w+)\s+(\w+)')
re_blank = re.compile(r'^\s*$')
re_keyval = re.compile(r'^\s*(\S+)\s+(\w+)')

# Instantiate the common plugin control object
obj = pc.PluginObject(PLUGIN, "")


# Create an alarm management class
class PTP_alarm_object:

    def __init__(self, source):

        self.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.cause = fm_constants.ALARM_PROBABLE_CAUSE_50
        self.alarm = ALARM_CAUSE__NONE
        self.source = source
        self.raised = False
        self.reason = ''
        self.repair = ''
        self.eid = ''


# Plugin specific control class and object.
class PTP_ctrl_object:

    def __init__(self):

        self.log_throttle_count = 0
        self.phase = 0
        self.pci_slot_name = None
        self.interface = None
        self.instance_type = PTP_INSTANCE_TYPE_PTP4L
        self.clock_ports = {}
        self.holdover_timestamp = None
        self.nolock_alarm_object = None
        self.process_alarm_object = None
        self.oot_alarm_object = None
        self.gnss_signal_loss_alarm_object = None
        self.pps_signal_loss_alarm_object = None

# Parameter in sysfs device/uevent file
PCI_SLOT_NAME = 'PCI_SLOT_NAME'

# PTP crtl objects for each PTP instances
ptpinstances = {}

# dpll status of each CGU input for GNSS
dpll_status = {}

# Alarm object list, one entry for each interface/instance and alarm cause case
ALARM_OBJ_LIST = []


# UT verification utilities
def assert_all_alarms():
    for o in ALARM_OBJ_LIST:
        raise_alarm(o.alarm, o.source, 0)


def clear_all_alarms():
    for o in ALARM_OBJ_LIST:
        if clear_alarm(o.eid) is True:
            msg = 'cleared'
        else:
            msg = 'clear failed'
        collectd.info("%s %s:%s alarm %s" %
                      (PLUGIN, PLUGIN_ALARMID, o.eid, msg))


def print_alarm_object(o):
    collectd.info("%s Source:%s  Cause: %d  Severity:%s  Raised:%d" %
                  (PLUGIN,
                   o.source,
                   o.alarm,
                   o.severity,
                   o.raised))
    collectd.info("%s Entity:[%s]" % (PLUGIN, o.eid))
    collectd.info("%s Reason:[%s]" % (PLUGIN, o.reason))
    collectd.info("%s Repair:[%s]" % (PLUGIN, o.repair))


def print_alarm_objects():
    for o in ALARM_OBJ_LIST:
        print_alarm_object(o)


# Interface:Supported Modes dictionary. key:value
#
# interface:modes
#
interfaces = {}


#####################################################################
#
# Name       : _get_supported_modes
#
# Description: Invoke ethtool -T <interface> and load its
#              time stamping capabilities.
#
#                 hardware, software or legacy.
#
# Parameters : The name of the physical interface to query the
#              supported modes for.
#
# Interface Capabilities Output Examples:
#
# vbox prints this as it only supports software timestamping
#    software-transmit     (SOF_TIMESTAMPING_TX_SOFTWARE)
#    software-receive      (SOF_TIMESTAMPING_RX_SOFTWARE)
#
# full support output looks like this
#    hardware-transmit     (SOF_TIMESTAMPING_TX_HARDWARE)
#    software-transmit     (SOF_TIMESTAMPING_TX_SOFTWARE)
#    hardware-receive      (SOF_TIMESTAMPING_RX_HARDWARE)
#    software-receive      (SOF_TIMESTAMPING_RX_SOFTWARE)
#    hardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)
#
# Only legacy support output looks like this
#    hardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)
#
# Provisionable PTP Modes are
#    hardware   -> hardware-transmit/receive
#    software   -> software-transmit/receive
#    legacy     -> hardware-raw-clock

TIMESTAMP_MODE__HW = 'hardware'
TIMESTAMP_MODE__SW = 'software'
TIMESTAMP_MODE__LEGACY = 'legacy'


#
# Returns  : a list of supported modes
#
#####################################################################
def _get_supported_modes(interface):
    """Get the supported modes for the specified interface"""

    hw_tx = hw_rx = sw_tx = sw_rx = False
    modes = []
    data = subprocess.check_output(
        [ETHTOOL, '-T', interface]).decode().split('\n')
    if data:
        collectd.debug("%s 'ethtool -T %s' output:%s\n" %
                       (PLUGIN, interface, data))
        check_for_modes = False
        for i in range(0, len(data)):
            collectd.debug("%s data[%d]:%s\n" % (PLUGIN, i, data[i]))
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
            collectd.debug("%s %s interface PTP capabilities: %s" %
                           (PLUGIN, interface, modes))
        else:
            collectd.info("%s no capabilities advertised for %s" %
                          (PLUGIN, interface))

    else:
        collectd.info("%s no ethtool output for %s" % (PLUGIN, interface))
        return None

    return modes


#####################################################################
#
# Name       : get_alarm_object
#
# Description: Search the alarm list based on the alarm cause
#              code and source.
#
# Returns    : Alarm object if found ; otherwise None
#
#####################################################################
def get_alarm_object(alarm, source=None):
    """Alarm object lookup"""

    for o in ALARM_OBJ_LIST:
        # print_alarm_object(o)
        if o.alarm == alarm:
            if not source or o.source == source:
                return o

    collectd.info("%s alarm object lookup failed ; %d:%s" %
                  (PLUGIN, alarm, source))
    return None


#####################################################################
#
# Name       : clear_alarm
#
# Description: Clear the ptp alarm with the specified entity ID.
#
# Returns    : True if operation succeeded
#              False if there was an error exception.
#
# Assumptions: Caller can decide to retry based on return status.
#
#####################################################################
def clear_alarm(eid):
    """Clear the ptp alarm with the specified entity ID"""

    try:
        if api.clear_fault(PLUGIN_ALARMID, eid) is True:
            collectd.info("%s %s:%s alarm cleared" %
                          (PLUGIN, PLUGIN_ALARMID, eid))
        else:
            collectd.info("%s %s:%s alarm already cleared" %
                          (PLUGIN, PLUGIN_ALARMID, eid))
        return True

    except Exception as ex:
        collectd.error("%s 'clear_fault' exception ; %s:%s ; %s" %
                       (PLUGIN, PLUGIN_ALARMID, eid, ex))
        return False


#####################################################################
#
# Name       : raise_alarm
#
# Description: Assert a specific PTP alarm based on the alarm cause
#              code and source.
#
#              Handle special case cause codes
#              Handle failure to raise fault
#
# Assumptions: Short circuited Success return if the alarm is
#              already known to be asserted.
#
# Returns    : False on Failure
#               True on Success
#
#####################################################################
def raise_alarm(alarm_cause, source=None, data=0):
    """Assert a cause based PTP alarm"""

    collectd.debug("%s Raising Alarm %d" % (PLUGIN, alarm_cause))

    alarm = get_alarm_object(alarm_cause, source)
    if alarm is None:
        # log created for None case in the get_alarm_object util
        return True

    # copy the reason as it might be updated for the OOT,
    # most typical, case.
    reason = alarm.reason

    # Handle some special cases
    #

    if alarm_cause == ALARM_CAUSE__OOT:
        # If this is an out of tolerance alarm then add the
        # out of tolerance reading to the reason string before
        # asserting the alarm.
        #
        # Keep the alarm updated with the latest sample reading
        # and severity even if its already asserted.
        if abs(float(data)) > 100000000000:
            reason += 'more than 100 seconds'
        elif abs(float(data)) > 10000000000:
            reason += 'more than 10 seconds'
        elif abs(float(data)) > 1000000000:
            reason += 'more than 1 second'
        elif abs(float(data)) > 1000000:
            reason += str(abs(int(data)) / 1000000)
            reason += ' millisecs'
        elif abs(float(data)) > 1000:
            reason += str(abs(int(data)) / 1000)
            reason += ' microsecs'
        else:
            reason += str(float(data))
            reason += ' ' + PLUGIN_TYPE_INSTANCE

    elif alarm.raised is True:
        # If alarm already raised then exit.
        #
        # All other alarms are a Major so there is no need to
        # track a change in severity and update accordingly.
        return True

    elif alarm_cause == ALARM_CAUSE__PROCESS:
        reason = 'Provisioned ' + PTP + ' \'' + obj.mode
        reason += '\' time stamping mode seems to be unsupported by this host'

    elif alarm_cause in [ALARM_CAUSE__1PPS_SIGNAL_LOSS,
                         ALARM_CAUSE__GNSS_SIGNAL_LOSS]:
        reason += ' state: ' + data

    try:
        fault = fm_api.Fault(
            alarm_id=PLUGIN_ALARMID,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=alarm.eid,
            severity=alarm.severity,
            reason_text=reason,
            alarm_type=obj.alarm_type,
            probable_cause=alarm.cause,
            proposed_repair_action=alarm.repair,
            service_affecting=False,  # obj.service_affecting,
            suppression=True)         # obj.suppression)

        alarm_uuid = api.set_fault(fault)
        if pc.is_uuid_like(alarm_uuid) is False:

            # Don't _add_unreachable_server list if the fm call failed.
            # That way it will be retried at a later time.
            collectd.error("%s 'set_fault' failed ; %s:%s ; %s" %
                           (PLUGIN, PLUGIN_ALARMID, alarm.eid, alarm_uuid))
            return False

        else:
            collectd.info("%s %s:%s:%s alarm raised" %
                          (PLUGIN, PLUGIN_ALARMID, alarm.eid, alarm.severity))
            alarm.raised = True
            return True

    except Exception as ex:
        collectd.error("%s 'set_fault' exception ; %s:%s:%s ; %s" %
                       (PLUGIN,
                        PLUGIN_ALARMID,
                        alarm.eid,
                        alarm.severity,
                        ex))
    return False


#####################################################################
#
# Name       : create_interface_alarm_objects
#
# Description: Create alarm objects for specified interface
#
#####################################################################
def create_interface_alarm_objects(interface, instance=None):
    """Create alarm objects"""

    collectd.debug("%s Alarm Object Create: Interface:%s " %
                   (PLUGIN, interface))

    if instance and not ptpinstances.get(instance, None):
        ctrl = PTP_ctrl_object()
        ctrl.interface = interface
        o = PTP_alarm_object(instance)
        o.alarm = ALARM_CAUSE__PROCESS
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname + ' does not support the provisioned '
        o.reason += PTP + ' mode '
        o.repair = 'Check host hardware reference manual '
        o.repair += 'to verify that the selected PTP mode is supported'
        o.eid = obj.base_eid + '.instance=' + instance + '.ptp'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN  # 'unknown'
        ALARM_OBJ_LIST.append(o)
        ctrl.process_alarm_object = o

        o = PTP_alarm_object(instance)
        o.alarm = ALARM_CAUSE__OOT
        o.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        o.reason = obj.hostname + ' '
        o.reason += PTP + " clocking is out of tolerance by "
        o.repair = "Check quality of the clocking network"
        o.eid = obj.base_eid + '.instance=' + instance + '.ptp=out-of-tolerance'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_50  # THRESHOLD CROSS
        ALARM_OBJ_LIST.append(o)
        ctrl.oot_alarm_object = o

        o = PTP_alarm_object(instance)
        # Only applies to storage and worker nodes
        o.alarm = ALARM_CAUSE__NO_LOCK
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' is not locked to remote PTP Grand Master'
        o.repair = 'Check network'
        o.eid = obj.base_eid + '.instance=' + instance + '.ptp=no-lock'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_51  # timing-problem
        ALARM_OBJ_LIST.append(o)
        ctrl.nolock_alarm_object = o

        o = PTP_alarm_object(interface)
        # Only applies to storage and worker nodes
        o.alarm = ALARM_CAUSE__GNSS_SIGNAL_LOSS
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' GNSS signal loss'
        o.repair = 'Check network'
        o.eid = obj.base_eid + '.interface=' + interface + '.ptp=signal-loss'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # loss-of-signal
        ALARM_OBJ_LIST.append(o)
        ctrl.gnss_signal_loss_alarm_object = o

        o = PTP_alarm_object(interface)
        # Only applies to storage and worker nodes
        o.alarm = ALARM_CAUSE__1PPS_SIGNAL_LOSS
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' 1PPS signal loss'
        o.repair = 'Check network'
        o.eid = obj.base_eid + '.interface=' + interface + '.ptp=signal-loss'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # loss-of-signal
        ALARM_OBJ_LIST.append(o)
        ctrl.pps_signal_loss_alarm_object = o

        ptpinstances[instance] = ctrl

    o = PTP_alarm_object(interface)
    o.alarm = ALARM_CAUSE__UNSUPPORTED_HW
    o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
    o.reason = obj.hostname + " '" + interface + "' does not support "
    o.reason += PTP + ' Hardware timestamping'
    o.repair = 'Check host hardware reference manual to verify PTP '
    o.repair += 'Hardware timestamping is supported by this interface'
    o.eid = obj.base_eid + '.ptp=' + interface
    o.eid += '.unsupported=hardware-timestamping'
    o.cause = fm_constants.ALARM_PROBABLE_CAUSE_7  # 'config error'
    ALARM_OBJ_LIST.append(o)

    o = PTP_alarm_object(interface)
    o.alarm = ALARM_CAUSE__UNSUPPORTED_SW
    o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
    o.reason = obj.hostname + " '" + interface + "' does not support "
    o.reason += PTP + ' Software timestamping'
    o.repair = 'Check host hardware reference manual to verify PTP '
    o.repair += 'Software timestamping is supported by this interface'
    o.eid = obj.base_eid + '.ptp=' + interface
    o.eid += '.unsupported=software-timestamping'
    o.cause = fm_constants.ALARM_PROBABLE_CAUSE_7  # 'config error'
    ALARM_OBJ_LIST.append(o)

    o = PTP_alarm_object(interface)
    o.alarm = ALARM_CAUSE__UNSUPPORTED_LEGACY
    o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
    o.reason = obj.hostname + " '" + interface + "' does not support "
    o.reason += PTP + " Legacy timestamping"
    o.repair = 'Check host hardware reference manual to verify PTP '
    o.repair += 'Legacy or Raw Clock is supported by this host'
    o.eid = obj.base_eid + '.ptp=' + interface
    o.eid += '.unsupported=legacy-timestamping'
    o.cause = fm_constants.ALARM_PROBABLE_CAUSE_7  # 'config error'
    ALARM_OBJ_LIST.append(o)


#####################################################################
#
# Name       : read_timestamp_mode
#
# Description: Refresh the timestamping mode if it changes
#
#####################################################################
def read_timestamp_mode(conf_file):
    """Load timestamping mode"""

    if os.path.exists(conf_file):
        current_mode = obj.mode
        with open(conf_file, 'r') as infile:
            for line in infile:
                if PLUGIN_CONF_TIMESTAMPING in line:
                    obj.mode = line.split()[1].strip('\n')
                    break

        if obj.mode:
            if obj.mode != current_mode:
                collectd.info("%s Timestamping Mode: %s" %
                              (PLUGIN, obj.mode))
        else:
            collectd.error("%s failed to get Timestamping Mode from %s" %
                           (PLUGIN, conf_file))
    else:
        collectd.error("%s failed to load ptp4l configuration from %s" %
                       (PLUGIN, conf_file))
        obj.mode = None


def get_pci_slot(interface):
    """get pci slot from uevent"""
    slot = None
    filename = '/sys/class/net/' + interface + '/device/uevent'
    if os.path.exists(filename):
        with open(filename, 'r') as infile:
            for line in infile:
                if PCI_SLOT_NAME in line:
                    slot = line.split('=')[1].strip('\n')
                    break

        if not slot:
            collectd.error("%s failed to get pci slot name of interface %s" %
                           (PLUGIN, interface))
    else:
        collectd.error("%s file %s does not exist" % (PLUGIN, filename))
    return slot


def init_dpll_status(pci_slot):
    """initialize dpll status"""
    pins = {}
    for pin in VALID_CGU_PIN_NAMES:
        pins[pin] = {'state': CLOCK_STATE_INVALID,
                     'eec_cgu_state': CLOCK_STATE_INVALID,
                     'pps_cgu_state': CLOCK_STATE_INVALID}
    dpll_status[pci_slot] = pins


def read_ptp4l_config():
    """read ptp4l conf files"""
    filenames = glob(PTPINSTANCE_PTP4L_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.debug("%s No PTP conf file configured for %s" %
                       (PLUGIN, type))
    else:
        for filename in filenames:
            pattern = PTP_INSTANCE_TYPE_PTP4L + '-(.*?)' + '.conf'
            instance = re.search(pattern, filename).group(1)
            ptpinstances[instance] = None
            with open(filename, 'r') as infile:
                for line in infile:
                    if line[0] == '[':
                        interface = line.split(']')[0].split('[')[1]
                        if interface and interface != 'global':
                            if (ptpinstances[instance] and
                                    ptpinstances[instance].interface == interface):
                                # ignore the duplicate interface in the file
                                continue
                            interfaces[interface] = _get_supported_modes(interface)
                            create_interface_alarm_objects(interface, instance)
                            ptpinstances[instance].instance_type = \
                                PTP_INSTANCE_TYPE_PTP4L

                    if PLUGIN_CONF_TIMESTAMPING in line:
                        obj.mode = line.split()[1].strip('\n')

            if obj.mode:
                collectd.info("%s instance %s Timestamping Mode: %s" %
                              (PLUGIN, instance, obj.mode))
            else:
                collectd.error("%s instance %s failed to get Timestamping Mode" %
                               (PLUGIN, instance))


def find_interface_from_pciaddr(pciaddr):
    pattern = "/sys/bus/pci/devices/*" + pciaddr
    filenames = glob(pattern)
    if len(filenames) == 0:
        collectd.info("%s Cannot find interface from pciaddr %s" %
                      (PLUGIN, pciaddr))
        return ""

    # If there's more than one filename, complain.
    if len(filenames) > 1:
        collectd.warning("%s Pattern %s gave %s matching filenames, using the first." %
                         (PLUGIN, pattern, len(filenames)))

    filepath = filenames[0] + '/net'
    if not os.path.exists(filepath):
        collectd.info("%s Cannot find interface from pciaddr %s, "
                      "directory not found: %s" %
                      (PLUGIN, pciaddr, filepath))
        return ""

    dirs = os.listdir(filepath)
    if len(dirs) == 0:
        collectd.info("%s Cannot find directory %s" %
                      (PLUGIN, filepath))
        return ""
    if len(dirs) > 1:
        collectd.warning("%s More than one directory found under %s, using the first." %
                         (PLUGIN, dirs))
    return dirs[0]


def read_ts2phc_config():
    """read ts2phc conf files"""
    filenames = glob(PTPINSTANCE_TS2PHC_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.info("%s No ts2phc conf file configured" % PLUGIN)
        return

    # If there is more than one filename, log a warning.
    if len(filenames) > 1:
        collectd.warning("Pattern %s gave %s matching filenames, using the first." %
                         (PTPINSTANCE_TS2PHC_CONF_FILE_PATTERN, len(filenames)))

    filename = filenames[0]
    instance = filename.split('ts2phc-')[1].split('.conf')[0]
    with open(filename, 'r') as infile:
        pci_slot = None
        for line in infile:
            if 'ts2phc.nmea_serialport' in line:
                tty = line.split(' ')[1].strip('\n')
                bus_device = tty.split('_')[1]
                function = tty.split('_')[2]
                pci_slot = '0000:' + bus_device[0:2] + ':' + \
                           bus_device[2:4] + '.' + function
                interface = find_interface_from_pciaddr(pci_slot)
                create_interface_alarm_objects(interface, instance)
                ptpinstances[instance].instance_type = \
                    PTP_INSTANCE_TYPE_TS2PHC
                ptpinstances[instance].pci_slot_name = pci_slot
                init_dpll_status(pci_slot)
                obj.capabilities['primary_nic'] = interface
                collectd.info("%s ts2phc instance:%s slot:%s primary_nic:%s" %
                              (PLUGIN, instance, pci_slot,
                               obj.capabilities['primary_nic']))
                break


def read_clock_config():
    """read clock conf files"""
    filenames = glob(PTPINSTANCE_CLOCK_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.info("%s No clock conf file configured" % PLUGIN)
        return

    # If there is more than one filename, log a warning.
    if len(filenames) > 1:
        collectd.warning("Pattern %s gave %s matching filenames, using the first." %
                         (PTPINSTANCE_CLOCK_CONF_FILE_PATTERN, len(filenames)))

    filename = filenames[0]
    found_port = False
    instance = PTP_INSTANCE_TYPE_CLOCK
    ptpinstances[instance] = None
    m = {}
    with open(filename, 'r') as infile:
        for line in infile:
            # skip lines we don't care about
            match = re_blank.search(line)
            if match:
                continue
            if 'ifname' in line:
                continue
            if 'base_port' in line:
                interface = line.split(']')[0].split('[')[1]
                if interface:
                    if (ptpinstances[instance] and
                            ptpinstances[instance].interface == interface):
                        # ignore the duplicate interface in the file
                        continue
                    if interface != obj.capabilities['primary_nic']:
                        create_interface_alarm_objects(interface, instance)
                        ptpinstances[instance].instance_type = \
                            PTP_INSTANCE_TYPE_CLOCK
                        slot = get_pci_slot(interface)
                        ptpinstances[instance].pci_slot_name = slot
                        init_dpll_status(slot)
                        found_port = True
                        m = {}
                        ptpinstances[instance].clock_ports[interface] = {}
            elif found_port:
                match = re_dict.search(line)
                if match:
                    k = match.group(1)
                    v = match.group(2)
                    m[k] = v
                    ptpinstances[instance].clock_ports[interface] = m
    if found_port:
        collectd.info("%s instance:%s ports:%s" %
                      (PLUGIN, instance, ptpinstances[instance].clock_ports))
    else:
        # When no base_port is found, it means synce is disabled.
        # Remove the ptp instance as it does not require monitoring.
        del ptpinstances[instance]


#####################################################################
#
# Name       : init_func
#
# Description: The collectd initialization entrypoint for
#              this plugin
#
# Assumptions: called only once
#
# Algorithm  : check for no
#
#
#####################################################################
def init_func():

    # do nothing till config is complete.
    if obj.config_complete() is False:
        return False

    obj.hostname = obj.gethostname()
    obj.base_eid = 'host=' + obj.hostname
    obj.capabilities = {'primary_nic': None}

    if os.path.exists(PTPINSTANCE_PATH):
        read_ptp4l_config()
        read_ts2phc_config()
        read_clock_config()
    else:
        collectd.error("%s instance configuration directory %s not found" %
                       (PLUGIN, PTPINSTANCE_PATH))
        obj.mode = None

    for key, value in interfaces.items():
        collectd.info("%s interface %s supports timestamping modes: %s" %
                      (PLUGIN, key, value))

    for key, ctrl in ptpinstances.items():
        collectd.info("%s instance:%s type:%s found" %
                      (PLUGIN, key, ctrl.instance_type))

    for key, value in dpll_status.items():
        collectd.debug("%s pci slot: %s info:%s" % (PLUGIN, key, value))

    # remove '# to dump alarm object data
    # print_alarm_objects()

    if tsc.nodetype == 'controller':
        obj.controller = True

    obj.virtual = obj.is_virtual()

    obj.init_completed()
    return 0


def read_dpll_status(pci_slot):
    """read dpll status from sysfs file"""
    filename = ICE_DEBUG_FS + pci_slot + '/cgu'
    current_dpll_type = None
    processing_cgu_input_status = False
    if os.path.exists(filename):
        with open(filename, 'r') as infile:
            for line in infile:
                if 'CGU Input status' in line:
                    processing_cgu_input_status = True
                    continue
                if processing_cgu_input_status:
                    for i in VALID_CGU_PIN_NAMES:
                        if i in line:
                            pin = line.split('|')[0].strip().split('(')[0].rstrip()
                            state = line.split('|')[1].strip()
                            dpll_status[pci_slot][pin].update({'state': state})
                            if pin == CGU_PIN_GNSS_1PPS:
                                processing_cgu_input_status = False
                    continue
                if 'Current reference' in line:
                    pin_name = line.split(':')[1].strip('\n\t')
                    continue
                if 'Status' in line:
                    status = line.split(':')[1].strip('\n\t')
                    if current_dpll_type == 'EEC':
                        dpll_status[pci_slot][pin_name].update(
                            {'eec_cgu_state': status})
                    elif current_dpll_type == 'PPS':
                        dpll_status[pci_slot][pin_name].update(
                            {'pps_cgu_state': status})
                    continue
                if 'EEC DPLL' in line:
                    current_dpll_type = 'EEC'
                    continue
                if 'PPS DPLL' in line:
                    current_dpll_type = 'PPS'
                    continue

            collectd.debug("%s pci_slot %s DPLL: %s" %
                           (PLUGIN, pci_slot, dpll_status[pci_slot]))
    return dpll_status


def check_gnss_alarm(instance, alarm_object, interface, state):
    """check for GNSS alarm"""

    ctrl = ptpinstances[instance]
    severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
    if not state or state in [CLOCK_STATE_HOLDOVER,
                              CLOCK_STATE_FREERUN,
                              CLOCK_STATE_INVALID]:
        severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
    elif state == CLOCK_STATE_UNLOCKED:
        severity = fm_constants.FM_ALARM_SEVERITY_MINOR
    elif state in [CLOCK_STATE_LOCKED, CLOCK_STATE_LOCKED_HO_ACK]:
        severity = fm_constants.FM_ALARM_SEVERITY_CLEAR

    if state == CLOCK_STATE_HOLDOVER:
        if not ctrl.holdover_timestamp:
            ctrl.holdover_timestamp = timeutils.utcnow()
    else:
        ctrl.holdover_timestamp = None

    if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
        if alarm_object.raised is True:
            if clear_alarm(alarm_object.eid) is True:
                alarm_object.severity = \
                    fm_constants.FM_ALARM_SEVERITY_CLEAR
                alarm_object.raised = False
    else:
        if alarm_object.severity != severity:
            alarm_object.severity = severity
        if alarm_object.raised is False:
            rc = raise_alarm(alarm_object.alarm, interface, state)
            if rc is True:
                alarm_object.raised = True


def _info_collecting_samples(hostname, instance, offset, gm_identity=None):
    if gm_identity:
        collectd.info("%s %s instance %s is collecting samples [%f] "
                      "with Grand Master %s" %
                      (PLUGIN, hostname, instance,
                       float(offset), gm_identity))
    else:
        collectd.info("%s %s instance %s is collecting samples [%f] "
                      "with GNSS" %
                      (PLUGIN, hostname, instance, float(offset)))


def check_time_drift(instance, gm_identity=None):
    """Check time drift"""
    ctrl = ptpinstances[instance]
    data = subprocess.check_output(
        [PHC_CTL, ctrl.interface, '-q', 'cmp']).decode()
    offset = 0
    if 'offset from CLOCK_REALTIME is' in data:
        raw_offset = float(data.rsplit(' ', 1)[1].strip('ns\n'))

        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            _info_collecting_samples(obj.hostname, instance, raw_offset,
                                     gm_identity)
        ctrl.log_throttle_count += 1

        # Manage the sample OOT alarm severity
        severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        offset = float(abs(raw_offset) - LEAP_SECOND)
        if abs(offset) > OOT_MAJOR_THRESHOLD:
            severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        elif abs(offset) > OOT_MINOR_THRESHOLD:
            severity = fm_constants.FM_ALARM_SEVERITY_MINOR

        # Handle clearing of Out-Of-Tolerance alarm
        if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
            if ctrl.oot_alarm_object.raised is True:
                if clear_alarm(ctrl.oot_alarm_object.eid) is True:
                    ctrl.oot_alarm_object.severity = \
                        fm_constants.FM_ALARM_SEVERITY_CLEAR
                    ctrl.oot_alarm_object.raised = False
        else:
            # Handle debounce of the OOT alarm.
            # Debounce by 1 for the same severity level.
            if ctrl.oot_alarm_object.severity != severity:
                ctrl.oot_alarm_object.severity = severity

            # This will keep refreshing the alarm text with the current
            # skew value while still debounce on state transitions.
            #
            # Precision ... (PTP) clocking is out of tolerance by 1004 nsec
            #
            elif (severity == fm_constants.FM_ALARM_SEVERITY_MINOR or
                  severity == fm_constants.FM_ALARM_SEVERITY_MAJOR):
                # Handle raising the OOT Alarm.
                rc = raise_alarm(ALARM_CAUSE__OOT, instance, offset)
                if rc is True:
                    ctrl.oot_alarm_object.raised = True

            # Record the value that is alarmable
            if severity != fm_constants.FM_ALARM_SEVERITY_CLEAR:
                collectd.info("%s ; "
                              "PTP instance: %s ; "
                              "Skew:%5d" % (PLUGIN,
                                            instance,
                                            offset))


def check_clock_class(instance):
    ctrl = ptpinstances[instance]
    conf_file = (PTPINSTANCE_PATH + ctrl.instance_type +
                 '-' + instance + '.conf')
    data = subprocess.check_output([PLUGIN_STATUS_QUERY_EXEC, '-f',
                                    conf_file,
                                    '-u', '-b', '0', 'GET GRANDMASTER_SETTINGS_NP']).decode()
    # Save all parameters in an ordered dict
    m = OrderedDict()
    obj.resp = data.split('\n')
    for line in obj.resp:
        if not('GRANDMASTER_SETTINGS_NP' in line):
            # match key value array pairs
            match = re_keyval.search(line)
            if match:
                k = match.group(1)
                v = match.group(2)
                m[k] = v
    current_clock_class = m['clockClass']

    # Determine the base port of the NIC from the interface
    base_port = ctrl.interface[:-1] + '0'
    pci_slot = get_pci_slot(base_port)
    state = CLOCK_STATE_INVALID
    instance_type = PTP_INSTANCE_TYPE_CLOCK
    if base_port == obj.capabilities['primary_nic']:
        state = dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state']
        instance_type = PTP_INSTANCE_TYPE_TS2PHC
    elif dpll_status.get(pci_slot, None):
        if dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state'] != CLOCK_STATE_INVALID:
            state = dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state']
        elif dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state'] != CLOCK_STATE_INVALID:
            state = dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state']
    time_traceable = False
    new_clock_class = current_clock_class
    if state in [CLOCK_STATE_LOCKED, CLOCK_STATE_LOCKED_HO_ACK]:
        new_clock_class = CLOCK_CLASS_6
        time_traceable = True
    elif state == CLOCK_STATE_HOLDOVER:
        new_clock_class = CLOCK_CLASS_7
        time_traceable = True
        # Get the holdover timestamp of the clock/ts2phc instance
        holdover_timestamp = None
        for key, ctrl_obj in ptpinstances.items():
            if ctrl_obj.instance_type == instance_type:
                holdover_timestamp = ctrl_obj.holdover_timestamp

        # If it is in holdover more than the holdover spec threshold,
        # set clock class to 140
        if holdover_timestamp:
            delta = timeutils.delta_seconds(holdover_timestamp,
                                            timeutils.utcnow())
            if delta > HOLDOVER_THRESHOLD:
                new_clock_class = CLOCK_CLASS_140
                time_traceable = False
    else:
        new_clock_class = CLOCK_CLASS_248

    if current_clock_class != new_clock_class:
        # Set clockClass and timeTraceable
        m['clockClass'] = new_clock_class
        m['timeTraceable'] = int(time_traceable)
        parameters = ' '.join("{} {}".format(*i) for i in m.items())
        cmd = 'SET GRANDMASTER_SETTINGS_NP ' + parameters
        collectd.debug("%s cmd=%s" % (PLUGIN, cmd))
        try:
            data = subprocess.check_output(
                [PLUGIN_STATUS_QUERY_EXEC, '-f', conf_file, '-u', '-b', '0', cmd]).decode()
        except subprocess.CalledProcessError as exc:
            collectd.error("%s Failed to set clockClass for instance %s" % (PLUGIN, instance))
        collectd.info("%s instance:%s Updated clockClass from %s to %s timeTraceable=%s" %
                      (PLUGIN, instance, current_clock_class, new_clock_class, time_traceable))


def process_ptp_synce():
    """process ptp synce alarms"""
    # Check GNSS signal status on primary NIC
    # Check SMA/1PPS signal status on secondary NIC

    pin_lookup = {
        'sma1': CGU_PIN_SMA1,
        'sma2': CGU_PIN_SMA2,
        # 'syncE': CGU_PIN_RCLKA
    }
    for instance, ctrl in ptpinstances.items():
        if ctrl.instance_type == PTP_INSTANCE_TYPE_TS2PHC:
            pci_slot = ctrl.pci_slot_name
            state = dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state']
            collectd.debug("%s Monitoring instance:%s interface: %s "
                           "pin:%s states:%s " %
                           (PLUGIN, instance, ctrl.interface, CGU_PIN_GNSS_1PPS,
                            dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]))
            check_gnss_alarm(instance, ctrl.gnss_signal_loss_alarm_object,
                             ctrl.interface, state)
            if state != CLOCK_STATE_LOCKED_HO_ACK:
                if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
                    collectd.info("%s %s not locked to remote GNSS"
                                  % (PLUGIN, obj.hostname))
                ctrl.log_throttle_count += 1
        elif ctrl.instance_type == PTP_INSTANCE_TYPE_CLOCK:
            for interface, pin_function in ctrl.clock_ports.items():
                if interface == obj.capabilities['primary_nic']:
                    # no need to check pins on the primary NIC
                    continue
                for key, function in pin_function.items():
                    if key in pin_lookup.keys():
                        pin = pin_lookup[key]
                    else:
                        # Do not care about the other pins
                        continue
                    pci_slot = ctrl.pci_slot_name
                    collectd.debug("%s Monitoring instance:%s interface: %s "
                                   "pin:%s states:%s " %
                                   (PLUGIN, instance, interface, pin,
                                    dpll_status[pci_slot][pin]))
                    check_gnss_alarm(instance, ctrl.pps_signal_loss_alarm_object,
                                     interface,
                                     dpll_status[pci_slot][pin]['pps_cgu_state'])
            else:
                # No pins are configured for the secondary NIC
                # It checks for alarm with the state of either SMA1 or SMA2 pin.
                pci_slot = ctrl.pci_slot_name
                state = CLOCK_STATE_INVALID
                if dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state'] != CLOCK_STATE_INVALID:
                    state = dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state']
                elif dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state'] != CLOCK_STATE_INVALID:
                    state = dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state']
                collectd.debug("%s Monitoring instance:%s interface: %s "
                               "state:%s " %
                               (PLUGIN, instance, ctrl.interface, state))
                check_gnss_alarm(instance, ctrl.pps_signal_loss_alarm_object,
                                 ctrl.interface, state)

        elif ctrl.instance_type == PTP_INSTANCE_TYPE_PTP4L and ctrl.interface:
            check_time_drift(instance)
            check_clock_class(instance)


#####################################################################
#
# Name       : read_func
#
# Description: The collectd audit entrypoint for PTP Monitoring
#
# Assumptions: collectd calls init_func one time.
#
#              retry init if needed
#              retry fm connect if needed
#              check service enabled state
#              check service running state
#                 error -> alarm host=<hostname>.ptp
#              check
#
#####################################################################
def read_func():

    if obj.virtual is True:
        return 0

    if obj.init_complete is False:
        init_func()
        return 0

    if obj._node_ready is False:
        if obj.node_ready() is False:
            return 0

        try:
            # query FM for existing alarms.
            alarms = api.get_faults_by_id(PLUGIN_ALARMID)
        except Exception as ex:
            collectd.error("%s 'get_faults_by_id' exception ;"
                           " %s ; %s" %
                           (PLUGIN, PLUGIN_ALARMID, ex))
            return 0

        if alarms:
            for alarm in alarms:
                collectd.debug("%s found startup alarm '%s'" %
                               (PLUGIN, alarm.entity_instance_id))

                eid = alarm.entity_instance_id
                if eid is None:
                    collectd.error("%s startup alarm query error ; no eid" %
                                   PLUGIN)
                    continue

                # get the hostname host=<hostname>.stuff
                # split over base eid and then
                # compare that to this plugin's base eid
                # ignore alarms not for this host
                if eid.split('.')[0] != obj.base_eid:
                    continue
                else:
                    # load the state of the specific alarm
                    instance = eid.split('.')[1].split('=')
                    if instance[0] == 'ptp':
                        # clear all ptp alarms on process startup
                        # just in case interface names have changed
                        # since the alarm was raised.
                        if clear_alarm(eid) is False:
                            # if we can't clear the alarm now then error out.
                            collectd.error("%s failed to clear startup "
                                           "alarm %s:%s" %
                                           (PLUGIN, PLUGIN_ALARMID, eid))
                            # try again next time around
                            return 0
                        else:
                            collectd.info("%s cleared startup alarm '%s'" %
                                          (PLUGIN, alarm.entity_instance_id))
                    else:

                        if clear_alarm(eid) is False:
                            collectd.error("%s failed to clear invalid PTP "
                                           "alarm %s:%s" %
                                           (PLUGIN, PLUGIN_ALARMID,
                                            alarm.entity_instance_id))
                            return 0
                        else:
                            collectd.info("%s cleared found invalid startup"
                                          " alarm %s:%s" %
                                          (PLUGIN,
                                           PLUGIN_ALARMID,
                                           alarm.entity_instance_id))
        else:
            collectd.info("%s no startup alarms found" % PLUGIN)

    obj.audits += 1
    for instance_name, ctrl in ptpinstances.items():
        instance = instance_name
        ptp_service = ctrl.instance_type + '@' + instance_name + '.service'
        conf_file = (PTPINSTANCE_PATH + ctrl.instance_type +
                     '-' + instance_name + '.conf')

        # Clock instance does not have a service, thus check non-clock instance type
        if ctrl.instance_type != PTP_INSTANCE_TYPE_CLOCK:
            # This plugin supports PTP in-service state change by checking
            # service state on every audit ; every 5 minutes.
            data = subprocess.check_output([SYSTEMCTL,
                                            SYSTEMCTL_IS_ENABLED_OPTION,
                                            ptp_service]).decode()
            collectd.debug("%s PTP service %s admin state:%s" % (PLUGIN, ptp_service, data.rstrip()))

            if data.rstrip() == SYSTEMCTL_IS_DISABLED_RESPONSE:

                # Manage execution phase
                if ctrl.phase != RUN_PHASE__DISABLED:
                    ctrl.phase = RUN_PHASE__DISABLED
                    ctrl.log_throttle_count = 0

                if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
                    collectd.info("%s PTP Service %s Disabled" % (PLUGIN, ptp_service))
                ctrl.log_throttle_count += 1

                for o in [ctrl.nolock_alarm_object, ctrl.process_alarm_object, ctrl.oot_alarm_object]:
                    if o.raised is True:
                        if clear_alarm(o.eid) is True:
                            o.raised = False
                        else:
                            collectd.error("%s %s:%s clear alarm failed "
                                           "; will retry" %
                                           (PLUGIN, PLUGIN_ALARMID, o.eid))
                continue

            data = subprocess.check_output([SYSTEMCTL,
                                            SYSTEMCTL_IS_ACTIVE_OPTION,
                                            ptp_service]).decode()

            if data.rstrip() == SYSTEMCTL_IS_INACTIVE_RESPONSE:

                # Manage execution phase
                if ctrl.phase != RUN_PHASE__NOT_RUNNING:
                    ctrl.phase = RUN_PHASE__NOT_RUNNING
                    ctrl.log_throttle_count = 0

                if ctrl.process_alarm_object.alarm == ALARM_CAUSE__PROCESS:
                    if ctrl.process_alarm_object.raised is False:
                        collectd.error("%s PTP service %s enabled but not running" %
                                       (PLUGIN, ptp_service))
                        if raise_alarm(ALARM_CAUSE__PROCESS, instance_name) is True:
                            ctrl.process_alarm_object.raised = True

                # clear all other alarms if the 'process' alarm is raised
                elif ctrl.process_alarm_object.raised is True:
                    if clear_alarm(ctrl.process_alarm_object.eid) is True:
                        msg = 'cleared'
                        ctrl.process_alarm_object.raised = False
                    else:
                        msg = 'failed to clear'
                    collectd.info("%s %s %s:%s" %
                                  (PLUGIN, msg, PLUGIN_ALARMID,
                                   ctrl.process_alarm_object.eid))
                continue

            # Handle clearing the 'process' alarm if it is asserted and
            # the process is now running
            if ctrl.process_alarm_object.raised is True:
                if clear_alarm(ctrl.process_alarm_object.eid) is True:
                    ctrl.process_alarm_object.raised = False
                    collectd.info("%s PTP service %s enabled and running" %
                                  (PLUGIN, ptp_service))

            # Auto refresh the timestamping mode in case collectd runs
            # before the ptp manifest or the mode changes on the fly by
            # an in-service manifest.
            # Every 4 audits.
            if (not obj.audits % 4 and
                    ctrl.instance_type == PTP_INSTANCE_TYPE_PTP4L):
                read_timestamp_mode(conf_file)

        # Manage execution phase
        if ctrl.phase != RUN_PHASE__SAMPLING:
            ctrl.phase = RUN_PHASE__SAMPLING
            ctrl.log_throttle_count = 0

        if not obj.capabilities['primary_nic']:
            # Non-synce PTP
            check_ptp_regular(instance, ctrl, conf_file)
        elif (ptpinstances[instance].instance_type in
                [PTP_INSTANCE_TYPE_CLOCK, PTP_INSTANCE_TYPE_TS2PHC]):
            read_dpll_status(ptpinstances[instance].pci_slot_name)

    if obj.capabilities['primary_nic']:
        process_ptp_synce()

    return 0


def check_ptp_regular(instance, ctrl, conf_file):
    # Let's read the port status information
    #
    # sudo /usr/sbin/pmc -u -b 0 'GET PORT_DATA_SET'
    #
    data = subprocess.check_output(
        [PLUGIN_STATUS_QUERY_EXEC, '-f', conf_file, '-u', '-b', '0',
            'GET PORT_DATA_SET']).decode()

    port_locked = False
    obj.resp = data.split('\n')
    for line in obj.resp:
        if 'portState' in line:
            collectd.debug("%s portState : %s" % (PLUGIN, line.split()[1]))
            port_state = line.split()[1]
            if port_state == 'SLAVE':
                port_locked = True

    # Let's read the clock info, Grand Master sig and skew
    #
    # sudo /usr/sbin/pmc -u -b 0 'GET TIME_STATUS_NP'
    #
    data = subprocess.check_output(
        [PLUGIN_STATUS_QUERY_EXEC, '-f', conf_file, '-u', '-b', '0',
            'GET TIME_STATUS_NP']).decode()

    got_master_offset = False
    master_offset = 0
    my_identity = ''
    gm_identity = ''
    gm_present = False
    obj.resp = data.split('\n')
    for line in obj.resp:
        if 'RESPONSE MANAGEMENT TIME_STATUS_NP' in line:
            collectd.debug("%s key       : %s" %
                           (PLUGIN, line.split()[0].split('-')[0]))
            my_identity = line.split()[0].split('-')[0]
        if 'master_offset' in line:
            collectd.debug("%s Offset    : %s" % (PLUGIN, line.split()[1]))
            master_offset = float(line.split()[1])
            got_master_offset = True
        if 'gmPresent' in line:
            collectd.debug("%s gmPresent : %s" % (PLUGIN, line.split()[1]))
            gm_present = line.split()[1]
        if 'gmIdentity' in line:
            collectd.debug("%s gmIdentity: %s" % (PLUGIN, line.split()[1]))
            gm_identity = line.split()[1]

    # Handle case where this host is the Grand Master
    #   ... or assumes it is.
    if my_identity == gm_identity or port_locked is False:
        if ctrl.nolock_alarm_object.raised is False:
            if raise_alarm(ALARM_CAUSE__NO_LOCK, instance, 0) is True:
                ctrl.nolock_alarm_object.raised = True

        # produce a throttled log while this host is not locked to the GM
        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            if instance:
                collectd.info("%s %s %s not locked to remote Grand Master "
                              "(%s)" % (PLUGIN, obj.hostname, instance, gm_identity))
            else:
                collectd.info("%s %s not locked to remote Grand Master "
                              "(%s)" % (PLUGIN, obj.hostname, gm_identity))
        ctrl.log_throttle_count += 1

        # No samples if we are not locked to a Grand Master
        return 0

    # Handle clearing nolock alarm
    elif ctrl.nolock_alarm_object.raised is True:
        if clear_alarm(ctrl.nolock_alarm_object.eid) is True:
            ctrl.nolock_alarm_object.raised = False

    # Keep this FIT test code but make it commented out for security
    # if os.path.exists('/var/run/fit/ptp_data'):
    #     master_offset = 0
    #     with open('/var/run/fit/ptp_data', 'r') as infile:
    #         for line in infile:
    #             master_offset = int(line)
    #             got_master_offset = True
    #             collectd.info("%s using ptp FIT data skew:%d" %
    #                           (PLUGIN, master_offset))
    #             break

    # Send sample and Manage the Out-Of-Tolerance alarm
    if got_master_offset is True:

        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            _info_collecting_samples(obj.hostname, instance, master_offset,
                                     gm_identity)

        ctrl.log_throttle_count += 1

        # setup the sample structure and dispatch
        val = collectd.Values(host=obj.hostname)
        val.type = PLUGIN_TYPE
        val.type_instance = PLUGIN_TYPE_INSTANCE
        val.plugin = 'ptp'
        val.dispatch(values=[float(master_offset)])

        # Manage the sample OOT alarm severity
        severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        if abs(master_offset) > OOT_MAJOR_THRESHOLD:
            severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        elif abs(master_offset) > OOT_MINOR_THRESHOLD:
            severity = fm_constants.FM_ALARM_SEVERITY_MINOR

        # Handle clearing of Out-Of-Tolerance alarm
        if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
            if ctrl.oot_alarm_object.raised is True:
                if clear_alarm(ctrl.oot_alarm_object.eid) is True:
                    ctrl.oot_alarm_object.severity = \
                        fm_constants.FM_ALARM_SEVERITY_CLEAR
                    ctrl.oot_alarm_object.raised = False

        else:
            # Special Case:
            # -------------
            # Don't raise minor alarm when in software timestamping mode.
            # Too much skew in software or legacy mode ; alarm would bounce.
            # TODO: Consider making ptp a real time process
            if severity == fm_constants.FM_ALARM_SEVERITY_MINOR \
                    and obj.mode != 'hardware':
                return 0

            # Handle debounce of the OOT alarm.
            # Debounce by 1 for the same severity level.
            if ctrl.oot_alarm_object.severity != severity:
                ctrl.oot_alarm_object.severity = severity

            # This will keep refreshing the alarm text with the current
            # skew value while still debounce on state transitions.
            #
            # Precision ... (PTP) clocking is out of tolerance by 1004 nsec
            #
            elif (severity == fm_constants.FM_ALARM_SEVERITY_MINOR or
                  severity == fm_constants.FM_ALARM_SEVERITY_MAJOR):
                # Handle raising the OOT Alarm.
                rc = raise_alarm(ALARM_CAUSE__OOT, instance, master_offset)
                if rc is True:
                    ctrl.oot_alarm_object.raised = True

            # Record the value that is alarmable
            if severity != fm_constants.FM_ALARM_SEVERITY_CLEAR:
                collectd.info("%s Grand Master ID: %s ; "
                              "HOST ID: %s ; "
                              "PTP instance: %s ; "
                              "GM Present:%s ; "
                              "Skew:%5d" % (PLUGIN,
                                            gm_identity,
                                            my_identity,
                                            instance,
                                            gm_present,
                                            master_offset))

        if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
            # Check time drift in PHC clock
            check_time_drift(instance, gm_identity)
    else:
        collectd.info("%s No Clock Sync" % PLUGIN)

    return 0


collectd.register_init(init_func)
collectd.register_read(read_func, interval=PLUGIN_AUDIT_INTERVAL)
