#
# Copyright (c) 2019-2024 Wind River Systems, Inc.
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
import socket
import collectd
import configparser
import subprocess
import tsconfig.tsconfig as tsc
import plugin_common as pc
import re
from fm_api import constants as fm_constants
from fm_api import fm_api
from glob import glob
from oslo_utils import timeutils
from functools import lru_cache

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
PTPINSTANCE_PHC2SYS_CONF_FILE_PATTERN = PTPINSTANCE_PATH + 'phc2sys-*.conf'
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

# Phc2sys HA Alarm codes
ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_SELECTION_CHANGE = 20
ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOW_PRIORITY = 21
ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOSS = 22
ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_NO_LOCK = 23
ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_FORCED_SELECTION = 24

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
CLOCK_STATE_LOCKED_HO_ACQ = 'locked_ho_acq'
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
CGU_PIN_SMA_OUTPUT = 'output'

VALID_CGU_PIN_NAMES = [
    CGU_PIN_SDP22,
    CGU_PIN_SDP20,
    CGU_PIN_RCLKA,
    CGU_PIN_RCLKB,
    CGU_PIN_SMA1,
    CGU_PIN_SMA2,
    CGU_PIN_GNSS_1PPS]

# PTP Clock Class
CLOCK_CLASS_6 = '6'      # T-GM connected to PRTC in locked mode
CLOCK_CLASS_7 = '7'      # T-GM in holdover, within holdover specification
CLOCK_CLASS_140 = '140'  # T-GM in holdover, out of holdover specification
CLOCK_CLASS_248 = '248'  # T-GM in free-run mode

# Time interval for holdover within spec (seconds)
# Holdover threshold is set to 4 hours to match the supported holdover time
# for Columbiaville NICs
HOLDOVER_THRESHOLD = 14400

PTP4L_SOURCE_EPRTC = 'ePRTC'
PTP4L_SOURCE_PRTC = 'PRTC'

# G.8275 values are obtained from
# https://www.itu.int/rec/T-REC-G.8275.1-202211-I/en
# See Table V.2 and Table V.3
G8275_CLOCK_ACCURACY_DEFAULT = '0xfe'
G8275_CLOCK_ACCURACY_PRTC = '0x20'
G8275_CLOCK_ACCURACY_EPRTC = '0x21'

G8275_OFFSET_SCALED_LOG_VARIANCE_DEFAULT = '0xffff'
G8275_OFFSET_SCALED_LOG_VARIANCE_PRTC = '0x4e5d'
G8275_OFFSET_SCALED_LOG_VARIANCE_EPRTC = '0x4b32'

G8275_TIME_SOURCE_DEFAULT = '0xa0'
G8275_TIME_SOURCE_GPS = '0x20'
G8275_TIME_SOURCE_PTP = '0x40'

G8275_PRC_LOCKED = {
    'ePRTC': {
        'clockAccuracy': G8275_CLOCK_ACCURACY_EPRTC,
        'offsetScaledLogVariance': G8275_OFFSET_SCALED_LOG_VARIANCE_EPRTC,
        'timeSource': G8275_TIME_SOURCE_GPS,
        'timeTraceable': True,
        'frequencyTraceable': True
    },
    'PRTC': {
        'clockAccuracy': G8275_CLOCK_ACCURACY_PRTC,
        'offsetScaledLogVariance': G8275_OFFSET_SCALED_LOG_VARIANCE_PRTC,
        'timeSource': G8275_TIME_SOURCE_GPS,
        'timeTraceable': True,
        'frequencyTraceable': True
    }
}

G8275_PRC_HOLDOVER = {
    'ePRTC': {
        'clockAccuracy': G8275_CLOCK_ACCURACY_DEFAULT,
        'offsetScaledLogVariance': G8275_OFFSET_SCALED_LOG_VARIANCE_DEFAULT,
        'timeSource': G8275_TIME_SOURCE_DEFAULT,
        'timeTraceable': True,
        'frequencyTraceable': True
    },
    'PRTC': {
        'clockAccuracy': G8275_CLOCK_ACCURACY_DEFAULT,
        'offsetScaledLogVariance': G8275_OFFSET_SCALED_LOG_VARIANCE_DEFAULT,
        'timeSource': G8275_TIME_SOURCE_DEFAULT,
        'timeTraceable': True,
        'frequencyTraceable': True
    }
}

G8275_PRC_FREERUN = {
    'ePRTC': {
        'clockAccuracy': G8275_CLOCK_ACCURACY_DEFAULT,
        'offsetScaledLogVariance': G8275_OFFSET_SCALED_LOG_VARIANCE_DEFAULT,
        'timeSource': G8275_TIME_SOURCE_DEFAULT,
        'timeTraceable': False,
        'frequencyTraceable': False
    },
    'PRTC': {
        'clockAccuracy': G8275_CLOCK_ACCURACY_DEFAULT,
        'offsetScaledLogVariance': G8275_OFFSET_SCALED_LOG_VARIANCE_DEFAULT,
        'timeSource': G8275_TIME_SOURCE_DEFAULT,
        'timeTraceable': False,
        'frequencyTraceable': False
    }
}


# regex pattern match
re_dict = re.compile(r'^(\w+)\s+(\w+)')
re_blank = re.compile(r'^\s*$')
re_keyval = re.compile(r'^\s*(\S+)\s+(\S+)')

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

    def __init__(self, instance_type=PTP_INSTANCE_TYPE_PTP4L):
        self.instance_type = instance_type
        self.log_throttle_count = 0
        self.phase = 0
        self.config_data = None
        self.holdover_timestamp = None
        self.interface = None
        self.pci_slot_name = None
        self.timing_instance = None
        self.phc2sys_ha_enabled = False
        self.prtc_present = False
        self.dpll_pci_slots = []
        self.interface_list = []
        self.clock_ports = {}

        # Ptp4l G.8275 variables
        self.ptp4l_prtc_type = PTP4L_SOURCE_PRTC
        self.ptp4l_current_utc_offset = 37
        self.ptp4l_current_utc_offset_valid = '0'
        self.ptp4l_clock_accuracy = None
        self.ptp4l_clock_class = None
        self.ptp4l_clock_identity = None
        self.ptp4l_grandmaster_identity = None
        self.ptp4l_offset_scaled_log_variance = None
        self.ptp4l_prc_state = None
        self.ptp4l_time_source = None
        self.ptp4l_utc_offset_nanoseconds = None
        self.ptp4l_announce_settings = {}

        # Alarm objects
        self.nolock_alarm_object = None
        self.process_alarm_object = None
        self.oot_alarm_object = None
        self.gnss_signal_loss_alarm_object = None
        self.pps_signal_loss_alarm_object = None
        self.phc2sys_clock_source_selection_change = None
        self.phc2sys_clock_source_low_priority = None
        self.phc2sys_clock_source_loss = None
        self.phc2sys_clock_source_no_lock = None
        self.phc2sys_clock_source_forced_selection = None


# Parameter in sysfs device/uevent file
PCI_SLOT_NAME = 'PCI_SLOT_NAME'

# PTP crtl objects for each PTP instances
ptpinstances = {}

# Mapping of ptp interfaces to instances
ptpinterfaces = {}

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
    collectd.info("%s PTP Instances: %s" % (PLUGIN, ptpinstances))
    collectd.info("%s PTP Interfaces: %s" % (PLUGIN, ptpinterfaces))
    for o in ALARM_OBJ_LIST:
        print_alarm_object(o)


# Interface:Supported Modes dictionary. key:value
#
# interface:modes
#
interfaces = {}

# ts2phc_source_interfaces dictionary
#
# source_interface:primary_interface
ts2phc_source_interfaces = {}
ts2phc_instance_map = {}

# List of timing instances
timing_instance_list = []


def read_files_for_timing_instances():
    """read phc2sys conf files"""
    filenames = glob(PTPINSTANCE_PHC2SYS_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.debug("%s No PTP conf file located for %s" %
                       (PLUGIN, "phc2sys"))
    else:
        for filename in filenames:
            instance = TimingInstance(filename)
            if not instance.interfaces:
                collectd.info("%s No interfaces configured for instance %s, "
                              "not enabling HA monitoring; deleting instance"
                              % (PLUGIN, instance.instance_name))
            elif 'ha_enabled' in instance.config['global'].keys() \
                    and instance.config['global']['ha_enabled'] == '1':
                ptpinstances[instance.instance_name].timing_instance = instance
                ptpinstances[instance.instance_name].phc2sys_ha_enabled = True
                collectd.info("%s Found HA enabled phc2sys instance %s" %
                              (PLUGIN, instance.instance_name))
            else:
                collectd.info("%s Phc2sys instance %s is not HA enabled, not enabling HA monitoring"
                              "; deleting instance"
                              % (PLUGIN, instance.instance_name))
                del instance


class TimingInstance:
    """The purpose of TimingInstance is to track the config and state data of a ptp instance"""

    """By supplying a config file path, a TimingInstance object will parse and store the instance
    configuration into a dict and provide functions for reading the state datafor each instance.

    At this time, only the phc2sys instance type is in use, but some of the other basic instance
    functions have been defined for future enhancements."""

    def __init__(self, config_file_path) -> None:
        self.config_file_path = config_file_path
        self.interfaces = set()  # use a python set to prevent duplicates
        self.config = {}  # dict of params from config file
        self.state = {}  # dict to hold the values read from pmc or cgu

        # synce4l handling to be included when full synce4l support is implemented
        self.instance_types = ["clock", "phc2sys", "ptp4l", "ts2phc"]
        self.config_parsers_dict = {"clock": self.parse_clock_config,
                                    "phc2sys": self.parse_phc2sys_config,
                                    "ptp4l": self.parse_ptp4l_config,
                                    "ts2phc": self.parse_ts2phc_config}

        self.state_setter_dict = {"phc2sys": self.set_phc2sys_state}

        # Determine instance name and type
        # Instance is guaranteed to be one of the valid types because that was checked in
        # read_files_for_timing_instances()
        for item in self.instance_types:
            pattern = item + '-(.*?)' + '.conf'
            try:
                instance = re.search(pattern, config_file_path).group(1)
            except AttributeError:
                instance = None
            if instance:
                collectd.info("%s Config file %s matches instance type %s"
                              % (PLUGIN, config_file_path, item))
                self.instance_type = item
                self.instance_name = instance

        # Select the appropriate parser to initialize self.interfaces and self.config
        self.parse_instance_config()

        if self.instance_type == PTP_INSTANCE_TYPE_PHC2SYS:
            self.init_phc2sys_ha_state()
        else:
            self.set_instance_state_data

    def parse_instance_config(self):
        # Select parser function from config_parsers_dict using instance_type as key
        # and run the parser
        collectd.info("%s Calling %s config parser for %s" % (
            PLUGIN, self.instance_type, self.config_file_path))
        self.config = self.config_parsers_dict[self.instance_type]()

    def set_instance_state_data(self):
        collectd.debug("%s Setting state for %s" %
                       (PLUGIN, self.instance_name))
        self.state_setter_dict[self.instance_type]()

    def parse_clock_config(self) -> dict:
        # Clock config is not an .ini style format, parse it manually
        # Not currently used
        config = {}
        clock_config_lines = []
        with open(self.config_file_path, 'r') as infile:
            # Strip blank lines
            lines = filter(None, (line.rstrip() for line in infile))
            for line in lines:
                clock_config_lines.append(line.strip())
                if 'ifname' in line:
                    continue
                if 'base_port' in line:
                    interface = line.split(']')[0].split('[')[1]
                    if interface:
                        self.interfaces.add(interface)
                        config[interface] = {}

        for interface in self.interfaces:
            # Once we know the interfaces, we can iterate through the lines and collect the
            # parameters
            start = interface
            end = 'ifname'
            copy = False
            for line in clock_config_lines:
                if start in line:
                    copy = True
                    continue
                elif end in line:
                    copy = False
                elif copy:
                    config[interface].update(
                        {line.split()[0]: line.split()[1]})
        return config

    def parse_ptp4l_config(self):
        # Not currently used
        # https://docs.python.org/3/library/configparser.html
        # You can access the parameters like so:
        # config['global']['parameter_name']
        # or
        # config['ens0f0']['parameter_name']"""
        config = configparser.ConfigParser(delimiters=' ')
        config.read(self.config_file_path)
        for item in config.sections():
            # unicast_master_table is a special section in ptp4l configs
            # It is only used by ptp4l itself and can be ignored by collectd
            if item != "global" and item != "unicast_master_table":
                self.interfaces.add(item)
        return config

    def parse_phc2sys_config(self):
        config = configparser.ConfigParser(delimiters=' ')
        config.read(self.config_file_path)
        for item in config.sections():
            if item != "global":
                self.interfaces.add(item)
        return config

    def parse_ts2phc_config(self):
        # Not currently used
        config = configparser.ConfigParser(delimiters=' ')
        config.read(self.config_file_path)
        for item in config.sections():
            if item != "global":
                self.interfaces.add(item)
        return config

    def init_phc2sys_ha_state(self):
        # Special handling for HA phc2sys
        if 'ha_enabled' in self.config['global'].keys() \
                and self.config['global']['ha_enabled'] == '1':

            # Set phc2sys communication socket
            self.phc2sys_com_socket = self.config['global'].get(
                'ha_phc2sys_com_socket', None)

            # Select the appropriate function to set instance state
            collectd.info("Initializing %s instance %s" %
                          (self.instance_type, self.instance_name))
            self.set_instance_state_data()

            # Add a state field to track the highest source priority value
            self.state['highest_source_priority'] = 0

            # Create alarm objects
            for interface in self.interfaces:
                create_interface_alarm_objects(interface, self.instance_name,
                                               PTP_INSTANCE_TYPE_PHC2SYS)

                # Set the highest source priority
                source_priority = int(self.config[interface]['ha_priority'])
                if source_priority > self.state['highest_source_priority']:
                    self.state['highest_source_priority'] = source_priority

    def set_phc2sys_state(self):
        collectd.debug("%s Setting state for phc2sys instance %s" %
                       (PLUGIN, self.instance_name))
        self.state['phc2sys_source_interface'] = self.query_phc2sys_socket('clock source',
                                                                           self.phc2sys_com_socket)
        self.state['phc2sys_forced_lock'] = self.query_phc2sys_socket('forced lock',
                                                                      self.phc2sys_com_socket)
        self.state['phc2sys_valid_sources'] = self.query_phc2sys_socket('valid sources',
                                                                        self.phc2sys_com_socket)

    def query_phc2sys_socket(self, query, unix_socket=None):
        if unix_socket:
            try:
                client_socket = socket.socket(
                    socket.AF_UNIX, socket.SOCK_STREAM)
                client_socket.connect(unix_socket)
                client_socket.send(query.encode())
                response = client_socket.recv(1024)
                response = response.decode()
                if response == "None":
                    response = None
                return response
            except ConnectionRefusedError as err:
                collectd.info("%s Error connecting to phc2sys socket for instance %s: %s" % (
                    PLUGIN, self.instance_name, err))
                return None
            except FileNotFoundError as err:
                collectd.info("%s Error connecting to phc2sys socket for instance %s: %s" % (
                    PLUGIN, self.instance_name, err))
                return None
            finally:
                if hasattr(client_socket, 'close'):
                    client_socket.close()
        else:
            collectd.warning(
                "%s No socket path supplied for instance %s" % (PLUGIN, self.instance_name))
            return None


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
def raise_alarm(alarm_cause,
                source=None,
                data=0,
                alarm_object=None,
                alarm_state=fm_constants.FM_ALARM_STATE_SET):
    """Assert a cause based PTP alarm"""

    collectd.debug("%s Raising Alarm %d" % (PLUGIN, alarm_cause))

    if not alarm_object:
        alarm = get_alarm_object(alarm_cause, source)
    else:
        alarm = alarm_object

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
        reason += ' state: ' + str(data)

    elif alarm_cause == ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOW_PRIORITY:
        reason += ' interface: ' + str(data)

    elif alarm_cause == ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_NO_LOCK:
        reason += ' clockClass: ' + str(data)

    try:
        fault = fm_api.Fault(
            alarm_id=PLUGIN_ALARMID,
            alarm_state=alarm_state,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=alarm.eid,
            severity=alarm.severity,
            reason_text=reason,
            alarm_type=obj.alarm_type,
            probable_cause=alarm.cause,
            proposed_repair_action=alarm.repair,
            service_affecting=False,  # obj.service_affecting,
            suppression=True)  # obj.suppression)

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
def create_interface_alarm_objects(interface, instance=None, instance_type=PTP_INSTANCE_TYPE_PTP4L):
    """Create alarm objects"""

    collectd.debug("%s Alarm Object Create: Interface:%s, Instance: %s " %
                   (PLUGIN, interface, instance))

    if instance and not ptpinstances.get(instance, None):
        ctrl = PTP_ctrl_object(instance_type)
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
        # Ts2phc allows only a single GNSS source, create a single alarm obj for it
        o.alarm = ALARM_CAUSE__GNSS_SIGNAL_LOSS
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' GNSS signal loss'
        o.repair = 'Check network'
        o.eid = obj.base_eid + '.interface=' + interface + '.ptp=GNSS-signal-loss'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # loss-of-signal
        ALARM_OBJ_LIST.append(o)
        ctrl.gnss_signal_loss_alarm_object = o

        o = PTP_alarm_object(instance)
        # Clock source selection change
        o.alarm = ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_SELECTION_CHANGE
        o.severity = fm_constants.FM_ALARM_SEVERITY_WARNING
        o.reason = obj.hostname
        o.reason += ' phc2sys HA source selection algorithm selected secondary source'
        o.repair += 'Check network'
        o.eid = obj.base_eid + '.interface=' + interface + '.phc2sys=source-failover'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_51  # timing-problem
        ALARM_OBJ_LIST.append(o)
        ctrl.phc2sys_clock_source_selection_change = o

        o = PTP_alarm_object(instance)
        # No clock source
        o.alarm = ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOSS
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' phc2sys HA has no source clock'
        o.repair += 'Check phc2sys configuration'
        o.eid = obj.base_eid + '.phc2sys=' + instance + '.phc2sys=no-source-clock'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_7  # 'config error'
        ALARM_OBJ_LIST.append(o)
        ctrl.phc2sys_clock_source_loss = o

        o = PTP_alarm_object(instance)
        # Forced source selection
        o.alarm = ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_FORCED_SELECTION
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' phc2sys HA automatic source selection has been disabled. '
        o.reason += 'Secondary clock sources will not be used.'
        o.repair += 'Check phc2sys configuration'
        o.eid = obj.base_eid + '.phc2sys=' + instance + '.phc2sys=forced-clock-selection'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN
        ALARM_OBJ_LIST.append(o)
        ctrl.phc2sys_clock_source_forced_selection = o

        o = PTP_alarm_object(instance)
        # Source clock low priority
        o.alarm = ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOW_PRIORITY
        o.severity = fm_constants.FM_ALARM_SEVERITY_MINOR
        o.reason = obj.hostname
        o.reason += ' phc2sys HA has selected a lower priority clock source.'
        o.repair += 'Check network'
        o.eid = obj.base_eid + '.phc2sys=' + instance + \
            '.phc2sys=source-clock-low-priority'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN
        ALARM_OBJ_LIST.append(o)
        ctrl.phc2sys_clock_source_low_priority = o

        ptpinstances[instance] = ctrl

    if interface and not ptpinterfaces.get(interface, None):
        # Create required interface based alarm objects for supplied interface
        o = PTP_alarm_object(interface)
        # 1-PPS signal loss
        o.alarm = ALARM_CAUSE__1PPS_SIGNAL_LOSS
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' 1PPS signal loss'
        o.repair = 'Check network'
        o.eid = obj.base_eid + '.interface=' + interface + '.ptp=1PPS-signal-loss'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # loss-of-signal
        ALARM_OBJ_LIST.append(o)

        o = PTP_alarm_object(interface)
        # Clock source selection change
        o.alarm = ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_SELECTION_CHANGE
        o.severity = fm_constants.FM_ALARM_SEVERITY_WARNING
        o.reason = obj.hostname
        o.reason += ' phc2sys HA source selection algorithm selected new active source'
        o.repair += 'Check network'
        o.eid = obj.base_eid + '.phc2sys=' + instance + '.interface=' + interface\
            + '.phc2sys=source-failover'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_51  # timing-problem
        ALARM_OBJ_LIST.append(o)

        o = PTP_alarm_object(interface)
        # Source clock no lock
        o.alarm = ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_NO_LOCK
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname
        o.reason += ' phc2sys HA source clock is not locked to a PRC'
        o.repair += 'Check network and ptp4l configuration'
        o.eid = obj.base_eid + '.phc2sys=' + instance + '.interface=' + interface + \
            '.phc2sys=source-clock-no-prc-lock'
        o.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # loss-of-signal
        ALARM_OBJ_LIST.append(o)

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

        # Add interface to ptpinterfaces dict if not present
        ptpinterfaces[interface] = []

    # Map instance to ptp interface
    ptpinterfaces[interface].append(instance)


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


def query_pmc(instance, query_string, uds_address=None, query_action='GET') -> dict:
    ctrl = ptpinstances[instance]
    data = {}
    query = query_action + ' ' + query_string
    if uds_address:
        try:
            data = subprocess.check_output([PLUGIN_STATUS_QUERY_EXEC, '-s', uds_address,
                                            '-u', '-b', '0', query]).decode()
        except subprocess.CalledProcessError as err:
            collectd.warning("%s Failed to query pmc: %s" % (PLUGIN, err))
            return data
    else:
        conf_file = (PTPINSTANCE_PATH + ctrl.instance_type +
                     '-' + instance + '.conf')
        try:
            data = subprocess.check_output([PLUGIN_STATUS_QUERY_EXEC, '-f', conf_file,
                                            '-u', '-b', '0', query]).decode()
        except subprocess.CalledProcessError as err:
            collectd.warning("%s Failed to query pmc: %s" % (PLUGIN, err))
            return data

    # Save all parameters in an ordered dict
    query_results_dict = OrderedDict()
    obj.resp = data.split('\n')
    for line in obj.resp:
        if not (query_string in line):
            # match key value array pairs
            match = re_keyval.search(line)
            if match:
                k = match.group(1)
                v = match.group(2)
                query_results_dict[k] = v
    return query_results_dict


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
                        if interface and interface != 'global' \
                                and interface != 'unicast_master_table':
                            # unicast_master_table is a special section in some ptp4l configs
                            # It can be ignored by collectd
                            if (ptpinstances[instance] and
                                    ptpinstances[instance].interface == interface):
                                # ignore the duplicate interface in the file
                                continue
                            interfaces[interface] = _get_supported_modes(
                                interface)
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

            ptpinstances[instance].config_data = configparser.ConfigParser(
                delimiters=' ')
            ptpinstances[instance].config_data.read(filename)


def initialize_ptp4l_state_fields(instance):
    ctrl = ptpinstances[instance]

    # Determine if there is a ts2phc instance disciplining this NIC
    base_port = ctrl.interface[:-1] + '0'
    pci_slot = get_pci_slot(base_port)
    mapped_ts2phc_instance = None

    if pci_slot in ts2phc_instance_map.keys():
        mapped_ts2phc_instance = ts2phc_instance_map[pci_slot]
        collectd.info("%s ptp4l instance %s is mapped to ts2phc instance %s"
                      % (PLUGIN, instance, mapped_ts2phc_instance))
        ctrl.prtc_present = True
        collectd.info("%s Instance %s PRTC present" % (PLUGIN, instance))
    else:
        ctrl.prtc_present = False
        collectd.info("%s Instance %s PRTC not present" % (PLUGIN, instance))

    # Read any configured G.8275.x field values, set to default if not present
    if ctrl.config_data.has_section('global'):
        ctrl.ptp4l_clock_accuracy = \
            ctrl.config_data['global'].get(
                'clockAccuracy', G8275_CLOCK_ACCURACY_PRTC).lower()
        ctrl.ptp4l_offset_scaled_log_variance = \
            ctrl.config_data['global'].get('offsetScaledLogVariance',
                                           G8275_OFFSET_SCALED_LOG_VARIANCE_PRTC).lower()
        ctrl.ptp4l_time_source = \
            ctrl.config_data['global'].get(
                'timeSource', G8275_TIME_SOURCE_GPS).lower()

    # Determine utcOffsetValid
    data = query_pmc(instance, 'GRANDMASTER_SETTINGS_NP', query_action='GET')
    if 'currentUtcOffsetValid' in data.keys():
        ctrl.ptp4l_current_utc_offset_valid = data['currentUtcOffsetValid']
    else:
        ctrl.ptp4l_current_utc_offset_valid = 0
    collectd.info("%s Instance %s currentUtcOffsetValid is initialized to %s"
                  % (PLUGIN, instance, str(ctrl.ptp4l_current_utc_offset_valid)))

    # Determine clockIdentity
    default_data_set = query_pmc(
        instance, 'DEFAULT_DATA_SET', query_action='GET')
    if 'clockIdentity' in default_data_set.keys():
        ctrl.ptp4l_clock_identity = default_data_set['clockIdentity']
    else:
        ctrl.ptp4l_clock_identity = None
    collectd.info("%s Instance %s clockIdentity is %s"
                  % (PLUGIN, instance, ctrl.ptp4l_clock_identity))

    # Determine currentUtcOffset
    if ctrl.config_data.has_section('global') and 'utc_offset' in ctrl.config_data['global'].keys():
        ctrl.ptp4l_current_utc_offset = ctrl.config_data['global']['utc_offset']
        collectd.info("%s Instance %s currentUtcOffset is initialized to %s"
                      % (PLUGIN, instance, str(ctrl.ptp4l_current_utc_offset)))
    else:
        # currentUtcOffset is not configured, use existing default
        ctrl.ptp4l_current_utc_offset = data['currentUtcOffset']
        collectd.info("%s Instance %s currentUtcOffset is not specified, initializing to %s"
                      % (PLUGIN, instance, str(ctrl.ptp4l_current_utc_offset)))


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


def convert_nmea_serialport_to_pci_addr(nmea_serialport):
    # Remove the /dev portion of the path
    pci_addr = None
    serialport = nmea_serialport.split('/')[2]
    uevent_file = '/sys/class/gnss/' + serialport + '/device/uevent'

    try:
        with open(uevent_file, 'r') as file:
            for line in file:
                if 'PCI_SLOT_NAME' in line:
                    # Regex split in '=' sign
                    pci_addr = re.split('=', line)[1].strip('\n')
                    break
    except (FileNotFoundError, PermissionError) as err:
        collectd.warning("%s Invalid NMEA serial port: %s" %
                         (PLUGIN, err))
    return pci_addr


def read_ts2phc_config():
    """read ts2phc conf files"""
    filenames = glob(PTPINSTANCE_TS2PHC_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.info("%s No ts2phc conf file configured" % PLUGIN)
        return
    else:
        # Handle one or more ts2phc instances. Multiple instances may be present for HA phc2sys
        for filename in filenames:
            instance = filename.split('ts2phc-')[1].split('.conf')[0]
            with open(filename, 'r') as infile:
                pci_slot = None
                for line in infile:
                    if 'ts2phc.nmea_serialport' in line:
                        tty = line.split(' ')[1].strip('\n')
                        pci_slot = convert_nmea_serialport_to_pci_addr(tty)
                        interface = find_interface_from_pciaddr(pci_slot)
                        create_interface_alarm_objects(interface, instance)
                        ptpinstances[instance].instance_type = \
                            PTP_INSTANCE_TYPE_TS2PHC
                        # Save the PCI slot for the ttyGNSS device
                        ptpinstances[instance].pci_slot_name = pci_slot
                        # Add the PCI slot to list of dplls this instance owns
                        ptpinstances[instance].dpll_pci_slots.append(pci_slot)
                        # Initialize dpll fields
                        init_dpll_status(pci_slot)
                        ts2phc_source_interfaces[pci_slot] = pci_slot
                        ts2phc_instance_map[pci_slot] = instance
                        obj.capabilities['primary_nic'] = interface

                        collectd.info("%s ts2phc instance:%s slot:%s primary_nic:%s" %
                                      (PLUGIN, instance, pci_slot,
                                       obj.capabilities['primary_nic']))
                        continue
                    # Find the configured interfaces and map them to the primary source interface
                    elif line[0] == '[':
                        interface = line.split(']')[0].split('[')[1]
                        if interface and interface != 'global':
                            base_port = interface[:-1] + '0'
                            secondary_ts2phc_pci = get_pci_slot(
                                base_port)
                            if secondary_ts2phc_pci != pci_slot:
                                ts2phc_source_interfaces[secondary_ts2phc_pci] = pci_slot
                                ts2phc_instance_map[secondary_ts2phc_pci] = instance
                                # Add the secondary PCI slot to list of owned dplls
                                ptpinstances[instance].dpll_pci_slots.append(
                                    secondary_ts2phc_pci)
                                # Initialize dpll fields
                                init_dpll_status(secondary_ts2phc_pci)
            collectd.info("%s Instance: %s DPLL PCI Slots: %s" % (
                PLUGIN, instance, ptpinstances[instance].dpll_pci_slots))


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
                    create_interface_alarm_objects(interface, instance)
                    ptpinstances[instance].instance_type = \
                        PTP_INSTANCE_TYPE_CLOCK
                    slot = get_pci_slot(interface)
                    ptpinstances[instance].pci_slot_name = slot
                    # Add PCI slot to list of owned dplls
                    ptpinstances[instance].dpll_pci_slots.append(slot)
                    # Initialize dpll fields
                    init_dpll_status(slot)
                    found_port = True
                    ptpinstances[instance].clock_ports[interface] = {}
            elif found_port:
                match = re_dict.search(line)
                if match:
                    k = match.group(1)
                    v = match.group(2)
                    m[k] = v
                    ptpinstances[instance].clock_ports[interface] = m
                m = {}
    if found_port:
        collectd.info("%s instance: %s ports: %s dpll slots: %s" %
                      (PLUGIN, instance, ptpinstances[instance].clock_ports,
                       ptpinstances[instance].dpll_pci_slots))
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
        # Initialize TimingInstance for HA phc2sys
        read_files_for_timing_instances()

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

    for instance in ptpinstances:
        if ptpinstances[instance].instance_type == PTP_INSTANCE_TYPE_PTP4L:
            initialize_ptp4l_state_fields(instance)

    if tsc.nodetype == 'controller':
        obj.controller = True

    obj.virtual = obj.is_virtual()

    obj.init_completed()
    return 0


def handle_ptp4l_g8275_fields(instance):
    """set the required parameters for g8275 conformance"""
    ctrl = ptpinstances[instance]
    previous_grandmaster_identity = ctrl.ptp4l_grandmaster_identity
    previous_clock_class = ctrl.ptp4l_clock_class

    if ctrl.config_data.has_section('global') \
            and 'dataset_comparison' not in ctrl.config_data['global'].keys():
        collectd.info(
            "%s G.8275.x profile is not enabled for instance %s" % (PLUGIN, instance))
        return

    data_grandmaster_settings = query_pmc(
        instance, 'GRANDMASTER_SETTINGS_NP', query_action='GET')

    parent_data_set = query_pmc(
        instance, 'PARENT_DATA_SET', query_action='GET')
    if 'grandmasterIdentity' in parent_data_set.keys():
        ctrl.ptp4l_grandmaster_identity = parent_data_set['grandmasterIdentity']

    default_data_set = query_pmc(
        instance, 'DEFAULT_DATA_SET', query_action='GET')
    number_ports = default_data_set.get('numberPorts', '0')
    if ctrl.ptp4l_clock_identity is None:
        if 'clockIdentity' in default_data_set.keys():
            ctrl.ptp4l_clock_identity = default_data_set['clockIdentity']

    if 'gm.ClockClass' in parent_data_set.keys():
        ctrl.ptp4l_clock_class = parent_data_set['gm.ClockClass']

    if ctrl.ptp4l_prc_state in [CLOCK_STATE_LOCKED,
                                CLOCK_STATE_LOCKED_HO_ACK,
                                CLOCK_STATE_LOCKED_HO_ACQ]:
        # PRC is locked
        # Use the values configured by initialize_ptp4l_state_fields()
        ctrl.ptp4l_announce_settings['clockAccuracy'] = ctrl.ptp4l_clock_accuracy
        ctrl.ptp4l_announce_settings['offsetScaledLogVariance'] = \
            ctrl.ptp4l_offset_scaled_log_variance
        ctrl.ptp4l_announce_settings['timeSource'] = ctrl.ptp4l_time_source

    elif ctrl.ptp4l_prc_state == CLOCK_STATE_HOLDOVER:
        # PRC is holdover
        ctrl.ptp4l_announce_settings['clockAccuracy'] =  \
            G8275_PRC_HOLDOVER[ctrl.ptp4l_prtc_type]['clockAccuracy']
        ctrl.ptp4l_announce_settings['offsetScaledLogVariance'] = \
            G8275_PRC_HOLDOVER[ctrl.ptp4l_prtc_type]['offsetScaledLogVariance']
        ctrl.ptp4l_announce_settings['timeSource'] = \
            G8275_PRC_HOLDOVER[ctrl.ptp4l_prtc_type]['timeSource']

    elif ctrl.ptp4l_prc_state in [CLOCK_STATE_INVALID, CLOCK_STATE_FREERUN]:
        # PRC is freerun
        ctrl.ptp4l_announce_settings['clockAccuracy'] =  \
            G8275_PRC_FREERUN[ctrl.ptp4l_prtc_type]['clockAccuracy']
        ctrl.ptp4l_announce_settings['offsetScaledLogVariance'] = \
            G8275_PRC_FREERUN[ctrl.ptp4l_prtc_type]['offsetScaledLogVariance']
        ctrl.ptp4l_announce_settings['timeSource'] = \
            G8275_PRC_FREERUN[ctrl.ptp4l_prtc_type]['timeSource']

    new_clock_class = previous_clock_class
    if previous_grandmaster_identity != ctrl.ptp4l_grandmaster_identity \
            and ctrl.prtc_present is False:
        # GM for this node just changed
        if ctrl.ptp4l_grandmaster_identity == ctrl.ptp4l_clock_identity:
            # We became a GM
            if int(number_ports) > 1:
                new_clock_class = '165'
            else:
                new_clock_class = '248'
            ctrl.ptp4l_announce_settings['timeTraceable'] = '0'
            ctrl.ptp4l_clock_class = new_clock_class
            ctrl.ptp4l_announce_settings['clockClass'] = new_clock_class
            collectd.info("%s Local clock is GM for instance %s: %s"
                          % (PLUGIN, instance, ctrl.ptp4l_grandmaster_identity))
        else:
            # Fields will be set according to new GM announcements
            collectd.info("%s New GM selected for instance %s: %s"
                          % (PLUGIN, instance, ctrl.ptp4l_grandmaster_identity))

    gm_settings_to_write = OrderedDict(data_grandmaster_settings)
    gm_settings_to_write.update(ctrl.ptp4l_announce_settings)
    if data_grandmaster_settings != gm_settings_to_write:
        collectd.info("%s Updating announce fields for instance %s" %
                      (PLUGIN, instance))
        write_ptp4l_gm_fields(instance, gm_settings_to_write)


def write_ptp4l_gm_fields(instance, gm_fields_dict):
    """update the pmc GRANDMASTER_SETTINGS_NP values"""
    ctrl = ptpinstances[instance]
    conf_file = (PTPINSTANCE_PATH + ctrl.instance_type +
                 '-' + instance + '.conf')
    parameters = ' '.join("{} {}".format(*i) for i in gm_fields_dict.items())
    cmd = 'SET GRANDMASTER_SETTINGS_NP ' + parameters
    collectd.debug("%s cmd=%s" % (PLUGIN, cmd))
    try:
        data = subprocess.check_output(
            [PLUGIN_STATUS_QUERY_EXEC, '-f', conf_file, '-u', '-b', '0', cmd]).decode()
    except subprocess.CalledProcessError as exc:
        collectd.error(
            "%s Failed to write GM settings for instance %s: %s" % (PLUGIN, instance, exc))
    collectd.info("%s instance: %s wrote gm settings %s" %
                  (PLUGIN, instance, gm_fields_dict))


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
                            pin = line.split('|')[0].strip().split(
                                '(')[0].rstrip()
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


@lru_cache()
def _get_proc_cmdline(instance, pidfile_path):
    pidfile = pidfile_path + "phc2sys-" + instance + ".pid"
    with open(pidfile, 'r') as f:
        pid = f.readline().strip()
    # Get command line params
    cmdline_file = "/proc/" + pid + "/cmdline"
    with open(cmdline_file, 'r') as f:
        cmdline_args = f.readline().strip()
    cmdline_args = cmdline_args.split("\x00")

    return cmdline_args


def _get_phc2sys_command_line_option(instance, pidfile_path, flag):
    try:
        cmdline_args = _get_proc_cmdline(instance, pidfile_path)
    except OSError as ex:
        collectd.debug("%s Cannot get cmdline for instance %s. %s" %
                       (PLUGIN, instance, ex))
        return None
    if cmdline_args is None:
        return None

    # The option value will be at the index after the flag
    try:
        index = cmdline_args.index(flag)
    except ValueError as ex:
        collectd.debug("%s Flag not found in cmdline args. %s" % (PLUGIN, ex))
        return None
    value = cmdline_args[index + 1]
    collectd.debug("%s %s value is %s" % (PLUGIN, flag, value))
    return value


def check_phc2sys_offset():
    """check if phc2sys offset is set"""
    phc2sysinstances = set()
    filenames = glob(PTPINSTANCE_PHC2SYS_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.info("%s No phc2sys conf file configured" % PLUGIN)
        return
    else:
        for filename in filenames:
            pattern = PTP_INSTANCE_TYPE_PHC2SYS + '-(.*?)' + '.conf'
            instance = re.search(pattern, filename).group(1)
            phc2sysinstances.add(instance)

    pidfile_path = '/var/run/'
    offset = None
    # Verify that a phc2sys instance is disciplining the system clock.
    # If -c flag is absent or -c is CLOCK_REALTIME (default) we can assume the
    # system clock is being disciplined
    found_disciplined = 0
    for phc2sysinstance in phc2sysinstances:
        slave_clock = _get_phc2sys_command_line_option(
            phc2sysinstance, pidfile_path, '-c')
        if slave_clock is None or slave_clock == 'CLOCK_REALTIME':
            offset = _get_phc2sys_command_line_option(
                phc2sysinstance, pidfile_path, '-O')
            if offset is not None:
                offset = abs(int(offset)) * 1000000000
            found_disciplined += 1
    if found_disciplined > 1:
        collectd.error(
            "%s Found more then one phc2sys instance disciplining the clock" % PLUGIN)
    return offset


def set_utc_offset(instance):
    """Determine the currentUtcOffset value from either the configured value or via the pmc.

    set_utc_offset() should run on each iteration.
    It is possible for the value to be updated by an upstream node at any time.
    """

    collectd.debug("%s Setting UTC offset for instance %s" %
                   (PLUGIN, instance))
    ctrl = ptpinstances[instance]
    conf_file = (PTPINSTANCE_PATH + ctrl.instance_type +
                 '-' + instance + '.conf')

    utc_offset = ctrl.ptp4l_current_utc_offset
    utc_offset_valid = False
    if ctrl.config_data.has_section('global') \
            and 'domainNumber' in ctrl.config_data['global'].keys() \
            and 'uds_address' in ctrl.config_data['global'].keys():
        #
        # sudo /usr/sbin/pmc -u -b 0 'GET TIME_PROPERTIES_DATA_SET'
        #
        data = subprocess.check_output(
            [PLUGIN_STATUS_QUERY_EXEC, '-f', conf_file, '-u', '-b', '0',
                'GET TIME_PROPERTIES_DATA_SET']).decode()
        for line in data.split('\n'):
            if 'currentUtcOffset ' in line:
                utc_offset = line.split()[1]
            if 'currentUtcOffsetValid ' in line:
                utc_offset_valid = bool(int(line.split()[1]))
        if not utc_offset_valid:
            utc_offset = ctrl.ptp4l_current_utc_offset
            collectd.warning("%s currentUtcOffsetValid is %s, "
                             "using the default currentUtcOffset %s"
                             % (PLUGIN, utc_offset_valid, utc_offset))

    if ctrl.ptp4l_current_utc_offset != int(utc_offset):
        ctrl.ptp4l_current_utc_offset = int(utc_offset)
        ctrl.ptp4l_utc_offset_nanoseconds = abs(int(utc_offset)) * 1000000000
        collectd.info("%s Instance %s utcOffset updated to %s" %
                      (PLUGIN, instance, utc_offset))


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
    elif state in [CLOCK_STATE_LOCKED, CLOCK_STATE_LOCKED_HO_ACK,
                   CLOCK_STATE_LOCKED_HO_ACQ]:
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
            rc = raise_alarm(alarm_object.alarm, interface,
                             state, alarm_object)
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
    phc2sys_clock_offset_ns = check_phc2sys_offset()

    set_utc_offset(instance)
    # If phc2sys offset is 0 or matches the ptp4l offset use it, if not it's a configuration error
    utc_offset_ns = ctrl.ptp4l_utc_offset_nanoseconds
    if phc2sys_clock_offset_ns is not None:
        if phc2sys_clock_offset_ns == 0 \
                or phc2sys_clock_offset_ns == ctrl.ptp4l_utc_offset_nanoseconds:
            utc_offset_ns = phc2sys_clock_offset_ns
        else:
            collectd.error("%s phc2sys offset (%s) does not match ptp4l offset (%s)" %
                           (PLUGIN, phc2sys_clock_offset_ns, ctrl.ptp4l_utc_offset_nanoseconds))

    if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
        collectd.info("%s found phc2sys offset %s" % (PLUGIN, phc2sys_clock_offset_ns))
        collectd.info("%s using utc offset %s" % (PLUGIN, utc_offset_ns))
    ctrl.log_throttle_count += 1

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
        offset = float(abs(raw_offset) - utc_offset_ns)
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
    data = {}
    conf_file = (PTPINSTANCE_PATH + ctrl.instance_type +
                 '-' + instance + '.conf')

    data = query_pmc(instance, 'GRANDMASTER_SETTINGS_NP', query_action='GET')
    current_clock_class = data.get('clockClass', CLOCK_CLASS_248)

    # Determine the base port of the NIC from the interface
    base_port = ctrl.interface[:-1] + '0'
    pci_slot = get_pci_slot(base_port)
    if pci_slot in ts2phc_source_interfaces.keys():
        primary_nic_pci_slot = ts2phc_source_interfaces[pci_slot]
    else:
        collectd.warning("%s Instance %s is has no time source" %
                         (PLUGIN, instance))
        return

    state = CLOCK_STATE_INVALID
    instance_type = PTP_INSTANCE_TYPE_CLOCK
    if primary_nic_pci_slot == pci_slot:
        # We have the primary NIC
        state = dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state']
        instance_type = PTP_INSTANCE_TYPE_TS2PHC
    elif dpll_status.get(pci_slot, None):
        # We have a secondary NIC
        if dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state'] != CLOCK_STATE_INVALID:
            state = dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state']
        elif dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state'] != CLOCK_STATE_INVALID:
            state = dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state']
        elif dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state'] != CLOCK_STATE_INVALID:
            state = dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state']
        if state != CLOCK_STATE_INVALID and state != CLOCK_STATE_HOLDOVER and primary_nic_pci_slot:
            # If the base NIC cgu shows a valid lock state, check the status of the primary_nic
            # GNSS connection
            collectd.info("%s Secondary NIC %s is locked, checking associated primary NIC %s"
                          % (PLUGIN, pci_slot, primary_nic_pci_slot))
            state = dpll_status[primary_nic_pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state']
            instance_type = PTP_INSTANCE_TYPE_TS2PHC

    time_traceable = False
    frequency_traceable = False
    new_clock_class = current_clock_class
    ctrl.ptp4l_prc_state = state
    if state in [CLOCK_STATE_LOCKED, CLOCK_STATE_LOCKED_HO_ACK,
                 CLOCK_STATE_LOCKED_HO_ACQ]:
        new_clock_class = CLOCK_CLASS_6
        time_traceable = True
        frequency_traceable = True
    elif state == CLOCK_STATE_HOLDOVER:
        new_clock_class = CLOCK_CLASS_7
        time_traceable = True
        frequency_traceable = True
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
                frequency_traceable = False
    else:
        new_clock_class = CLOCK_CLASS_248

    if state != CLOCK_STATE_INVALID and current_clock_class != new_clock_class:
        # Set clockClass and timeTraceable
        data['clockClass'] = new_clock_class
        data['timeTraceable'] = int(time_traceable)
        data['frequencyTraceable'] = int(frequency_traceable)
        parameters = ' '.join("{} {}".format(*i) for i in data.items())
        cmd = 'SET GRANDMASTER_SETTINGS_NP ' + parameters
        collectd.debug("%s cmd=%s" % (PLUGIN, cmd))
        try:
            data = subprocess.check_output(
                [PLUGIN_STATUS_QUERY_EXEC, '-f', conf_file, '-u', '-b', '0', cmd]).decode()
        except subprocess.CalledProcessError as exc:
            collectd.error(
                "%s Failed to set clockClass for instance %s" % (PLUGIN, instance))
        collectd.info("%s instance:%s Updated clockClass from %s to %s timeTraceable=%s,"
                      "frequencyTraceable=%s"
                      % (PLUGIN, instance, current_clock_class, new_clock_class, time_traceable,
                         frequency_traceable))


def process_ptp_synce(instance):
    """process ptp synce alarms"""
    # Check GNSS signal status on primary NIC
    # Check SMA/1PPS signal status on secondary NIC

    pin_lookup = {
        'sma1': CGU_PIN_SMA1,
        'sma2': CGU_PIN_SMA2,
        # 'syncE': CGU_PIN_RCLKA
    }
    ctrl = ptpinstances[instance]
    if ctrl.instance_type == PTP_INSTANCE_TYPE_TS2PHC:
        pci_slot = ctrl.pci_slot_name
        state = dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state']
        collectd.info("%s Monitoring instance: %s interface: %s pci_slot: %s "
                      "pin: %s states: %s " %
                      (PLUGIN, instance, ctrl.interface, pci_slot, CGU_PIN_GNSS_1PPS,
                       dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]))
        check_gnss_alarm(instance, ctrl.gnss_signal_loss_alarm_object,
                         ctrl.interface, state)
        if state not in [CLOCK_STATE_LOCKED_HO_ACK, CLOCK_STATE_LOCKED_HO_ACQ]:
            if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
                collectd.info("%s %s not locked to remote GNSS"
                              % (PLUGIN, obj.hostname))
            ctrl.log_throttle_count += 1
    elif ctrl.instance_type == PTP_INSTANCE_TYPE_CLOCK:
        for interface, pin_function in ctrl.clock_ports.items():
            alarm_obj = get_alarm_object(
                ALARM_CAUSE__1PPS_SIGNAL_LOSS, interface)
            if len(pin_function) == 0:
                # No pins are configured for the secondary NIC
                # It checks for alarm with the state of SMA1, SMA2 or GNSS-1PPS pins.
                pci_slot = get_pci_slot(interface)
                state = CLOCK_STATE_INVALID
                if dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['pps_cgu_state'] \
                        != CLOCK_STATE_INVALID:
                    state = dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['pps_cgu_state']
                elif dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state'] != CLOCK_STATE_INVALID:
                    state = dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state']
                elif dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state'] != CLOCK_STATE_INVALID:
                    state = dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state']
                collectd.info("%s Monitoring instance: %s interface: %s pci_slot: %s state: %s "
                              % (PLUGIN, instance, ctrl.interface, pci_slot, state))
                check_gnss_alarm(instance, alarm_obj,
                                 ctrl.interface, state)
            else:
                # Pins are configured, check GNSS then SMA
                pci_slot = get_pci_slot(interface)
                if dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['pps_cgu_state'] != CLOCK_STATE_INVALID:
                    # NIC has a GNSS connection and it takes priority over SMA1/SMA2
                    pin = CGU_PIN_GNSS_1PPS
                    collectd.info("%s Monitoring instance: %s interface: %s pci_slot: %s "
                                  "pin: %s states: %s " %
                                  (PLUGIN, instance, interface, pci_slot, pin,
                                   dpll_status[pci_slot][pin]))
                    check_gnss_alarm(instance,
                                     alarm_obj,
                                     interface,
                                     dpll_status[pci_slot][pin]['pps_cgu_state'])
                else:
                    # Check the SMA pins if they are configured
                    for key, function in pin_function.items():
                        # Do not care about pins configured for 'output' functionality
                        if key in pin_lookup.keys() and function.lower() != CGU_PIN_SMA_OUTPUT:
                            pin = pin_lookup[key]
                        else:
                            # Do not care about the other pins
                            continue
                        collectd.info("%s Monitoring instance: %s interface: %s pci_slot: %s "
                                      "pin: %s states: %s " %
                                      (PLUGIN, instance, interface, pci_slot, pin,
                                       dpll_status[pci_slot][pin]))
                        check_gnss_alarm(instance,
                                         alarm_obj,
                                         interface,
                                         dpll_status[pci_slot][pin]['pps_cgu_state'])

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
    dpll_checked = set()
    for instance_name, ctrl in ptpinstances.items():
        collectd.debug("%s Instance: %s Instance type: %s"
                       % (PLUGIN, instance_name, ctrl.instance_type))
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
            collectd.info("%s PTP service %s admin state:%s" %
                          (PLUGIN, ptp_service, data.rstrip()))

            if data.rstrip() == SYSTEMCTL_IS_DISABLED_RESPONSE:

                # Manage execution phase
                if ctrl.phase != RUN_PHASE__DISABLED:
                    ctrl.phase = RUN_PHASE__DISABLED
                    ctrl.log_throttle_count = 0

                if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
                    collectd.info("%s PTP Service %s Disabled" %
                                  (PLUGIN, ptp_service))
                ctrl.log_throttle_count += 1

                for o in [ctrl.nolock_alarm_object, ctrl.process_alarm_object,
                          ctrl.oot_alarm_object]:
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

                if ctrl.process_alarm_object.alarm == ALARM_CAUSE__PROCESS and ctrl.instance_type \
                        == PTP_INSTANCE_TYPE_PTP4L:
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

        # Handle other instance types
        if ctrl.instance_type == PTP_INSTANCE_TYPE_PTP4L:
            # Non-synce PTP
            check_ptp_regular(instance, ctrl, conf_file)
        elif (ptpinstances[instance].instance_type in
              [PTP_INSTANCE_TYPE_CLOCK, PTP_INSTANCE_TYPE_TS2PHC]):
            # Update the dpll state for each dpll owned by the instance
            for dpll in ptpinstances[instance].dpll_pci_slots:
                if dpll not in dpll_checked:
                    read_dpll_status(dpll)
                    dpll_checked.add(dpll)

        if obj.capabilities['primary_nic']:
            process_ptp_synce(instance)

        if ctrl.instance_type == PTP_INSTANCE_TYPE_PTP4L:
            handle_ptp4l_g8275_fields(instance)

        if ctrl.instance_type == PTP_INSTANCE_TYPE_PHC2SYS and ctrl.phc2sys_ha_enabled is True:
            process_phc2sys_ha(ctrl)

    return 0


def process_phc2sys_ha(ctrl):
    # Update state for phc2sys instances

    previous_state = ctrl.timing_instance.state['phc2sys_source_interface']
    ctrl.timing_instance.set_instance_state_data()
    phc2sys_source_interface = ctrl.timing_instance.state['phc2sys_source_interface']
    phc2sys_lock_state_forced = ctrl.timing_instance.state['phc2sys_forced_lock']
    phc2sys_valid_sources = ctrl.timing_instance.state['phc2sys_valid_sources']

    if phc2sys_source_interface is not None:
        active_source_priority = ctrl.timing_instance.config[phc2sys_source_interface][
            'ha_priority']

    collectd.info("%s phc2sys source clock is %s for instance %s" % (
        PLUGIN, phc2sys_source_interface, ctrl.timing_instance.instance_name))

    # phc2sys_clock_source_loss
    if phc2sys_valid_sources is None:
        # Raise source loss alarm, no sources meet selection threshold
        rc = raise_alarm(ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOSS,
                         ctrl.timing_instance.instance_name,
                         0)
        if rc is True:
            ctrl.phc2sys_clock_source_loss.raised = True
        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            collectd.info("%s No clock sources meet selection threshold for instance %s" % (
                PLUGIN, ctrl.timing_instance.instance_name))
        ctrl.log_throttle_count += 1
    else:
        # Handle clearing no source clock alarm
        if ctrl.phc2sys_clock_source_loss.raised is True:
            if clear_alarm(ctrl.phc2sys_clock_source_loss.eid) is True:
                ctrl.phc2sys_clock_source_loss.raised = False
                collectd.info("%s Phc2sys instance %s source clock detected: %s" % (
                    PLUGIN, ctrl.timing_instance.instance_name, phc2sys_source_interface))

        # phc2sys_clock_source_no_lock
        # Check the configured interfaces for their lock state
        for interface in ctrl.timing_instance.interfaces:
            phc2sys_ha_source_prc = False
            domain_number = None
            max_gm_clockClass = \
                ctrl.timing_instance.config['global'].get(
                    'ha_max_gm_clockClass', '6')
            interface_uds_addr = ctrl.timing_instance.config[interface].get(
                'ha_uds_address', None)

            # Get the domain number for the interface ptp instance, check global domain if not
            # configured
            # If both interface and global domain number are not present, default to 0
            if ctrl.timing_instance.config.has_section(interface):
                domain_number = \
                    ctrl.timing_instance.config[interface].get(
                        'ha_domainNumber', None)
            if domain_number is None:
                domain_number = ctrl.timing_instance.config['global'].get(
                    'domainNumber', '0')

            alarm_obj = get_alarm_object(
                ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_NO_LOCK, interface)
            if interface_uds_addr:
                data = subprocess.check_output(
                    [PLUGIN_STATUS_QUERY_EXEC, '-s', interface_uds_addr, '-d',
                     domain_number, '-u', '-b', '0',
                     'GET PARENT_DATA_SET']).decode()
                # Save all parameters in an ordered dict
                m = OrderedDict()
                response = data.split('\n')
                for line in response:
                    if not ('PARENT_DATA_SET' in line):
                        # match key value array pairs
                        match = re_keyval.search(line)
                        if match:
                            k = match.group(1)
                            v = match.group(2)
                            m[k] = v
                try:
                    current_clock_class = m['gm.ClockClass']
                    if int(current_clock_class) <= int(max_gm_clockClass):
                        phc2sys_ha_source_prc = True
                except KeyError:
                    collectd.info("%s Phc2sy instance %s source clock %s: unable to read clockClass"
                                  % (PLUGIN, ctrl.timing_instance.instance_name,
                                     phc2sys_source_interface))
                    current_clock_class = None
            else:
                collectd.info("%s No ha_uds_address configured for instance %s, interface %s"
                              % (PLUGIN, ctrl.timing_instance.instance_name, interface))

            if phc2sys_ha_source_prc is False:
                rc = raise_alarm(ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_NO_LOCK, interface,
                                 current_clock_class)
                if rc is True:
                    alarm_obj.raised = True
                if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
                    collectd.info("%s Phc2sys instance %s source clock %s is not locked to a PRC"
                                  % (PLUGIN, ctrl.timing_instance.instance_name,
                                     phc2sys_source_interface))
                ctrl.log_throttle_count += 1
            else:
                if alarm_obj.raised is True:
                    if clear_alarm(alarm_obj.eid) is True:
                        alarm_obj.raised = False
                        collectd.info(
                            "%s Phc2sys instance %s source clock %s is now locked to a PRC" %
                            (PLUGIN, ctrl.timing_instance.instance_name,
                             phc2sys_source_interface))

    # phc2sys_clock_source_selection_change
    if phc2sys_source_interface != previous_state and previous_state is not None:
        # Log an fm msg event for source selection change
        # Use the 'msg' alarm state to generate an event log
        # It is not necessary to persist an alarm for this change
        alarm_obj = get_alarm_object(ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_SELECTION_CHANGE,
                                     phc2sys_source_interface)
        rc = raise_alarm(ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_SELECTION_CHANGE,
                         phc2sys_source_interface, ctrl.timing_instance.instance_name,
                         alarm_state=fm_constants.FM_ALARM_STATE_MSG)
        if rc is True:
            alarm_obj.raised = True
            collectd.info("%s phc2sys instance %s clock source changed from %s to %s" % (
                PLUGIN, ctrl.timing_instance.instance_name, previous_state,
                phc2sys_source_interface))
        # Clear low priority alarm in order to re-evaluate the new source
        if ctrl.phc2sys_clock_source_low_priority.raised is True:
            if clear_alarm(ctrl.phc2sys_clock_source_low_priority.eid) is True:
                ctrl.phc2sys_clock_source_low_priority.raised = False

    # Check if phc2sys is force locked to a specific interface
    if active_source_priority == "254" or phc2sys_lock_state_forced == 'True':
        # raise clock source forced alarm
        rc = raise_alarm(ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_FORCED_SELECTION,
                         ctrl.timing_instance.instance_name, 0)
        if rc is True:
            ctrl.phc2sys_clock_source_forced_selection.raised = True
        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            collectd.info("%s Phc2sys instance %s clock source selection has been overridden. "
                          "Only interface %s will be used as source clock." %
                          (PLUGIN, ctrl.timing_instance.instance_name,
                           phc2sys_source_interface))
        ctrl.log_throttle_count += 1
    elif ctrl.phc2sys_clock_source_forced_selection.raised is True:
        if clear_alarm(ctrl.phc2sys_clock_source_forced_selection.eid) is True:
            ctrl.phc2sys_clock_source_forced_selection.raised = False
            collectd.info("%s Phc2sys instance %s automatic clock source selection enabled." % (
                PLUGIN, ctrl.timing_instance.instance_name))

    # phc2sys_clock_source_low_priority
    if int(active_source_priority) < ctrl.timing_instance.state['highest_source_priority']:
        rc = raise_alarm(ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOW_PRIORITY,
                         ctrl.timing_instance.instance_name, phc2sys_source_interface)
        if rc is True:
            ctrl.phc2sys_clock_source_low_priority.raised = True
        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            collectd.info("%s Phc2sys instance %s operating with lower priority source: %s"
                          % (PLUGIN, ctrl.timing_instance.instance_name,
                             phc2sys_source_interface))
        ctrl.log_throttle_count += 1
    elif ctrl.phc2sys_clock_source_low_priority.raised is True:
        if clear_alarm(ctrl.phc2sys_clock_source_low_priority.eid) is True:
            ctrl.phc2sys_clock_source_low_priority.raised = False
            collectd.info("%s Phc2sys instance %s is using the highest priority clock source %s"
                          % (PLUGIN, ctrl.timing_instance.instance_name,
                             phc2sys_source_interface))


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

    # Let's read the clock state, GNSS 1PPS and SMA1
    #
    # Determine the base port of the NIC from the interface, and
    # get state for primary or secondary NIC.
    base_port = ctrl.interface[:-1] + '0'
    pci_slot = get_pci_slot(base_port)
    clock_locked = False
    if dpll_status.get(pci_slot):
        try:
            gnss_state = dpll_status[pci_slot][CGU_PIN_GNSS_1PPS]['eec_cgu_state']
        except KeyError as err:
            collectd.debug(
                "%s KeyError in dpll_status, %s not found" % (PLUGIN, err))
            gnss_state = None
        try:
            sma1_state = dpll_status[pci_slot][CGU_PIN_SMA1]['pps_cgu_state']
        except KeyError as err:
            collectd.debug(
                "%s KeyError in dpll_status %s, not found" % (PLUGIN, err))
            sma1_state = None
        try:
            sma2_state = dpll_status[pci_slot][CGU_PIN_SMA2]['pps_cgu_state']
        except KeyError as err:
            collectd.debug(
                "%s KeyError in dpll_status, %s not found" % (PLUGIN, err))
            sma2_state = None
        gnss_locked = gnss_state in [CLOCK_STATE_LOCKED,
                                     CLOCK_STATE_LOCKED_HO_ACK,
                                     CLOCK_STATE_LOCKED_HO_ACQ]
        sma1_locked = sma1_state in [CLOCK_STATE_LOCKED,
                                     CLOCK_STATE_LOCKED_HO_ACK,
                                     CLOCK_STATE_LOCKED_HO_ACQ]
        sma2_locked = sma2_state in [CLOCK_STATE_LOCKED,
                                     CLOCK_STATE_LOCKED_HO_ACK,
                                     CLOCK_STATE_LOCKED_HO_ACQ]
        clock_locked = gnss_locked or sma1_locked or sma2_locked

    # Handle case where this host is the Grand Master
    #   ... or assumes it is.
    if (my_identity == gm_identity or port_locked is False) and not clock_locked:
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
        if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR or clock_locked:
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
