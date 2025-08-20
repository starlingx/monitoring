#
# Copyright (c) 2019-2025 Wind River Systems, Inc.
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
from ptp_interface import Interface
import ptp_gnss_monitor as pm
from cgu_handler import CguHandler
from pynetlink import DeviceType
from pynetlink import LockStatus
from pynetlink import PinState
from pynetlink import PinType

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
PTPINSTANCE_GNSS_MONITOR_CONF_FILE_PATTERN = PTPINSTANCE_PATH + "gnss-monitor-*.conf"


def _get_ptp_options_path():
    os_type = _get_os_release()
    if os_type == '\"centos\"':
        return '/etc/sysconfig'
    elif os_type == 'debian':
        return '/etc/default'
    else:
        collectd.error("%s unsupported OS type '%s'" % (PLUGIN, os_type))
        return ''


PTP_OPTIONS_PATH = _get_ptp_options_path()


PTP_INSTANCE_TYPE_PTP4L = 'ptp4l'
PTP_INSTANCE_TYPE_PHC2SYS = 'phc2sys'
PTP_INSTANCE_TYPE_TS2PHC = 'ts2phc'
PTP_INSTANCE_TYPE_CLOCK = 'clock'
PTP_INSTANCE_TYPE_GNSS_MONITOR = "gnss-monitor"

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

# gnss-monitor Alarm codes
ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS = 30
ALARM_CAUSE__GNSS_MONITOR_SATELLITE_COUNT = 31
ALARM_CAUSE__GNSS_MONITOR_SIGNAL_QUALITY_DB = 32

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
CLOCK_STATE_INVALID = LockStatus.UNDEFINED
CLOCK_STATE_LOCKED = LockStatus.LOCKED
CLOCK_STATE_LOCKED_HO_ACQ = LockStatus.LOCKED_AND_HOLDOVER
CLOCK_STATE_HOLDOVER = LockStatus.HOLDOVER
CLOCK_STATE_UNLOCKED = LockStatus.UNLOCKED

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

# DPLL Priority List
CGU_PINS_ORDERED_BY_PRIO = [
    CGU_PIN_GNSS_1PPS,
    CGU_PIN_SMA2,
    CGU_PIN_SMA1,
    CGU_PIN_SDP20,
    CGU_PIN_SDP22,
    CGU_PIN_RCLKA,
    CGU_PIN_RCLKB]

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

# sysfs paths
PTP_SYSFS_PATH = '/sys/class/net/%s/device/ptp/'
GNSS_SYSFS_PATH = '/sys/class/net/%s/device/gnss/%s'
USB_DEVICE_PATH = '/sys/bus/usb/devices/'
USB_TTY_DEVICE_PATH = USB_DEVICE_PATH + '*/*/tty/%s'
ZL3073X_SYSFS_PATH = '/sys/module/zl3073x'

# default phc2sys HA socket
PHC2SYS_HA_SOCKET_DEFAULT = '/var/run/phc2sys-phc-ha'

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
        self.holdover_timestamp = {}
        self.interface = None
        self.timing_instance = None
        self.phc2sys_ha_enabled = False
        self.prtc_present = False
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


# PTP crtl objects for each PTP instances
ptpinstances = {}
ordered_instances = OrderedDict()

# Mapping of ptp interfaces to instances
ptpinterfaces = {}

# dpll status of each CGU input for GNSS
cgu_handler = CguHandler()

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

# List of interfaces used by PTP services
interfaces = {}


def create_interface(interface):
    if interface not in interfaces.keys():
        interfaces[interface] = Interface(interface)
        base_port = interfaces[interface].get_base_port()
        if base_port not in interfaces.keys():
            interfaces[base_port] = Interface(base_port)

# ts2phc_source_interfaces dictionary
#
# source_interface:primary_interface
ts2phc_source_interfaces = {}
ts2phc_instance_map = {}

# List of timing instances
timing_instance_list = []


def read_gnss_monitor_ptp_config():
    """read gnss-monitor-ptp conf files"""
    filenames = glob(PTPINSTANCE_GNSS_MONITOR_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.debug(
            "%s No PTP conf file located for %s"
            % (PLUGIN, PTP_INSTANCE_TYPE_GNSS_MONITOR)
        )
    else:
        for filename in filenames:
            instance = TimingInstance(filename)
            ptpinstances[instance.instance_name] = None
            create_interface_alarm_objects(
                'dummy', instance.instance_name, PTP_INSTANCE_TYPE_GNSS_MONITOR
            )
            collectd.info("ptpinstances = %s" % ptpinstances)
            for device_path in instance.device_paths:
                create_interface_alarm_objects(
                    device_path, instance.instance_name, PTP_INSTANCE_TYPE_GNSS_MONITOR
                )

            ptpinstances[instance.instance_name].timing_instance = instance


def read_files_for_timing_instances():
    """read phc2sys conf files"""
    filenames = glob(PTPINSTANCE_PHC2SYS_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.debug("%s No PTP conf file located for %s" %
                       (PLUGIN, "phc2sys"))
    else:
        for filename in filenames:
            instance = TimingInstance(filename)
            collectd.info("ptpinstances = %s" % ptpinstances)
            if 'ha_enabled' in instance.config['global'].keys() \
                    and instance.config['global']['ha_enabled'] == '1' \
                    and instance.interfaces:
                ptpinstances[instance.instance_name].phc2sys_ha_enabled = True
                collectd.info("%s Found HA enabled phc2sys instance %s" %
                              (PLUGIN, instance.instance_name))
            else:
                collectd.info("%s HA not enabled for instance %s, "
                              "using default monitoring"
                              % (PLUGIN, instance.instance_name))
                create_interface_alarm_objects('dummy', instance.instance_name)
                ptpinstances[instance.instance_name].instance_type = \
                    PTP_INSTANCE_TYPE_PHC2SYS
                ptpinstances[instance.instance_name].phc2sys_ha_enabled = False
            ptpinstances[instance.instance_name].timing_instance = instance


class TimingInstance:
    """The purpose of TimingInstance is to track the config and state data of a ptp instance.

    By supplying a config file path, a TimingInstance object will parse and store the instance
    configuration into a dict and provide functions for reading the state data for each instance.

    At this time, only the phc2sys instance type is in use, but some of the other basic instance
    functions have been defined for future enhancements.
    """

    def __init__(self, config_file_path) -> None:
        self.config_file_path = config_file_path
        self.interfaces = set()  # use a python set to prevent duplicates
        self.device_paths = (
            set()
        )  # set to hold device_path list from gnss-monitor instance
        self.config = {}  # dict of params from config file
        self.state = {}  # dict to hold the values read from pmc or cgu or gpsd

        # synce4l handling to be included when full synce4l support is implemented
        self.instance_types = [
            "clock",
            "phc2sys",
            "ptp4l",
            "ts2phc",
            PTP_INSTANCE_TYPE_GNSS_MONITOR,
        ]
        self.config_parsers_dict = {
            "clock": self.parse_clock_config,
            "phc2sys": self.parse_phc2sys_config,
            "ptp4l": self.parse_ptp4l_config,
            "ts2phc": self.parse_ts2phc_config,
            PTP_INSTANCE_TYPE_GNSS_MONITOR: self.parse_gnss_monitor_config,
        }

        self.state_setter_dict = {
            "phc2sys": self.set_phc2sys_state,
            PTP_INSTANCE_TYPE_GNSS_MONITOR: self.set_gnss_monitor_state,
        }

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
                if item == PTP_INSTANCE_TYPE_GNSS_MONITOR:
                    self.instance_name = f"{item}-{instance}"
                else:
                    self.instance_name = instance

        # Select the appropriate parser to initialize self.interfaces/self.device_paths
        # and self.config
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
        self.state = self.state_setter_dict[self.instance_type]()

    def config_to_dict(self, config):
        return {section: dict(config[section]) for section in config}

    def parse_gnss_monitor_config(self):
        config = pm.parse_gnss_monitor_config(self.config_file_path)
        collectd.info(f"{PLUGIN} parsing of {self.config_file_path}: {self.config_to_dict(config)}")
        try:
            self.device_paths = set(
                [
                    device_str.strip()
                    for device_str in config["global"]["devices"].split(" ")
                ]
            )
        except Exception as exc:
            collectd.error(
                "%s Reading devices from gnss-monitor config file %s failed. error: %s"
                % (PLUGIN, self.config_file_path, exc)
            )
        return config

    def set_gnss_monitor_state(self):
        collectd.debug(
            "%s Setting state for gnss-monitor instance %s" % (PLUGIN, self.instance_name)
        )
        state = {}
        for device_path in self.device_paths:
            collectd.info((
                f"{PLUGIN} instance {self.instance_name} reading gpsd data for"
                f" {device_path}"
            ))
            state[device_path] = pm.get_gps_data(device_path)
            collectd.info((
                f"{PLUGIN} instance {self.instance_name} device {device_path}"
                f" data: {state[device_path]}"
            ))
        return state

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
            # unicast_master_table and global are special sections in
            # ptp4l configs, and aren't interfaces. They are only used
            # by ptp4l, and can be ignored by collectd.
            ignore_list = ['global', 'unicast_master_table']
            if item not in ignore_list:
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
            # global is a special section in ts2phc configs, and is not
            # an interface.
            if item != "global":
                self.interfaces.add(item)
        return config

    def init_phc2sys_ha_state(self):
        # Special handling for HA phc2sys
        if 'ha_enabled' in self.config['global'].keys() \
                and self.config['global']['ha_enabled'] == '1':

            # Set phc2sys communication socket
            self.phc2sys_com_socket = self.config['global'].get(
                'ha_phc2sys_com_socket',
                PHC2SYS_HA_SOCKET_DEFAULT)

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
        state = self.state
        state["phc2sys_source_interface"] = self.query_phc2sys_socket(
            "clock source", self.phc2sys_com_socket
        )
        state["phc2sys_forced_lock"] = self.query_phc2sys_socket(
            "forced lock", self.phc2sys_com_socket
        )
        state["phc2sys_valid_sources"] = self.query_phc2sys_socket(
            "valid sources", self.phc2sys_com_socket
        )
        return state

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
        reason += f"PTP service {data} enabled but not running"
        alarm.repair += (
            f"enable service with: systemctl start {data}. "
            "If it still persists: Check host hardware reference manual "
            f"to verify the provisioned {PTP} '{obj.mode}' time stamping "
            "mode is supported by this host."
        )

    elif alarm_cause in [
        ALARM_CAUSE__1PPS_SIGNAL_LOSS,
        ALARM_CAUSE__GNSS_SIGNAL_LOSS,
        ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS,
        ALARM_CAUSE__GNSS_MONITOR_SATELLITE_COUNT,
        ALARM_CAUSE__GNSS_MONITOR_SIGNAL_QUALITY_DB,
    ]:
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

    collectd.info("%s Alarm Object Create: Interface:%s, Instance: %s " %
                  (PLUGIN, interface, instance))

    if instance and not ptpinstances.get(instance, None):
        ctrl = PTP_ctrl_object(instance_type)
        ctrl.interface = interface
        o = PTP_alarm_object(instance)
        o.alarm = ALARM_CAUSE__PROCESS
        o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        o.reason = obj.hostname + ' '
        o.repair = obj.hostname + ' '
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
        if instance_type != PTP_INSTANCE_TYPE_GNSS_MONITOR:
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
        else:  # instance_type == PTP_INSTANCE_TYPE_GNSS_MONITOR
            # Create gnss-monitor instance specific required device_path based alarm
            # objects for supplied interface (here interface means device_path e.g. /dev/gnss0)
            o = PTP_alarm_object(interface)
            o.alarm = ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS
            o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
            o.reason = obj.hostname
            o.reason += " GNSS signal loss"
            o.repair += "Check network"
            o.eid = (
                obj.base_eid
                + ".gnss-monitor="
                + instance
                + ".device_path="
                + interface
                + ".ptp=GNSS-signal-loss"
            )
            o.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # loss-of-signal
            ALARM_OBJ_LIST.append(o)

            o = PTP_alarm_object(interface)
            o.alarm = ALARM_CAUSE__GNSS_MONITOR_SATELLITE_COUNT
            o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
            o.reason = obj.hostname
            o.reason += " GNSS satellite count below threshold"
            o.repair += "Check network"
            o.eid = (
                obj.base_eid
                + ".gnss-monitor="
                + instance
                + ".device_path="
                + interface
                + ".ptp=GNSS-satellite-count"
            )
            o.cause = fm_constants.ALARM_PROBABLE_CAUSE_50  # THRESHOLD CROSS
            ALARM_OBJ_LIST.append(o)

            o = PTP_alarm_object(interface)
            o.alarm = ALARM_CAUSE__GNSS_MONITOR_SIGNAL_QUALITY_DB
            o.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
            o.reason = obj.hostname
            o.reason += " GNSS signal quality db below threshold"
            o.repair += "Check network"
            o.eid = (
                obj.base_eid
                + ".gnss-monitor="
                + instance
                + ".device_path="
                + interface
                + ".ptp=GNSS-signal-quality-db"
            )
            o.cause = fm_constants.ALARM_PROBABLE_CAUSE_50  # THRESHOLD CROSS
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
        collectd.debug("%s No PTP conf file configured" % PLUGIN)
    else:
        for filename in filenames:
            instance = TimingInstance(filename)
            instance_name = instance.instance_name
            ptpinstances[instance_name] = None
            if instance.interfaces:
                for interface in instance.interfaces:
                    create_interface(interface)
                    create_interface_alarm_objects(interface, instance_name)
                    ptpinstances[instance_name].instance_type = \
                        PTP_INSTANCE_TYPE_PTP4L
                    ptpinstances[instance_name].timing_instance = instance
            # timestamping mode
            if instance.config.has_section('global'):
                obj.mode = instance.config['global'].get(
                    PLUGIN_CONF_TIMESTAMPING, None)
            if obj.mode:
                collectd.info("%s instance %s Timestamping Mode: %s" %
                              (PLUGIN, instance_name, obj.mode))
            else:
                collectd.error("%s instance %s failed to get Timestamping Mode" %
                               (PLUGIN, instance_name))


def initialize_ptp4l_state_fields(instance):
    ctrl = ptpinstances[instance]

    # Determine if there is a ts2phc instance disciplining this NIC
    base_port = Interface.base_port(ctrl.interface)

    mapped_ts2phc_instance = ts2phc_instance_map.get(base_port, None)
    if mapped_ts2phc_instance:
        collectd.info("%s ptp4l instance %s is mapped to ts2phc instance %s"
                      % (PLUGIN, instance, mapped_ts2phc_instance))
        ctrl.prtc_present = True
        collectd.info("%s Instance %s PRTC present" % (PLUGIN, instance))
    else:
        ctrl.prtc_present = False
        collectd.info("%s Instance %s PRTC not present" % (PLUGIN, instance))

    # Read any configured G.8275.x field values, set to default if not present
    if ctrl.timing_instance.config.has_section('global'):
        ctrl.ptp4l_clock_accuracy = \
            ctrl.timing_instance.config['global'].get(
                'clockAccuracy', G8275_CLOCK_ACCURACY_PRTC).lower()
        ctrl.ptp4l_offset_scaled_log_variance = \
            ctrl.timing_instance.config['global'].get('offsetScaledLogVariance',
                                                      G8275_OFFSET_SCALED_LOG_VARIANCE_PRTC).lower()
        ctrl.ptp4l_time_source = \
            ctrl.timing_instance.config['global'].get(
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
    if ctrl.timing_instance.config.has_section('global') and \
       'utc_offset' in ctrl.timing_instance.config['global'].keys():
        ctrl.ptp4l_current_utc_offset = ctrl.timing_instance.config['global']['utc_offset']
        collectd.info("%s Instance %s currentUtcOffset is initialized to %s"
                      % (PLUGIN, instance, str(ctrl.ptp4l_current_utc_offset)))
    else:
        # currentUtcOffset is not configured, use existing default
        ctrl.ptp4l_current_utc_offset = data['currentUtcOffset']
        collectd.info("%s Instance %s currentUtcOffset is not specified, initializing to %s"
                      % (PLUGIN, instance, str(ctrl.ptp4l_current_utc_offset)))


def split_gnss_path(gnss):
    """split gnss path in nmea"""
    nmea = None
    if gnss:
        splitted_gnss = gnss.split(os.sep)
        if len(splitted_gnss) == 3:
            nmea = splitted_gnss[2]
    return nmea


def get_interface_name_from_gnss(gnss):
    interface_name = None
    nmea = split_gnss_path(gnss)
    # get gnss path with given nmea serial port name
    if nmea:
        filenames = glob(GNSS_SYSFS_PATH % ('*', nmea))
    # get the interface name from gnss path
    if len(filenames) == 1:
        splitted_path = filenames[0].split(os.sep)
        if len(splitted_path) == 8:
            interface_name = splitted_path[4]
    return interface_name


def is_microchip_gnss_module_available():
    """check if Microchip's GNSS module is available"""
    return os.path.exists(ZL3073X_SYSFS_PATH)


def get_usb_vendor_id(usb):
    """get USB device vendor id"""
    vendor_id = None
    vendor_id_path = os.path.join(USB_DEVICE_PATH, usb, 'idVendor')
    try:
        with open(vendor_id_path, 'r') as infile:
            vendor_id = infile.read().strip()
    except (FileNotFoundError, PermissionError) as err:
        collectd.debug(f"Get USB vendor id failed, "
                       f"reason {err}")
    return vendor_id


def get_usb_product_id(usb):
    """get USB device product id"""
    product_id = None
    product_id_path = os.path.join(USB_DEVICE_PATH, usb, 'idProduct')
    try:
        with open(product_id_path, 'r') as infile:
            product_id = infile.read().strip()
    except (FileNotFoundError, PermissionError) as err:
        collectd.debug(f"Get USB product id failed, "
                       f"reason {err}")
    return product_id


def is_nmea_tty_a_microchip_gnss_receiver(tty_device):
    """check if NMEA tty is an Microchip's GNSS receiver"""
    vendor_id = None
    product_id = None
    nmea = split_gnss_path(tty_device)
    if not nmea:
        return False

    # Search for an USB TTY device matching the NMEA, than
    # get its vendor and product ids.
    filenames = glob(USB_TTY_DEVICE_PATH % nmea)
    if len(filenames) == 1:
        splitted_path = filenames[0].split(os.sep)
        if len(splitted_path) == 9:
            usb = splitted_path[5]
            vendor_id = get_usb_vendor_id(usb)
            product_id = get_usb_product_id(usb)

    return vendor_id in ['1546'] and product_id in ['01a9']


def read_ptp_service_options(instance_name, instance_type):
    data = None
    filepath = os.path.join(PTP_OPTIONS_PATH, 'ptpinstance',
                            f"{instance_type}-instance-{instance_name}")
    try:
        with open(filepath, 'r', encoding='utf-8') as infile:
            data = infile.read().strip('\n')
    except (FileNotFoundError, PermissionError) as err:
        collectd.info(f"{PLUGIN} {instance_name} Read service options file {filepath} failed, "
                      f"reason: {err}")
    return data


def prune_reconfigured_suffix(nmea_serialport):
    # truncate suffix .pty (gpspipe output device) if any, to get the actual device path
    return nmea_serialport.removesuffix(".pty") if nmea_serialport else None


def read_ts2phc_config():
    """read ts2phc conf files"""
    filenames = glob(PTPINSTANCE_TS2PHC_CONF_FILE_PATTERN)
    if len(filenames) == 0:
        collectd.info("%s No ts2phc conf file configured" % PLUGIN)
    else:
        # Handle one or more ts2phc instances. Multiple instances may be present for HA phc2sys
        for filename in filenames:
            instance = TimingInstance(filename)
            instance_name = instance.instance_name

            # Get source from ts2phc command line
            service_options = read_ptp_service_options(instance_name, PTP_INSTANCE_TYPE_TS2PHC)
            if service_options:
                collectd.info(f"{PLUGIN} {instance_name} service options {service_options}")
                source = None
                matches = re.search('OPTIONS="-s (.*)"', service_options)
                if matches:
                    source = matches.group(1)
                if source:
                    collectd.info(f"{PLUGIN} ts2phc {instance_name} source is {source}")
                    obj.capabilities['ts2phc_source'] = source

            primary_interface = None
            if instance.config.has_section('global'):
                # primary interface
                nmea_mask = instance.config['global'].get('ts2phc.nmea_serialport', None)
                nmea = prune_reconfigured_suffix(nmea_mask)
                if nmea:
                    interface = get_interface_name_from_gnss(nmea)
                    if interface:
                        primary_interface = interface
                        create_interface(interface)
                        create_interface_alarm_objects(interface, instance_name)
                        ptpinstances[instance_name].instance_type = \
                            PTP_INSTANCE_TYPE_TS2PHC
                        ptpinstances[instance_name].timing_instance = instance
                        ts2phc_source_interfaces[interface] = interface
                        ts2phc_instance_map[interface] = instance_name
                        obj.capabilities['primary_nic'] = interface
                        obj.capabilities['ts2phc_source'] = 'nmea'

                        collectd.info(f"{PLUGIN} ts2phc instance {instance_name} "
                                      f"primary_nic {primary_interface}")
                    elif is_microchip_gnss_module_available() and is_nmea_tty_a_microchip_gnss_receiver(nmea):
                        collectd.info(f"{PLUGIN} ts2phc instance:{instance_name}"
                                      f" microchip GNSS module detected")

                        # get the 1st GNR-D interface name
                        ptp_paths = glob(PTP_SYSFS_PATH % '*')
                        if len(ptp_paths) > 0:
                            for path in ptp_paths:
                                splitted_path = path.split(os.sep)
                                if len(splitted_path) == 8:
                                    interface = splitted_path[4]
                                    if Interface(interface).get_family() == 'Granite Rapid-D':
                                        primary_interface = interface
                                        break

                        if primary_interface:
                            create_interface(primary_interface)
                            create_interface_alarm_objects(primary_interface, instance_name)
                            ptpinstances[instance_name].instance_type = \
                                PTP_INSTANCE_TYPE_TS2PHC
                            ptpinstances[instance_name].timing_instance = instance
                            ts2phc_source_interfaces[primary_interface] = primary_interface
                            ts2phc_instance_map[primary_interface] = instance_name
                            obj.capabilities['primary_nic'] = primary_interface
                            obj.capabilities['ts2phc_source'] = 'nmea'

                            collectd.info(f"{PLUGIN} ts2phc instance {instance_name} "
                                          f"primary_nic {primary_interface}")
                        else:
                            collectd.warning(f"{PLUGIN} Create ts2phc instance failed.")
                    else:
                        collectd.warning("%s invalid nmea serial port path: %s" %
                                         (PLUGIN, nmea))

            # secondary interfaces
            if instance.interfaces:
                for interface in instance.interfaces:
                    create_interface(interface)
                    base_port = interfaces[interface].get_base_port()
                    # if interface is different than primary's
                    if base_port != primary_interface:
                        ts2phc_source_interfaces[base_port] = primary_interface
                        ts2phc_instance_map[base_port] = instance_name


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
    instance = TimingInstance(filename)
    instance_name = PTP_INSTANCE_TYPE_CLOCK
    ptpinstances[instance_name] = None
    if instance.interfaces:
        for interface in instance.interfaces:
            create_interface(interface)
            create_interface_alarm_objects(interface, instance_name)
            ptpinstances[instance_name].instance_type = \
                PTP_INSTANCE_TYPE_CLOCK
            ptpinstances[instance_name].timing_instance = instance
            ptpinstances[instance_name].clock_ports[interface] = instance.config[interface]

        collectd.info("%s instance: %s ports: %s" %
                      (PLUGIN, instance_name,
                       ptpinstances[instance_name].clock_ports))
    else:
        collectd.info("%s No interfaces configured for instance %s" %
                      (PLUGIN, PTP_INSTANCE_TYPE_CLOCK))
        # When no base_port is found, it means synce is disabled.
        # Remove the ptp instance as it does not require monitoring.
        del instance
        del ptpinstances[instance_name]


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
    obj.capabilities = {'primary_nic': None, 'ts2phc_source': None}

    if os.path.exists(PTPINSTANCE_PATH):
        read_ptp4l_config()
        read_ts2phc_config()
        read_clock_config()
        # Initialize TimingInstance for HA phc2sys
        read_files_for_timing_instances()
        read_gnss_monitor_ptp_config()
        for key, ctrl in ptpinstances.items():
            collectd.info("%s instance:%s type:%s found" %
                          (PLUGIN, key, ctrl.instance_type))

    else:
        collectd.error("%s instance configuration directory %s not found" %
                       (PLUGIN, PTPINSTANCE_PATH))
        obj.mode = None

    for key, value in interfaces.items():
        collectd.info("%s interface %s supports timestamping modes: %s" %
                      (PLUGIN, key, value.get_ts_supported_modes()))
        collectd.info("%s interface %s pci slot: %s" %
                      (PLUGIN, key, value.get_pci_slot()))
        collectd.info("%s interface %s nmea: %s" %
                      (PLUGIN, key, value.get_nmea()))
        collectd.info("%s interface %s clock-id: %s" %
                      (PLUGIN, key, value.get_switch_id()))
        collectd.info("%s interface %s family: %s" %
                      (PLUGIN, key, value.get_family()))

    for key, ctrl in ptpinstances.items():
        collectd.info("%s instance:%s type:%s found" %
                      (PLUGIN, key, ctrl.instance_type))

    # print initial CGU state per clock id
    cgu_handler.read_cgu()
    cgu_dict = cgu_handler.cgu_output_to_dict()
    for clock_id, info in cgu_dict.items():
        collectd.debug("%s clock_id: %s cgu info: %s" % (PLUGIN, clock_id, info))

    # remove '# to dump alarm object data
    # print_alarm_objects()

    for instance in ptpinstances:
        if ptpinstances[instance].instance_type == PTP_INSTANCE_TYPE_PTP4L:
            initialize_ptp4l_state_fields(instance)

    # Set the ordered_instances dict to allow the read_func to process
    # the instances in the order of ts2phc, clock, ptp4l, other
    _set_instance_order()

    if tsc.nodetype == 'controller':
        obj.controller = True

    obj.virtual = obj.is_virtual()

    obj.init_completed()
    return 0


def _set_instance_order():
    """Order the ptp instances to allow the read_fun to check ts2phc->clock->ptp4l->other"""
    checked_types = [PTP_INSTANCE_TYPE_TS2PHC, PTP_INSTANCE_TYPE_CLOCK, PTP_INSTANCE_TYPE_PTP4L]

    def add_instances_by_type(instance_type):
        # Use map and filter to order instances by type
        for instance, ctrl in \
                filter(lambda item: item[1].instance_type == instance_type, ptpinstances.items()):
            ordered_instances[instance] = ctrl
    for t in checked_types:
        add_instances_by_type(t)

    # Add any remaining types not in checked_types
    for instance, ctrl in \
            filter(lambda item: item[1].instance_type not in checked_types, ptpinstances.items()):
        ordered_instances[instance] = ctrl

    collectd.info(
        f"{PLUGIN} Ordered instances: {list(ordered_instances.keys())}")


def handle_ptp4l_g8275_fields(instance):
    """set the required parameters for g8275 conformance"""
    collectd.debug(f"{PLUGIN} handle_ptp4l_g8275_fields: {instance}")
    ctrl = ptpinstances[instance]
    previous_grandmaster_identity = ctrl.ptp4l_grandmaster_identity
    previous_clock_class = ctrl.ptp4l_clock_class

    if ctrl.timing_instance.config.has_section('global') \
            and 'dataset_comparison' not in ctrl.timing_instance.config['global'].keys():
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

    elif ctrl.ptp4l_prc_state in [CLOCK_STATE_INVALID,
                                  CLOCK_STATE_UNLOCKED]:
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
    collectd.debug(f"{PLUGIN} write_ptp4l_gm_fields: {instance}")
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


def get_netlink_dpll_status(interface_name, type):
    """Get current DPLL status"""

    pin = None
    device = None
    clock_id = None
    status = CLOCK_STATE_INVALID
    interface = interfaces.get(interface_name, None)
    if interface:
        # Granit Rapid-D and Connorsville interfaces don´t have
        # embedded DPLL circuitry, but they can synchronize to
        # an external DPLL in the system.
        #
        # For all other interfaces, retrieve their switch id, used
        # as clock identifier in DPLL status reports.
        clock_id = interface.get_switch_id()

        # Retrieve the current DPLL state, filtered by clock id and
        # type (EEC, PPS).
        device, pin = \
            cgu_handler.cgu_get_current_device_state(clock_id, type)

    if device:
        status = device.lock_status
        if status in [CLOCK_STATE_LOCKED and
                      CLOCK_STATE_LOCKED_HO_ACQ]:
            collectd.debug(f"{PLUGIN} DPLL device {interface_name} clock id {clock_id} "
                           f"type {type.value} status {status.value} current source %s"
                           % (pin.pin_board_label if pin else "undefined"))
        else:
            collectd.info(f"{PLUGIN} DPLL device {interface_name} clock_id {clock_id} "
                          f"type {type.value} status {status.value} "
                          f"lock status error {device.lock_status_error.value}")
    else:
        collectd.info(f"{PLUGIN} DPLL device clock id {clock_id} and "
                      f"type {type.value} not found!")

    return status, pin


def get_netlink_pin_status(interface_name, pin_name):
    pins = []
    interface = interfaces.get(interface_name, None)
    if interface:
        clock_id = interface.get_switch_id()
        pins = cgu_handler.search_pins(clock_id, pin_name)
    return pins[0] if len(pins) > 0 else None


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
    collectd.debug(f"{PLUGIN} check_phc2sys_offset")
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
    if ctrl.timing_instance.config.has_section('global') \
            and 'domainNumber' in ctrl.timing_instance.config['global'].keys() \
            and 'uds_address' in ctrl.timing_instance.config['global'].keys():
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
            if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
                collectd.warning("%s currentUtcOffsetValid is %s, "
                                 "using the default currentUtcOffset %s"
                                 % (PLUGIN, utc_offset_valid, utc_offset))
            ctrl.log_throttle_count += 1

    if ctrl.ptp4l_current_utc_offset != int(utc_offset):
        ctrl.ptp4l_current_utc_offset = int(utc_offset)
        ctrl.ptp4l_utc_offset_nanoseconds = abs(int(utc_offset)) * 1000000000
        collectd.info("%s Instance %s utcOffset updated to %s" %
                      (PLUGIN, instance, utc_offset))


def check_gnss_alarm(instance, alarm_object, interface, state):
    """check for GNSS alarm"""
    collectd.debug(f"{PLUGIN} check_gnss_alarm: {instance} {interface}")
    ctrl = ptpinstances[instance]
    base_port = Interface.base_port(interface)
    primary_nic = ts2phc_source_interfaces.get(base_port, None)

    severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
    if not state or state in [CLOCK_STATE_INVALID,
                              CLOCK_STATE_UNLOCKED]:
        severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
    elif state == CLOCK_STATE_HOLDOVER:
        severity = fm_constants.FM_ALARM_SEVERITY_MINOR
    elif state in [CLOCK_STATE_LOCKED,
                   CLOCK_STATE_LOCKED_HO_ACQ]:
        severity = fm_constants.FM_ALARM_SEVERITY_CLEAR

    if state == CLOCK_STATE_HOLDOVER:
        if interface != primary_nic:
            holdover_ts = ctrl.holdover_timestamp.get(primary_nic, None)
            if holdover_ts:
                # We were already in holdover because of the primary nic
                # Copy the timestamp to secondary nic
                ctrl.holdover_timestamp[interface] = holdover_ts
        # If there is no entry for the current interface,
        # create it and initialize
        if interface not in ctrl.holdover_timestamp or \
           not ctrl.holdover_timestamp[interface]:
            ctrl.holdover_timestamp[interface] = timeutils.utcnow()
        collectd.info(f"{PLUGIN} Holdover timestamp for PHC {interface}: "
                      f"{ctrl.holdover_timestamp[interface]}")
    else:
        ctrl.holdover_timestamp[interface] = None

    if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
        if alarm_object.raised is True:
            if clear_alarm(alarm_object.eid) is True:
                alarm_object.severity = \
                    fm_constants.FM_ALARM_SEVERITY_CLEAR
                alarm_object.raised = False
        # Clear pre-existing holdover timestamp
        ctrl.holdover_timestamp[interface] = None
    else:
        if alarm_object.severity != severity:
            alarm_object.severity = severity
        if alarm_object.raised is False:
            rc = raise_alarm(alarm_object.alarm, interface,
                             state, alarm_object)
            if rc is True:
                alarm_object.raised = True


def check_pin_alarm(instance, alarm_object, interface, state):
    """check pin alarm"""

    ctrl = ptpinstances[instance]
    severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
    if not state and state in [PinState.UNDEFINED,
                               PinState.DISCONNECTED]:
        severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
    elif state in [PinState.SELECTABLE,
                   PinState.CONNECTED]:
        severity = fm_constants.FM_ALARM_SEVERITY_CLEAR

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


def check_time_drift(instance, gm_identity=None, master_offset=0):
    """Check time drift"""
    collectd.debug(f"{PLUGIN} check_time_drift: %s" % instance)
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
        collectd.info("%s found phc2sys offset %s" %
                      (PLUGIN, phc2sys_clock_offset_ns))
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
        fault_offset = master_offset if abs(master_offset) > abs(offset) else offset
        collectd.info("%s instance %s phc offset %f master_offset %f" %
                      (PLUGIN, instance, offset, master_offset))
        if (abs(offset) > OOT_MAJOR_THRESHOLD
                or abs(master_offset) > OOT_MAJOR_THRESHOLD):
            severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        elif (abs(offset) > OOT_MINOR_THRESHOLD
                or abs(master_offset) > OOT_MINOR_THRESHOLD):
            severity = fm_constants.FM_ALARM_SEVERITY_MINOR

        # Handle clearing of Out-Of-Tolerance alarm
        if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
            if ctrl.oot_alarm_object.raised is True:
                if clear_alarm(ctrl.oot_alarm_object.eid) is True:
                    ctrl.oot_alarm_object.severity = \
                        fm_constants.FM_ALARM_SEVERITY_CLEAR
                    ctrl.oot_alarm_object.raised = False

        # Special Case:
        # -------------
        # Don't raise minor alarm when in software timestamping mode.
        # Too much skew in software or legacy mode ; alarm would bounce.
        elif severity == fm_constants.FM_ALARM_SEVERITY_MINOR \
                and obj.mode != 'hardware' \
                and abs(master_offset) > OOT_MINOR_THRESHOLD:
            collectd.info("%s instance %s minor skew detected, "
                          "not raising OOT alarm in software mode" %
                          (PLUGIN, instance))
            return 0

        else:
            # Handle raising the OOT alarm.
            # Because the polling cycle for the ptp plugin is 30 seconds, we cannot
            # afford to wait two cycles while debouncing the OOT alarm.
            # The previous logic required a skew to be present for 2 consecutive
            # polling cycles before raising the OOT alarm, but this would fail to
            # alarm for transient skews that are present for less than 60 seconds.

            # The OOT alarm is now raised immediately when the skew is detected,
            # and the severity is updated accordingly.

            if ctrl.oot_alarm_object.severity != severity:
                ctrl.oot_alarm_object.severity = severity

            # This will keep refreshing the alarm text with the current
            # skew value.
            #
            # Precision ... (PTP) clocking is out of tolerance by 1004 nsec
            #
            if severity in (fm_constants.FM_ALARM_SEVERITY_MINOR,
                            fm_constants.FM_ALARM_SEVERITY_MAJOR):
                # Handle raising the OOT Alarm.
                rc = raise_alarm(ALARM_CAUSE__OOT, instance, fault_offset)
                if rc is True:
                    ctrl.oot_alarm_object.raised = True

            # Record the value that is alarmable
            if severity != fm_constants.FM_ALARM_SEVERITY_CLEAR:
                collectd.info("%s ; "
                              "PTP instance: %s ; "
                              "Skew:%5d" % (PLUGIN,
                                            instance,
                                            fault_offset))


def is_service_running(ptp_service):
    data = subprocess.check_output([SYSTEMCTL,
                                    SYSTEMCTL_IS_ACTIVE_OPTION,
                                    ptp_service]).decode()
    if data.rstrip() == SYSTEMCTL_IS_ACTIVE_RESPONSE:
        return True
    return False


def is_local_gm(ptp4l_instance):
    ctrl = ptpinstances[ptp4l_instance]
    parent_data_set = query_pmc(
        ptp4l_instance, "PARENT_DATA_SET", query_action="GET")
    ptp4l_grandmaster_identity = parent_data_set.get(
        "grandmasterIdentity", ctrl.ptp4l_grandmaster_identity
    )

    default_data_set = query_pmc(
        ptp4l_instance, "DEFAULT_DATA_SET", query_action="GET")
    ptp4l_clock_identity = default_data_set.get(
        "clockIdentity", ctrl.ptp4l_clock_identity
    )

    if ptp4l_grandmaster_identity == ptp4l_clock_identity:
        return True
    return False


def check_clock_class(instance):
    collectd.debug(f"{PLUGIN} check_clock_class {instance}")
    ctrl = ptpinstances[instance]
    data = {}
    conf_file = (PTPINSTANCE_PATH + ctrl.instance_type +
                 '-' + instance + '.conf')

    data = query_pmc(instance, 'GRANDMASTER_SETTINGS_NP', query_action='GET')
    current_clock_class = data.get('clockClass', CLOCK_CLASS_248)

    # Determine the base port of the NIC from the interface
    interface = interfaces.get(ctrl.interface, None)
    if not interface:
        collectd.warning(f"{PLUGIN} {instance} Interface {ctrl.interface} not found")
        return
    base_port = interface.get_base_port()
    # Granite Rapid-D and Connorsville NICs are always primary, because
    # they can't be daisy-chained.
    primary_nic = None
    if interface.get_family() in ['Granite Rapid-D', 'Connorsville']:
        primary_nic = base_port
    else:
        primary_nic = ts2phc_source_interfaces.get(base_port, None)

    if not primary_nic:
        collectd.warning("%s Instance %s has no time source" %
                         (PLUGIN, instance))
        return

    mapped_ts2phc_instance = ts2phc_instance_map.get(base_port, None)
    mapped_ts2phc_service = (
        PTP_INSTANCE_TYPE_TS2PHC + "@" + mapped_ts2phc_instance + ".service"
    )
    is_ts2phc_running = is_service_running(mapped_ts2phc_service)
    if not is_ts2phc_running:
        collectd.info(
            "%s PTP service %s is not running" % (
                PLUGIN, mapped_ts2phc_service)
        )
        if not is_local_gm(instance):
            collectd.info(
                "%s Instance %s is not local GM, clock-class will be updated by PTP source"
                % (PLUGIN, instance)
            )
            return

    pin = None
    state = CLOCK_STATE_INVALID
    instance_type = PTP_INSTANCE_TYPE_CLOCK
    ho_timer_interface = base_port
    if primary_nic == base_port:
        # We have the primary NIC
        state, _ = get_netlink_dpll_status(base_port, DeviceType.EEC)
        instance_type = PTP_INSTANCE_TYPE_TS2PHC
        collectd.info(f"{PLUGIN} {instance} Primary device {base_port} "
                      f"status {state}")
    else:
        # We have a secondary NIC
        state, pin = get_netlink_dpll_status(base_port, DeviceType.PPS)
        if state == CLOCK_STATE_INVALID:
            state, pin = get_netlink_dpll_status(base_port, DeviceType.EEC)
        if state not in [CLOCK_STATE_INVALID, CLOCK_STATE_UNLOCKED, CLOCK_STATE_HOLDOVER] \
           and pin and pin.pin_type == PinType.EXT:
            # If the base NIC cgu shows a valid lock state and pin type is external,
            # check the status of the primary_nic GNSS connection
            state, _ = get_netlink_dpll_status(primary_nic, DeviceType.EEC)
            collectd.info(f"{PLUGIN} {instance} Secondary device {base_port} "
                          f"is locked to an external source, checking primary "
                          f"{primary_nic}. Primary status is {state}")
            instance_type = PTP_INSTANCE_TYPE_TS2PHC
            ho_timer_interface = primary_nic

    time_traceable = False
    frequency_traceable = False
    new_clock_class = current_clock_class
    ctrl.ptp4l_prc_state = state
    if (is_ts2phc_running and state in [CLOCK_STATE_LOCKED, CLOCK_STATE_LOCKED_HO_ACQ]):
        new_clock_class = CLOCK_CLASS_6
        time_traceable = True
        frequency_traceable = True
    elif is_ts2phc_running and state == CLOCK_STATE_HOLDOVER:
        new_clock_class = CLOCK_CLASS_7
        time_traceable = True
        frequency_traceable = True
        holdover_timestamp = None
        # Get the holdover timestamp of the clock/ts2phc instance
        for key, ctrl_obj in ptpinstances.items():
            if ctrl_obj.instance_type == instance_type:
                holdover_timestamp = ctrl_obj.holdover_timestamp.get(ho_timer_interface, None)
                if holdover_timestamp:
                    collectd.debug(f"{PLUGIN} check_clock_class:"
                                   f"holdover_timestamp: {holdover_timestamp}")
                else:
                    collectd.warning(f"{PLUGIN} No holdover timestamp found for "
                                     f"{key}: {ho_timer_interface}")

        # If it is in holdover more than the holdover spec threshold,
        # set clock class to 140
        if holdover_timestamp:
            delta = timeutils.delta_seconds(holdover_timestamp,
                                            timeutils.utcnow())
            collectd.info(
                f"{PLUGIN} {instance} holdover timer: {delta} seconds")
            if delta > HOLDOVER_THRESHOLD:
                new_clock_class = CLOCK_CLASS_140
                time_traceable = False
                frequency_traceable = False
    else:
        new_clock_class = CLOCK_CLASS_248

    if current_clock_class != new_clock_class and (
        not is_ts2phc_running or state != CLOCK_STATE_INVALID
    ):
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


def check_gnss_signal(instance):
    """check GNSS signal and manage alarms"""
    collectd.debug(f"{PLUGIN} check_gnss_signal: {instance}")

    ctrl = ptpinstances[instance]
    base_port = Interface.base_port(ctrl.interface)
    state, pin = get_netlink_dpll_status(base_port, DeviceType.PPS)
    collectd.info(f"{PLUGIN} gnss-monitor instance: {instance} "
                  f"device {ctrl.interface} status {state.value} pin %s"
                  % (pin.pin_board_label if pin else "unknown"))
    check_gnss_alarm(instance, ctrl.gnss_signal_loss_alarm_object,
                     ctrl.interface, state)
    if state not in [CLOCK_STATE_LOCKED, CLOCK_STATE_LOCKED_HO_ACQ]:
        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            collectd.info("%s %s not locked to remote GNSS" %
                          (PLUGIN, obj.hostname))
        ctrl.log_throttle_count += 1


def check_1pps_signal(instance):
    """check 1PPS signal and manage alarms"""
    collectd.debug(f"{PLUGIN} check_1pps_signal: {instance}")
    # Check GNSS signal status on primary NIC
    # Check SMA/1PPS signal status on secondary NIC

    pin_lookup = {
        'sma1': CGU_PIN_SMA1,
        'sma2': CGU_PIN_SMA2,
        # 'syncE': CGU_PIN_RCLKA
    }

    ctrl = ptpinstances[instance]
    for interface, pin_function in ctrl.clock_ports.items():
        alarm_obj = get_alarm_object(
            ALARM_CAUSE__1PPS_SIGNAL_LOSS, interface)
        if len(pin_function) == 0:
            # No pins are configured for the secondary NIC
            # It checks for alarm with the state of SMA1, SMA2 or GNSS-1PPS pins.
            state, pin = get_netlink_dpll_status(interface, DeviceType.PPS)
            if state in [CLOCK_STATE_INVALID, CLOCK_STATE_UNLOCKED]:
                state, pin = get_netlink_dpll_status(interface, DeviceType.EEC)
            collectd.info(f"{PLUGIN} Monitoring instance {instance} "
                          f"device {ctrl.interface} status {state.value} pin %s"
                          % (pin.pin_board_label if pin else "unknown"))
            check_gnss_alarm(instance, alarm_obj, ctrl.interface, state)
        else:
            # Pins are configured, check GNSS then SMA
            state, pin = get_netlink_dpll_status(interface, DeviceType.PPS)
            if state not in [CLOCK_STATE_INVALID, CLOCK_STATE_UNLOCKED]:
                # NIC has a GNSS connection and it takes priority over SMA1/SMA2
                collectd.info(f"{PLUGIN} Monitoring instance {instance} "
                              f"device {interface} status {state.value} pin %s"
                              % (pin.pin_board_label if pin else "unknown"))
                check_gnss_alarm(instance, alarm_obj, interface, state)
            else:
                # Check the SMA pins if they are configured
                for key, function in pin_function.items():
                    # Do not care about pins configured for 'output' functionality
                    if key in pin_lookup.keys() and function.lower() != CGU_PIN_SMA_OUTPUT:
                        pin_name = pin_lookup[key]
                    else:
                        # Do not care about the other pins
                        continue
                    pin = get_netlink_pin_status(interface, pin_name)
                    if pin:
                        collectd.info(f"{PLUGIN} Monitoring instance {instance} "
                                      f"device {interface} pin {pin.pin_board_label} "
                                      f"status {pin.pin_state.value}")
                        check_pin_alarm(instance, alarm_obj, interface, pin.pin_state)


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
    cgu_handler.read_cgu()
    cgu_dict = cgu_handler.cgu_output_to_dict()
    for clock_id, info in cgu_dict.items():
        collectd.info(f"{PLUGIN} DPLL clock_id: {clock_id} info: {info}")
    for instance_name, ctrl in ordered_instances.items():
        collectd.info("%s Instance: %s Instance type: %s"
                      % (PLUGIN, instance_name, ctrl.instance_type))
        instance = instance_name
        if ctrl.instance_type == PTP_INSTANCE_TYPE_GNSS_MONITOR:
            ptp_service = "gpsd.service"
            conf_file = PTPINSTANCE_PATH + instance_name + ".conf"
        else:
            ptp_service = ctrl.instance_type + "@" + instance_name + ".service"
            conf_file = (
                PTPINSTANCE_PATH + ctrl.instance_type + "-" + instance_name + ".conf"
            )

        # Clock instance does not have a service, thus check non-clock instance type
        if ctrl.instance_type != PTP_INSTANCE_TYPE_CLOCK:
            # This plugin supports PTP in-service state change by checking
            # service state on every audit ; every 5 minutes.
            data = subprocess.check_output([SYSTEMCTL,
                                            SYSTEMCTL_IS_ENABLED_OPTION,
                                            ptp_service]).decode()
            is_running = is_service_running(ptp_service)
            collectd.info("%s PTP service %s admin state:%s running:%s" %
                          (PLUGIN, ptp_service, data.rstrip(), is_running))

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

            if not is_running:
                # Manage execution phase
                if ctrl.phase != RUN_PHASE__NOT_RUNNING:
                    ctrl.phase = RUN_PHASE__NOT_RUNNING
                    ctrl.log_throttle_count = 0

                if ctrl.process_alarm_object.alarm == ALARM_CAUSE__PROCESS and ctrl.instance_type \
                        in [PTP_INSTANCE_TYPE_PTP4L,
                            PTP_INSTANCE_TYPE_PHC2SYS,
                            PTP_INSTANCE_TYPE_TS2PHC,
                            PTP_INSTANCE_TYPE_GNSS_MONITOR]:
                    # If the process is not running, raise the process alarm
                    if ctrl.process_alarm_object.raised is False:
                        collectd.error("%s PTP service %s enabled but not running" %
                                       (PLUGIN, ptp_service))
                        if raise_alarm(ALARM_CAUSE__PROCESS,
                                       instance_name, data=ptp_service) is True:
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

        # Check GNSS and 1PPS alarms if nmea source is configured
        if obj.capabilities['ts2phc_source'] == 'nmea':
            if ctrl.instance_type == PTP_INSTANCE_TYPE_TS2PHC:
                check_gnss_signal(instance)
            if ctrl.instance_type == PTP_INSTANCE_TYPE_CLOCK:
                check_1pps_signal(instance)

        # Check time drift and manage PTP clock class if any ts2phc
        # source is configured, and instance type is PTP4l.
        if obj.capabilities['ts2phc_source'] and \
           ctrl.instance_type == PTP_INSTANCE_TYPE_PTP4L:
            # Removed redundant call to check_time_drift()
            # Handled in check_ptp_regular() above
            # Manage PTP clock class only for configured follower PHC clocks
            if ctrl.interface and \
               Interface.base_port(ctrl.interface) in ts2phc_source_interfaces.keys():
                check_clock_class(instance)

        if ctrl.instance_type == PTP_INSTANCE_TYPE_PTP4L:
            handle_ptp4l_g8275_fields(instance)

        if ctrl.instance_type == PTP_INSTANCE_TYPE_PHC2SYS and ctrl.phc2sys_ha_enabled is True:
            process_phc2sys_ha(ctrl)

        if ctrl.instance_type == PTP_INSTANCE_TYPE_GNSS_MONITOR:
            process_gnss_monitor(ctrl)

    return 0


def process_gnss_monitor_alarm(ctrl, alarm_obj, device_path, raise_condition, state):
    if raise_condition:
        rc = raise_alarm(alarm_obj.alarm, device_path, state, alarm_obj)
        if rc is True:
            alarm_obj.raised = True

        if not (ctrl.log_throttle_count % obj.INIT_LOG_THROTTLE):
            collectd.info(
                "%s %s instance %s device_path %s alarm raised: %s"
                % (
                    PLUGIN,
                    ctrl.instance_type,
                    ctrl.timing_instance.instance_name,
                    device_path,
                    state,
                )
            )
        ctrl.log_throttle_count += 1
    else:
        if alarm_obj.raised is True:
            if clear_alarm(alarm_obj.eid) is True:
                alarm_obj.raised = False
                collectd.info(
                    "%s %s instance %s device path %s alarm cleared: %s"
                    % (
                        PLUGIN,
                        ctrl.instance_type,
                        ctrl.timing_instance.instance_name,
                        device_path,
                        state,
                    )
                )


def process_gnss_monitor(ctrl):
    collectd.debug(f"{PLUGIN} {ctrl.timing_instance.instance_name} process_gnss_monitor")
    # per device signal lock expected
    expected_signal_lock = True

    # per device expected satellite count, read from config file.
    expected_satellite_count = None
    try:
        expected_satellite_count = int(
            ctrl.timing_instance.config["global"]["satellite_count"]
        )
    except Exception as exc:
        collectd.error(
            "%s Reading satellite_count from gnss-monitor config file %s failed. error: %s"
            % (PLUGIN, ctrl.timing_instance.config_file_path, exc)
        )

    # per device expected signal quality db, read from config file.
    expected_signal_quality_db = None
    try:
        expected_signal_quality_db = float(
            ctrl.timing_instance.config['global']['signal_quality_db']
        )
    except Exception as exc:
        collectd.error(
            "%s Reading signal_quality_db from gnss-monitor config file %s failed. error: %s"
            % (PLUGIN, ctrl.timing_instance.config_file_path, exc)
        )

    ctrl.timing_instance.set_instance_state_data()
    for device_path in ctrl.timing_instance.device_paths:
        # alarm ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS
        signal_lock = ctrl.timing_instance.state[device_path].lock_state
        raise_condition = signal_lock != expected_signal_lock

        alarm_obj = get_alarm_object(
            ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS, device_path
        )
        state = f"signal lock {bool(signal_lock)} (expected: {expected_signal_lock})"

        process_gnss_monitor_alarm(ctrl, alarm_obj, device_path, raise_condition, state)

        # alarm ALARM_CAUSE__GNSS_MONITOR_SATELLITE_COUNT
        if expected_satellite_count is not None:
            satellite_count = ctrl.timing_instance.state[device_path].satellite_count
            raise_condition = satellite_count < expected_satellite_count

            alarm_obj = get_alarm_object(
                ALARM_CAUSE__GNSS_MONITOR_SATELLITE_COUNT, device_path
            )
            state = f"satellite count {satellite_count} (expected: >= {expected_satellite_count})"

            process_gnss_monitor_alarm(ctrl, alarm_obj, device_path, raise_condition, state)

        # alarm ALARM_CAUSE__GNSS_MONITOR_SIGNAL_QUALITY_DB
        if expected_signal_quality_db is not None:
            # alarm is based upon avg snr
            signal_quality_db = ctrl.timing_instance.state[
                device_path
            ].signal_quality_db.avg
            raise_condition = signal_quality_db < expected_signal_quality_db

            alarm_obj = get_alarm_object(
                ALARM_CAUSE__GNSS_MONITOR_SIGNAL_QUALITY_DB, device_path
            )
            state = (
                f"signal_quality_db {signal_quality_db}"
                f" (expected: >= {expected_signal_quality_db})"
            )

            process_gnss_monitor_alarm(ctrl, alarm_obj, device_path, raise_condition, state)


def process_phc2sys_ha(ctrl):
    # Update state for phc2sys instances
    collectd.debug(f"{PLUGIN} {ctrl.timing_instance.instance_name} process_phc2sys_ha")
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
    collectd.debug(f"{PLUGIN} check_ptp_regular {instance}")
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
    base_port = Interface.base_port(ctrl.interface)
    pps_status, _ = get_netlink_dpll_status(base_port, DeviceType.PPS)
    eec_status, _ = get_netlink_dpll_status(base_port, DeviceType.EEC)
    clock_locked = any(
        status in [CLOCK_STATE_LOCKED, CLOCK_STATE_LOCKED_HO_ACQ]
        for status in [pps_status, eec_status]
    )

    collectd.info(f"{PLUGIN} {obj.hostname} {instance} base port {base_port} "
                  f"eec {eec_status.value} pps {pps_status.value}")

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
        collectd.info("%s %s %s locked to remote Grand Master "
                      "(%s)" % (PLUGIN, obj.hostname, instance, gm_identity))
        if clear_alarm(ctrl.nolock_alarm_object.eid) is True:
            ctrl.nolock_alarm_object.raised = False

    if got_master_offset:
        check_time_drift(instance, gm_identity, master_offset)
    else:
        check_time_drift(instance, gm_identity)

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

    return 0


collectd.register_init(init_func)
collectd.register_read(read_func, interval=PLUGIN_AUDIT_INTERVAL)
