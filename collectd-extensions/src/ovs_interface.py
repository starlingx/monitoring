#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
#
############################################################################
#
# This is the OVS Interface Monitor plugin for collectd.
#
# This plugin monitors the OVS port and interface status. Some host interfaces
# will be added to OVS port. Only these port and interfaces will be monitored.
#
# This plugin only runs on openstack worker node because OVS is running on
# this kind of node.
#
# This plugin queries interface states by using OVS commands as following:
#     ovs-vsctl show
#     ovs-vsctl list-br
#     ovs-vsctl list-ifaces
#     ovs-ofctl dump-ports-desc
#     ovs-appctl --target=/var/run/openvswitch/ovs-vswitchd.43.ctl bond/list
#     ovs-appctl --target=/var/run/openvswitch/ovs-vswitchd.43.ctl bond/show
#
# By parsing the result, interface and port states can be retrived.
#
# To be noticed, the port can be a bond and then the port will contain multiple
# interfaces. In this case, the port states is determined by the states of all
# interfaces. The rule is following:

# Severity: Interface and Port levels
#
#  Alarm Level  Minor        Major                        Critical
#  -----------  -----  ---------------------      ----------------------------
#  Interface     N/A   Physical Link is Down      N/A
#       Port     N/A   Some interfaces are down   All Interface ports are Down
#
# Sample Data: represented as % of total interfaces Up for that port
#
#  100     or 100% percent used      - all interfaces of that port are up.
#  0<x<100 or 0%<x<100% percent used - some interfaces of that port are Down
#  0       or 0% percent used        - all interfaces for that port are Down
#
# For example:
#     x is 0 when all interfaces of that port are Down.
#     x is 50 when one interface of a two interface bond is down.
#     x is 66.7 when two of a three interface bond is down.
#     x is 100 when all interfaces of that port are up.
#
############################################################################

import os
import time
import datetime
import collectd
import plugin_common as pc
from oslo_concurrency import processutils
from fm_api import constants as fm_constants
from fm_api import fm_api
import tsconfig.tsconfig as tsc

# Fault manager API Object
api = fm_api.FaultAPIsV2()

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = 'ovs interface plugin'

# Interface Monitoring Interval in seconds
PLUGIN_AUDIT_INTERVAL = 10

# Sample Data 'type' and 'instance' database field values.
PLUGIN_TYPE = 'percent'
PLUGIN_TYPE_INSTANCE = 'usage'

# This plugin's timeout
PLUGIN_HTTP_TIMEOUT = 5

# OVS commands
OVS_VSCTL_LIST_BR = "ovs-vsctl list-br"
OVS_VSCTL_LIST_IFACES = "ovs-vsctl list-ifaces"
OVS_VSCTL_SHOW = "ovs-vsctl show"
OVS_OFCTL_DUMP_PORTS_DESC = "ovs-ofctl dump-ports-desc"
OVS_APPCTL = "ovs-appctl"
BOND_LIST = "bond/list"
BOND_SHOW = "bond/show"
LACP_SHOW = "lacp/show"

# socket for ovs-vswitchd
OVS_VSWITCHD_SOCKET = ""

# Path for ovs-vswitchd
OVS_VSWITCHD_PATH = "/var/run/openvswitch/ovs-vswitchd"

# Path of the pid file for ovs-vswitchd
OVS_VSWITCHD_PID_FILE = "/var/run/openvswitch/ovs-vswitchd.pid"

# Interface path
INTERFACE_PATH = "/sys/class/net"

# Virtual Interface Path
VIRTUAL_INTERFACE_PATH = "/sys/devices/virtual/net"

# Port and Interface Alarm Identifiers
OVS_IFACE_ALARMID = fm_constants.FM_ALARM_ID_NETWORK_INTERFACE
OVS_PORT_ALARMID = fm_constants.FM_ALARM_ID_NETWORK_PROVIDERNET

# List of all ALARM ID
ALARM_ID_LIST = [OVS_IFACE_ALARMID, OVS_PORT_ALARMID]

# Port / Interface State strings
LINK_UP = 'Up'
LINK_DOWN = 'Down'
UNKNOWN_STATE = 'Unknown'

# Alarm control actions
ALARM_ACTION_RAISE = 'raise'
ALARM_ACTION_CLEAR = 'clear'

# Alarm level.
# Interface is the lowest level and represent a physical link
# If bond is not used, Port only contains one interface
# If bond used, Port will contain multiple interfaces
LEVEL_INTERFACE = 'interface'
LEVEL_PORT = 'port'

# Run phases
RUN_PHASE__INIT = 0
RUN_PHASE__ALARMS_CLEARED = 1
RUN_PHASE__HTTP_REQUEST_PASS = 2

# Plugin http url prefix
PLUGIN_HTTP_URL_PREFIX = "http://localhost:"

# port object dictionary. key: bridge name value: PortObject
# Use this dictionary to track all ports. If sysadmin binds new interfaces
# with OVS bridge, the host will reboot and this dictionary will regenerate.
ports = {}

# Plugin Control Object
obj = pc.PluginObject(PLUGIN, PLUGIN_HTTP_URL_PREFIX)


# Interface Object (aka Physical interface) Structure
# and member functions.
class InterfaceObject:

    def __init__(self, name):

        self.name = name
        self.state = LINK_UP
        self.timestamp = datetime.datetime.now()
        self.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.alarm_id = OVS_IFACE_ALARMID
        self.state_change = True

        collectd.debug("%s InterfaceObject constructor: %s" %
                       (PLUGIN, self.name))

    ##################################################################
    #
    # Name       : _raise_alarm
    #
    # Purpose    : This interface object member function is used to
    #              raise interface alarm.
    #
    # Returns    : False on failure
    #              True on success
    #
    ##################################################################
    def _raise_alarm(self):
        """Raise an interface alarm"""

        if self.severity != fm_constants.FM_ALARM_SEVERITY_MAJOR:

            self.timestamp = datetime.datetime.now()
            if manage_alarm(self.name,
                            LEVEL_INTERFACE,
                            ALARM_ACTION_RAISE,
                            fm_constants.FM_ALARM_SEVERITY_MAJOR,
                            self.alarm_id,
                            self.timestamp) is True:

                self.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
                collectd.info("%s %s %s interface alarm raised" %
                              (PLUGIN, self.name, self.alarm_id))
                return True
            else:
                return False
        else:
            return True

    ##################################################################
    #
    # Name       : _clear_alarm
    #
    # Purpose    : This Interface object member function is used to
    #              clear interface alarm.
    #
    # Returns    : False on failure
    #              True on success.
    #
    ##################################################################
    def _clear_alarm(self):
        """Clear an interface alarm"""

        if self.severity != fm_constants.FM_ALARM_SEVERITY_CLEAR:
            if manage_alarm(self.name,
                            LEVEL_INTERFACE,
                            ALARM_ACTION_CLEAR,
                            fm_constants.FM_ALARM_SEVERITY_CLEAR,
                            self.alarm_id,
                            self.timestamp) is True:

                collectd.info("%s %s %s interface alarm cleared" %
                              (PLUGIN, self.name, self.alarm_id))
                self.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
                return True
            else:
                return False
        else:
            return True

    def manage_interface_alarm(self, current_state):
        """raise or clear interface alarm based on previous/current state"""

        if current_state != self.state:
            if current_state == LINK_UP:
                # clear alarm
                self._clear_alarm()
            elif current_state == LINK_DOWN:
                # raise alarm
                self._raise_alarm()
            else:
                # Unknown state
                # raise alarm
                self._raise_alarm()

            self.state = current_state


# Port Level Object Structure and member functions
# Normal Port only has one interface.
# If a Port is a bond, the port may have multiple interfaces
class PortObject:

    def __init__(self, bridge_name):

        # If bond is used, port name will be the same as bond name
        # and can be used to retrieve bond status
        # port name will only be set if this port is a bond
        self.name = ""
        # the bridge where the port is attached
        self.bridge_name = bridge_name
        self.sample = 0
        self.sample_last = 0
        self.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.degraded = False
        self.timestamp = datetime.datetime.now()
        self.alarm_id = OVS_PORT_ALARMID
        self.interfaces = []   # bond may contain multiple interfaces

        collectd.debug("%s %s PortObject constructor: %s" %
                       (PLUGIN, bridge_name, self.alarm_id))

    ##################################################################
    #
    # Name       : _raise_alarm
    #
    # Purpose    : This port object member function used to
    #              raise port alarm.
    #
    # Parameters : current severity
    #
    # Returns    : False on failure
    #              True on success
    #
    ##################################################################
    def _raise_alarm(self, current_severity):
        """Raise a port alarm"""

        if current_severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
            collectd.error("%s %s raise alarm called with clear severity" %
                           (PLUGIN, self.bridge_name))
            return True

        if self.severity != current_severity:
            if self.name:
                name = ":".join([self.bridge_name, self.name])
            else:
                name = self.bridge_name

            self.timestamp = datetime.datetime.now()
            if manage_alarm(name,
                            LEVEL_PORT,
                            ALARM_ACTION_RAISE,
                            current_severity,
                            self.alarm_id,
                            self.timestamp) is True:

                self.severity = current_severity
                if self.name:
                    collectd.info("%s %s %s %s port alarm raised" %
                                  (PLUGIN,
                                   self.bridge_name,
                                   self.name,
                                   pc.get_severity_str(current_severity)))
                else:
                    collectd.info("%s %s %s port alarm raised" %
                                  (PLUGIN,
                                   self.bridge_name,
                                   pc.get_severity_str(current_severity)))
                return True
            else:
                return False
        else:
            return True

    ##################################################################
    #
    # Name       : _clear_alarm
    #
    # Purpose    : This port object member function used to
    #              clear port alarm.
    #
    # Parameters : None
    #
    # Returns    : False on failure
    #              True on success.
    #
    ##################################################################
    def _clear_alarm(self):
        """Clear a port alarm"""

        if self.severity != fm_constants.FM_ALARM_SEVERITY_CLEAR:
            if self.name:
                name = ":".join([self.bridge_name, self.name])
            else:
                name = self.bridge_name

            if manage_alarm(name,
                            LEVEL_PORT,
                            ALARM_ACTION_CLEAR,
                            fm_constants.FM_ALARM_SEVERITY_CLEAR,
                            self.alarm_id,
                            self.timestamp) is True:

                collectd.info("%s %s %s %s port alarm cleared" %
                              (PLUGIN,
                               self.name,
                               self.alarm_id,
                               pc.get_severity_str(self.severity)))
                self.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
                return True
            else:
                return False
        else:
            return True

    ######################################################################
    #
    # Name     : manage_port_alarm
    #
    # Purpose  : clear or raise appropriate severity level port alarm
    #
    # Returns  : None
    #
    ######################################################################
    def manage_port_alarm(self):
        """clear or raise appropriate severity level port alarm"""

        # not bond
        if len(self.interfaces) == 1:
            interface = self.interfaces[0]
            if interface.state == LINK_UP:
                current_severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
            elif interface.state == LINK_DOWN:
                current_severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL
            else:
                current_severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL
        # bond
        # if interfaces all down or unknown state: critical
        # if some interfaces down or unknown state: major
        # if interfaces all up: clear
        elif len(self.interfaces) > 1:
            all_up = True
            all_down = True
            for interface in self.interfaces:
                if interface.state == LINK_UP:
                    all_down = False
                elif interface.state == LINK_DOWN:
                    all_up = False
                else:
                    all_up = False

            if all_up:
                current_severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
            elif all_down:
                current_severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL
            else:
                current_severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        # bridge doesn't have physical interfaces
        else:
            collectd.info("%s port %s doesn't have physical interfaces"
                          % (PLUGIN, self.bridge_name))
            return 0

        if current_severity != self.severity:
            if current_severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
                self._clear_alarm()
            elif current_severity == fm_constants.FM_ALARM_SEVERITY_MAJOR:
                self._raise_alarm(fm_constants.FM_ALARM_SEVERITY_MAJOR)
            elif current_severity == fm_constants.FM_ALARM_SEVERITY_CRITICAL:
                self._raise_alarm(fm_constants.FM_ALARM_SEVERITY_CRITICAL)
            else:
                collectd.debug("%s failed to manage_port_alarm" % PLUGIN)
                return 0
        # self.severity will be updated in function _raise_alarm() and
        # _clear_alarm()


#########################################################################
#
# Name       : this_hosts_alarm
#
# Purpose    : Determine if the supplied eid is for this host.
#
# Description: The eid formats for the alarms managed by this plugin are
#
#              host=<hostname>.interface=<interface_name>
#              host=<hostname>.port=<bridge_name>
#              host=<hostname>.port=<bridge_name>:<port_name>
#
# Assumptions: There is no restriction preventing the system
#              administrator from creating hostnames with period's ('.')
#              in them. Because so the eid cannot simply be split
#              around '='s and '.'s. Instead its split around this
#              plugins level type '.port' or '.interface'.
#
# Returns    : True if hostname is a match
#              False otherwise
#
##########################################################################
def this_hosts_alarm(hostname, eid):
    """Check if the specified eid is for this host"""

    if hostname:
        if eid:
            # 'host=controller-0.interface=eth0'
            # 'host=controller-0.port=br-phy0'
            # 'host=controller-0.port=br-phy0:bond0'
            try:
                eid_host = None
                eid_disected = eid.split('=')
                if len(eid_disected) == 3:
                    # ['host', 'controller-0.interface', 'eth0']
                    # ['host', 'controller-0.port', 'br-phy0']
                    # ['host', 'controller-0.port', 'br-phy0:bond0']
                    if len(eid_disected[1].split('.interface')) == 2:
                        eid_host = eid_disected[1].split('.interface')[0]
                        if eid_host and eid_host == hostname:
                            return True
                    elif len(eid_disected[1].split('.port')) == 2:
                        eid_host = eid_disected[1].split('.port')[0]
                        if eid_host and eid_host == hostname:
                            return True
            except Exception as ex:
                collectd.error("%s failed to parse alarm eid (%s)"
                               " [eid:%s]" % (PLUGIN, str(ex), eid))

    return False


##########################################################################
#
# Name       : clear_alarms
#
# Purpose    : Clear all interface alarms on process startup.
#
# Description: Loops over the provided alarm id list querying all alarms
#              for each. Any that are raised are precisely cleared.
#
#              Prevents stuck alarms over port and interface reconfig.
#
#              If the original alarm case still exists the alarm will
#              be re-raised.
#
# Parameters : A list of this plugin's alarm ids
#
# Returns    : True on Success
#              False on Failure
#
##########################################################################
def clear_alarms(alarm_id_list):
    """Clear alarm state of all plugin alarms"""
    found = False
    for alarm_id in alarm_id_list:

        try:
            alarms = api.get_faults_by_id(alarm_id)
        except Exception as ex:
            collectd.error("%s 'get_faults_by_id' exception ;"
                           " %s ; %s" %
                           (PLUGIN, alarm_id, ex))
            return False

        if alarms:
            for alarm in alarms:
                eid = alarm.entity_instance_id
                if this_hosts_alarm(obj.hostname, eid) is False:
                    # ignore other host alarms
                    continue

                if alarm_id == OVS_IFACE_ALARMID or \
                        alarm_id == OVS_PORT_ALARMID:

                    try:
                        if api.clear_fault(alarm_id, eid) is False:
                            collectd.info("%s %s:%s:%s alarm already cleared" %
                                          (PLUGIN,
                                           alarm.severity,
                                           alarm_id,
                                           eid))
                        else:
                            found = True
                            collectd.info("%s %s:%s:%s alarm cleared" %
                                          (PLUGIN,
                                           alarm.severity,
                                           alarm_id,
                                           eid))
                    except Exception as ex:
                        collectd.error("%s 'clear_fault' exception ; "
                                       "%s:%s ; %s" %
                                       (PLUGIN, alarm_id, eid, ex))
                        return False
    if found is False:
        collectd.info("%s found no startup alarms" % PLUGIN)

    return True


##########################################################################
#
# Name       : manage_alarm
#
# Purpose    : Raises or clears port and interface alarms based on
#              calling parameters.
#
# Returns    : True on success
#              False on failure
#
##########################################################################
def manage_alarm(name, level, action, severity, alarm_id, timestamp):
    """Manage raise and clear port and interface alarms"""

    ts = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')

    if action == ALARM_ACTION_CLEAR:
        alarm_state = fm_constants.FM_ALARM_STATE_CLEAR
        reason = ''
        repair = ''
    else:
        # reason ad repair strings are only needed on alarm assertion
        alarm_state = fm_constants.FM_ALARM_STATE_SET
        reason = "'" + name + "' " + level
        repair = 'Check cabling and far-end port configuration ' \
                 'and status on adjacent equipment.'

    # build the alarm eid and name string
    if level == LEVEL_INTERFACE:
        eid = 'host=' + obj.hostname + "." + level + '=' + name
        reason += " failed"
    else:
        eid = 'host=' + obj.hostname + "." + level + '=' + name
        if severity == fm_constants.FM_ALARM_SEVERITY_MAJOR:
            reason += " degraded"
        else:
            reason += " failed"

    if alarm_state == fm_constants.FM_ALARM_STATE_CLEAR:
        try:
            if api.clear_fault(alarm_id, eid) is False:
                collectd.info("%s %s:%s alarm already cleared" %
                              (PLUGIN, alarm_id, eid))
            else:
                collectd.info("%s %s:%s alarm cleared" %
                              (PLUGIN, alarm_id, eid))
            return True

        except Exception as ex:
            collectd.error("%s 'clear_fault' failed ; %s:%s ; %s" %
                           (PLUGIN, alarm_id, eid, ex))
            return False

    else:
        fault = fm_api.Fault(
            uuid="",
            alarm_id=alarm_id,
            alarm_state=alarm_state,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=eid,
            severity=severity,
            reason_text=reason,
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN,
            proposed_repair_action=repair,
            service_affecting=True,
            timestamp=ts,
            suppression=True)

        try:
            alarm_uuid = api.set_fault(fault)
        except Exception as ex:
            collectd.error("%s 'set_fault' exception ; %s:%s ; %s" %
                           (PLUGIN, alarm_id, eid, ex))
            return False

        if pc.is_uuid_like(alarm_uuid) is False:
            collectd.error("%s 'set_fault' failed ; %s:%s ; %s" %
                           (PLUGIN, alarm_id, eid, alarm_uuid))
            return False
        else:
            return True


def get_physical_interfaces():
    """get host physical interfaces"""

    if (os.path.exists(INTERFACE_PATH)):
        try:
            interfaces = os.listdir(INTERFACE_PATH)
        except EnvironmentError as e:
            collectd.error(str(e), UserWarning)

    if (os.path.exists(VIRTUAL_INTERFACE_PATH)):
        try:
            virtual_interfaces = os.listdir(VIRTUAL_INTERFACE_PATH)
        except EnvironmentError as e:
            collectd.error(str(e), UserWarning)

    if interfaces:
        if virtual_interfaces:
            physical_interfaces = []
            for interface in interfaces:
                if interface not in virtual_interfaces:
                    physical_interfaces.append(interface)
            return physical_interfaces
        else:
            return interfaces
    else:
        collectd.error("%s finds no interfaces in path %s" %
                       (PLUGIN, INTERFACE_PATH))


def parse_ovs_vsctl_list_ports(buf):
    """parse the result of command ovs-vsctl list-ports $BRIDGE"""

    buf = buf.strip().split("\n")
    return buf


def parse_ovs_vsctl_list_ifaces(buf):
    """parse the result of command ovs-vsctl list-ifaces $BRIDGE"""

    buf = buf.strip().split("\n")
    return buf


def parse_ovs_ofctl_dump_ports_desc(buf, port):
    """parse the result of command ovs-ofctl dump-ports-desc $BRIDGE"""

    #OFPST_PORT_DESC reply (xid=0x2):
    # 1(lldpb111d58c-6b): addr:52:e4:c9:da:19:32
    #     config:     0
    #     state:      0
    #     current:    10MB-FD COPPER
    #     speed: 10 Mbps now, 0 Mbps max
    # 2(eth0): addr:3c:fd:fe:da:e8:84
    #     config:     0
    #     state:      LINK_DOWN
    #     current:    AUTO_NEG
    #     speed: 0 Mbps now, 0 Mbps max
    # LOCAL(br-phy0): addr:3c:fd:fe:da:e8:84
    #     config:     0
    #     state:      0
    #     current:    10MB-FD COPPER
    #     speed: 10 Mbps now, 0 Mbps max

    buf = buf.strip().split("\n")
    result = {}
    find = False
    for idx, line in enumerate(buf):
        line = line.strip()
        for interface in port.interfaces:
            if interface.name in line:
                state = buf[idx + 2].split(":")
                if "0" in state[1]:
                    result[interface.name] = LINK_UP
                elif "LINK_DOWN" in state[1]:
                    result[interface.name] = LINK_DOWN
                else:
                    result[interface.name] = UNKNOWN_STATE

    return result


def parse_ovs_vsctl_show(buf, bridge):
    """parse the result of command ovs-vsctl show $PORT"""

    #  Bridge "br-phy1"
    #    Port "eth1"
    #        Interface "eth1"
    #            type: dpdk
    #            options: {dpdk-devargs="0000:18:00.1", n_rxq="1"}
    buf = buf.strip().split("\n")
    result = []
    find = False
    for line in buf:
        line = line.strip()
        if "Bridge" in line:
            if bridge in line:
                find = True
                port = ""
            else:
                find = False
        if find:
            if line.startswith("Port"):
                port = line[4:].strip()
                if port.startswith("\""):
                    port = port[1:len(port) - 1]
            if port:
                if "dpdk" in line:
                    result.append(port)

    return result


def parse_ovs_appctl_bond_list(buf):
    """parse the result of command ovs-appctl bond/list"""

    # bond    type    recircID        slaves
    # bond0   active-backup   0       enp134s0f1, enp134s0f0
    buf = buf.strip().split("\n")
    result = {}
    for idx, line in enumerate(buf):
        if idx is 0:
            continue

        line = line.strip()
        items = line.split("\t")
        interfaces = items[3].split(",")
        for idx, interface in enumerate(interfaces):
            interfaces[idx] = interface.strip()

        result[items[0]] = interfaces

    return result


def parse_ovs_appctl_bond_show(buf):
    """parse the result of command ovs-appctl bond/show $PORT"""

    #---- bond0 ----
    #bond_mode: active-backup
    #bond may use recirculation: no, Recirc-ID : -1
    #bond-hash-basis: 0
    #updelay: 0 ms
    #downdelay: 0 ms
    #lacp_status: configured
    #lacp_fallback_ab: false
    #active slave mac: 00:00:00:00:00:00(none)
    #
    #slave enp134s0f0: disabled
    #  may_enable: false
    #
    #slave enp134s0f1: disabled
    #  may_enable: false
    buf = buf.strip().split("\n")
    states = {}
    for idx, line in enumerate(buf):
        line = line.strip()
        if line.startswith("slave"):
            state = line.split(":")
            interface = state[0][6:]
            if "disabled" in state[1]:
                states[interface] = LINK_DOWN
            elif "enabled" in state[1]:
                states[interface] = LINK_UP
            else:
                states[interface] = UNKNOWN_STATE

    return states


def is_physical_interface(interface, bridge):
    """Check whether interface is physical interface or not

    If OVS-DPDK is used, the relative interface can't be found
    in directory /sys/class/net
    """

    physical_interfaces = get_physical_interfaces()
    if interface in physical_interfaces:
        return True

    # The interface will have type dpdk
    #  Bridge "br-phy1"
    #    Port "eth1"
    #        Interface "eth1"
    #            type: dpdk
    #            options: {dpdk-devargs="0000:18:00.1", n_rxq="1"}
    res, err = processutils.execute(OVS_VSCTL_SHOW, shell=True)
    if err:
        raise Exception("%s failed to run command ovs-vsctl show %s"
                        "retry next audit" % (PLUGIN, err))
    elif res:
        dpdk_interfaces = parse_ovs_vsctl_show(res, bridge)
        if interface in dpdk_interfaces:
            return True
        else:
            return False
    else:
        return False


def is_interface_in_port(interface, port):
    """Check interface is in port or not"""

    for iface in port.interfaces:
        if interface == iface.name:
            return True

    return False


def compare_interfaces(interfaces1, interfaces2):
    set1 = set(interfaces1)
    set2 = set(interfaces2)
    len1 = len(set1 - set2)
    len2 = len(set2 - set1)

    if len1 is 0 and len2 is 0:
        return True
    else:
        return False


# The config function - called once on collectd process startup
def config_func(config):

    """Configure the plugin"""

    collectd.info('%s config function' % PLUGIN)


# The init function - called once on collectd process startup
def init_func():
    """Init the plugin"""

    if obj.init_done is False:
        if obj.init_ready() is False:
            return 0

    # Only runs on worker nodes
    if 'worker' not in tsc.subfunctions:
        return 0

    # Check whether this host is openstack worker node or not
    # OVS and OVSDPDK will only run on openstack worker node
    # For non openstack worker node, pid file won't exist
    if os.path.exists(OVS_VSWITCHD_PID_FILE):
        with open(OVS_VSWITCHD_PID_FILE, 'r') as infile:
            count = 0
            for line in infile:
                pid = line.strip()
                count += 1

            if count == 1 and pid:
                # /var/run/openvswitch/ovs-vswitchd.43.ctl
                global OVS_VSWITCHD_SOCKET
                OVS_VSWITCHD_SOCKET = \
                    "".join([OVS_VSWITCHD_PATH, ".", pid, ".ctl"])
                obj.init_done = True
                obj.hostname = obj.gethostname()
                collectd.info("%s initialization complete" % PLUGIN)
                obj.error_logged = False

            elif obj.error_logged is False:
                collectd.info("%s failed to retrieve pid for ovs-vswitchd in "
                              "file /var/run/openvswitch/ovs-vswitchd.pid" %
                              PLUGIN)
                obj.error_logged = True

    elif obj.error_logged is False:
        collectd.info("%s waiting for ovs-vswitchd to be running" % PLUGIN)
        obj.error_logged = True

    return 0


# The sample read function - called on every audit interval
def read_func():
    """collectd ovs interface/port monitor plugin read function"""

    if obj.init_done is False:
        init_func()
        return 0

    if obj.phase < RUN_PHASE__ALARMS_CLEARED:

        # clear all alarms on first audit
        #
        # block on fm availability
        #
        # If the existing raised alarms are still valid then
        # they will be re-raised
        if clear_alarms(ALARM_ID_LIST) is False:
            collectd.error("%s failed to clear existing alarms ; "
                           "retry next audit" % PLUGIN)

            # Don't proceed till we can communicate with FM and
            # clear all existing interface and port alarms.
            return 0
        else:
            obj.phase = RUN_PHASE__ALARMS_CLEARED

    # construct monitoring objects
    bridges_phy = []
    res, err = processutils.execute(OVS_VSCTL_LIST_BR, shell=True)
    if err:
        collectd.error("%s failed to list ovs bridges ; "
                       "retry next audit" % PLUGIN)
        return 0
    elif res:
        # remove the trailing '\n' with strip()
        bridges = res.strip().split("\n")
        for bridge in bridges:
            # the bridges added by starlingx follows the format br-phy%num
            # the bridges' name start with br-phy is used for datanetwork
            if bridge.startswith("br-phy"):
                bridges_phy.append(bridge)
    else:
        collectd.error("%s find no ovs bridges ; "
                       "retry next audit" % PLUGIN)
        return 0

    # generate port and interface objects for first time
    physical_interfaces = get_physical_interfaces()
    for bridge in bridges_phy:
        if bridge not in ports:
            port = PortObject(bridge)
            ports[bridge] = port

        cmd = " ".join([OVS_VSCTL_LIST_IFACES, bridge])
        res, err = processutils.execute(cmd, shell=True)
        if err:
            collectd.error("%s failed to dump ports %s desc ; "
                           "retry next audit" % (PLUGIN, bridge))
            return 0
        elif res:
            interfaces = parse_ovs_vsctl_list_ifaces(res)
            port = ports[bridge]
            # Remove the physical interfaces which has been removed from port
            remove_list = []
            for interface in port.interfaces:
                if interface.name not in interfaces:
                    remove_list.append(interface)

            for interface in remove_list:
                # Remove the existing alarms before deleting interface
                interface.manage_interface_alarm(LINK_UP)
                interface.state = LINK_UP
                port.interfaces.remove(interface)

            # Add physical interfaces to port.interfaces
            for interface in interfaces:
                try:
                    if is_physical_interface(interface, bridge):
                        if not is_interface_in_port(interface, port):
                            iface = InterfaceObject(interface)
                            port.interfaces.append(iface)
                except Exception as ex:
                    collectd.error("%s exception %s" % (PLUGIN, ex))
                    return 0

    for port in ports.values():
        # Delete the port which has been removed from OVS
        if port.bridge_name not in bridges_phy:
            # Remove the existing alarms before delete ports
            for interface in port.interfaces:
                interface.manage_interface_alarm(LINK_UP)
                interface.state = LINK_UP
            port.manage_port_alarm()
            ports.pop(port.bridge_name)
            continue

        # Retrieve interface state
        cmd = " ".join([OVS_OFCTL_DUMP_PORTS_DESC, port.bridge_name])
        res, err = processutils.execute(cmd, shell=True)
        if err:
            collectd.error("%s failed to dump ports %s desc ; "
                           "retry next audit" % (PLUGIN, bridge))
            return 0
        elif res:
            states = parse_ovs_ofctl_dump_ports_desc(res, port)
            # Not bond
            if len(port.interfaces) == 1:
                interface = port.interfaces[0]
                interface.manage_interface_alarm(states[interface.name])
                interface.state = states[interface.name]
            # Bond: do nothing here
            # Need to use ovs-appctl commands to retrieve bond interfaces
            # status. Because if LACP is enabled for bond, it can detect
            # the remote status of the bond which can't retrived here.

    # handle bond
    cmd = "".join([OVS_APPCTL, " --target=", OVS_VSWITCHD_SOCKET, " ", BOND_LIST])
    res, err = processutils.execute(cmd, shell=True)
    if err:
        collectd.error("%s failed to list bond ; "
                       "retry next audit" % PLUGIN)
        return 0
    elif res:
        bonds = parse_ovs_appctl_bond_list(res)

    # Mapping bond to port by checking interfaces same or not
    # If port is a bond, the port name will be set
    for bond, interfaces in bonds.iteritems():
        for port in ports.values():
            port_interfaces = []
            for iface in port.interfaces:
                port_interfaces.append(iface.name)
            if compare_interfaces(interfaces, port_interfaces):
                port.name = bond

    for port in ports.values():
        if port.name:
            cmd = "".join([OVS_APPCTL, " --target=", OVS_VSWITCHD_SOCKET,
                           " ", BOND_SHOW, " ", port.name])
            res, err = processutils.execute(cmd, shell=True)
            if err:
                collectd.error("%s failed to list bond ; "
                               "retry next audit" % PLUGIN)
                return 0
            elif res:
                states = parse_ovs_appctl_bond_show(res)
                for interface in port.interfaces:
                    interface.manage_interface_alarm(states[interface.name])
                    interface.state = states[interface.name]

    # Manage port alarms
    for port in ports.values():
        port.manage_port_alarm()

    # Dispatch usage value to collectd
    val = collectd.Values(host=obj.hostname)
    val.plugin = 'ovs interface'
    val.type = 'percent'
    val.type_instance = 'used'

    # For each port
    #   calculate the percentage used sample
    #      sample = 100 % when all its links are up
    #      sample =   0 % when all its links are down
    #      sample =   x % x > 0 and x < 100. Some interfaces of
    #                     that bond are Down. For example, x will
    #                     be 50 when one interface of the bond
    #                     which contains two interfaces is down.
    #                     x will be 66.7 when two of the bond
    #                     which contains three interfaces is down.
    for port in ports.values():
        if len(port.interfaces) > 0:
            val.plugin_instance = port.bridge_name
            port_up = 0.0
            for interface in port.interfaces:
                if interface.state == LINK_UP:
                    port_up += 1.0

            port.sample = (port_up / float(len(port.interfaces))) * 100.0
            val.dispatch(values=[port.sample])

        else:
            collectd.debug("%s %s bridge not provisioned" %
                           (PLUGIN, port.bridge_name))
    obj.audits += 1

    return 0


# register the config, init and read functions
collectd.register_config(config_func)
collectd.register_init(init_func)
collectd.register_read(read_func, interval=PLUGIN_AUDIT_INTERVAL)
