#
# Copyright (c) 2018-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Version 1.0
#
############################################################################
#
# This file is the collectd 'FM Alarm' Notifier.
#
# This notifier debounces and then manages raising and clearing alarms
# and sending degrade assert and clear messages to maintenance based on
# Collectd resource usage severity notifications.
#
# Collectd process startup automatically calls this module's init_func which
# declares and initializes a plugObject class for plugin type in preparation
# for periodic ongoing monitoring where Collectd calls notify_func for each
# plugin and instance of that plugin every audit interval.
#
# All other class or common member functions implemented herein exist in
# support of that aformentioned initialization and periodic monitoring.
#
# Collectd provides information about each event as an object passed to the
# notification handler ; the notification object.
#
#    object.host              - the hostname.
#
#    object.plugin            - the name of the plugin aka resource.
#    object.plugin_instance   - plugin instance string i.e. say mountpoint
#                               for df plugin or numa? node for memory.
#    object.type,             - the unit i.e. percent or absolute.
#    object.type_instance     - the attribute i.e. free, used, etc.
#
#    object.severity          - a integer value 0=OK , 1=warning, 2=failure.
#    object.message           - a log-able message containing the above along
#                               with the value.
#
# This notifier uses the notification object to manage plugin/instance alarms.
#
# To avoid stuck alarms or missing alarms the plugin thresholds should be
# configured with Persist = true and persistOK = true. These controls tell
# Collectd to send notifications every audit interval regardless of state
# change.
#
# Persist   = False ; only send notifications on 'okay' to 'not okay' change.
# PersistOK = False ; only send notifications on 'not okay' to 'okay' change.
#
# With these both set to True in the threshold spec for the plugin then
# Collectd will call this notifier for each audit plugin/instance audit.
#
# Collectd supports only 2 threshold severities ; warning and failure.
# The 'failure' maps to 'critical' while 'warning' maps to 'major' in FM.
#
# To avoid unnecessary load on FM, this notifier maintains current alarm
# state and only makes an FM call on alarm state changes. Current alarm state
# is queried by the init function called by Collectd on process startup.
#
# Current alarm state is maintained by two severity lists for each plugin,
# a warnings list and a failures list.
#
# When a failure is reported against a specific plugin then that resources's
# entity_id is added to that plugin's alarm object's failures list. Similarly,
# warning assertions get their entity id added to plugin's alarm object's
# warnings list. Any entity id should only exist in one of the lists at one
# time or in none at all if the notification condition is 'okay' and the alarm
# is cleared.
#
# Adding Plugins:
#
# To add new plugin support just search for ADD_NEW_PLUGIN and add the data
# requested in that area.
#
# Example commands to read samples from the influx database
#
# SELECT * FROM df_value WHERE instance='root' AND type='percent_bytes' AND
#                                                      type_instance='used'
# SELECT * FROM cpu_value WHERE type='percent' AND type_instance='used'
# SELECT * FROM memory_value WHERE type='percent' AND type_instance='used'
#
############################################################################
#
# Import list

# UT imports
import os
import re
import socket
import collectd
from threading import RLock as Lock
from fm_api import constants as fm_constants
from fm_api import fm_api
import tsconfig.tsconfig as tsc
import plugin_common as pc

# only load influxdb on the controller
if tsc.nodetype == 'controller':
    from influxdb import InfluxDBClient

api = fm_api.FaultAPIsV2()

# Debug control
debug = False
debug_lists = False
want_state_audit = False
want_vswitch = False

# Number of notifier loop between each audit.
# @ 30 sec interval audit rate is every 5 minutes
AUDIT_RATE = 10

# write a 'value' log on a the resource sample change of more than this amount
LOG_STEP = 10

# Same state message throttle count.
# Only send the degrade message every 'this' number
# while the state of assert or clear remains the same.
ONE_EVERY = 20

# This plugin name
PLUGIN = 'alarm notifier'

# This plugin's degrade function
PLUGIN_DEGRADE = 'degrade notifier'

# the name of the collectd samples database
DATABASE_NAME = 'collectd samples'

READING_TYPE__PERCENT_USAGE = '% usage'

# Default invalid threshold value
INVALID_THRESHOLD = float(-1)

# 3 minute alarm assertion debounce
# 1 minute alarm clear debounce
#    assuming 30 second interval
DEBOUNCE_FROM_CLEAR_THLD = 7  # (((3 * 60) / 30) + 1)
DEBOUNCE_FROM_ASSERT_THLD = 3

# collectd severity definitions ;
# Note: can't seem to pull then in symbolically with a header
NOTIF_FAILURE = 1
NOTIF_WARNING = 2
NOTIF_OKAY = 4

PASS = 0
FAIL = 1

# Maintenance Degrade Service definitions

# default mtce port.
# ... with configuration override
MTCE_CMD_RX_PORT = 2101

# Filesystem plugin_instances are mangled by collectd.
# For instance the "/var/log" MountPoint instance is
# reported as "var-log".
#
# The following is a dictionary that provides mapping between the
# stock df plugin instance name and the linux filesystem pATH where the
# key = mangled filesystem instance from stock df plugin
# val = actual filesystem mountpoint path
#
# ADD_NEW_PLUGIN if there are new file systems being added that
# have subdirectories in the name then they will need to be added
# to the mangled list
DF_MANGLED_DICT = {
    # instance : path
    'root': '/',
    'dev': '/dev',
    'tmp': '/tmp',
    'boot': '/boot',
    'scratch': '/scratch',
    'dev-shm': '/dev/shm',
    'var-log': '/var/log',
    'var-run': '/var/run',
    'var-lock': '/var/lock',
    'var-lib-rabbitmq': '/var/lib/rabbitmq',
    'var-lib-postgresql': '/var/lib/postgresql',
    'var-lib-ceph-mon': '/var/lib/ceph/mon',
    'var-lib-docker': '/var/lib/docker',
    'var-lib-docker-distribution': '/var/lib/docker-distribution',
    'var-lib-kubelet': '/var/lib/kubelet',
    'var-lib-nova-instances': '/var/lib/nova/instances',
    'opt-platform': '/opt/platform',
    'opt-etcd': '/opt/etcd',
    'opt-extension': '/opt/extension',
    'opt-backups': '/opt/backups'}


# ADD_NEW_PLUGIN: add new alarm id definition
ALARM_ID__CPU = "100.101"
ALARM_ID__MEM = "100.103"
ALARM_ID__DF = "100.104"

ALARM_ID__VSWITCH_CPU = "100.102"
ALARM_ID__VSWITCH_MEM = "100.115"
ALARM_ID__VSWITCH_PORT = "300.001"
ALARM_ID__VSWITCH_IFACE = "300.002"


# ADD_NEW_PLUGIN: add new alarm id to the list
ALARM_ID_LIST = [ALARM_ID__CPU,
                 ALARM_ID__MEM,
                 ALARM_ID__DF,
                 ALARM_ID__VSWITCH_CPU,
                 ALARM_ID__VSWITCH_MEM,
                 ALARM_ID__VSWITCH_PORT,
                 ALARM_ID__VSWITCH_IFACE]

AUDIT_ALARM_ID_LIST = [ALARM_ID__CPU,
                       ALARM_ID__MEM,
                       ALARM_ID__DF]

# ADD_NEW_PLUGIN: add plugin name definition
# WARNING: This must line up exactly with the plugin
#          filename without the extension.
PLUGIN__DF = "df"
PLUGIN__CPU = "cpu"
PLUGIN__MEM = "memory"
PLUGIN__INTERFACE = "interface"
PLUGIN__NTP_QUERY = "ntpq"
PLUGIN__VSWITCH_PORT = "vswitch_port"
PLUGIN__VSWITCH_CPU = "vswitch_cpu"
PLUGIN__VSWITCH_MEM = "vswitch_mem"
PLUGIN__VSWITCH_IFACE = "vswitch_iface"

# ADD_NEW_PLUGIN: add plugin name to list
PLUGIN_NAME_LIST = [PLUGIN__CPU,
                    PLUGIN__MEM,
                    PLUGIN__DF,
                    PLUGIN__VSWITCH_CPU,
                    PLUGIN__VSWITCH_MEM,
                    PLUGIN__VSWITCH_PORT,
                    PLUGIN__VSWITCH_IFACE]

# Used to find plugin name based on alarm id
# for managing degrade for startup alarms.
ALARM_ID__TO__PLUGIN_DICT = {ALARM_ID__CPU: PLUGIN__CPU,
                             ALARM_ID__MEM: PLUGIN__MEM,
                             ALARM_ID__DF: PLUGIN__DF,
                             ALARM_ID__VSWITCH_CPU: PLUGIN__VSWITCH_CPU,
                             ALARM_ID__VSWITCH_MEM: PLUGIN__VSWITCH_MEM,
                             ALARM_ID__VSWITCH_PORT: PLUGIN__VSWITCH_PORT,
                             ALARM_ID__VSWITCH_IFACE: PLUGIN__VSWITCH_IFACE}

# Common plugin object
pluginObject = pc.PluginObject(PLUGIN, '')


#########################################
# The collectd Maintenance Degrade Object
#########################################
class DegradeObject:

    def __init__(self, port):
        """DegradeObject Class constructor"""

        # maintenance port for degrade messages
        self.port = port

        # controller floating address
        self.addr = None

        # specifies the protocol family to use when messaging maintenance.
        # if system is IPV6, then that is learned and this 'protocol' is
        # updated with AF_INET6
        self.protocol = socket.AF_INET

        self.resource = ""

        # List of plugin names that require degrade for specified severity.
        self.degrade_list__failure = [PLUGIN__DF,
                                      PLUGIN__MEM,
                                      PLUGIN__CPU,
                                      PLUGIN__INTERFACE]
        self.degrade_list__warning = [PLUGIN__INTERFACE]

        # The running list of resources that require degrade.
        # a degrade clear message is sent whenever this list is empty.
        # a degrade assert message is sent whenever this list is not empty.
        self.degrade_list = []

        # throttle down sending of duplicate degrade assert/clear messages
        self.last_state = "undef"
        self.msg_throttle = 0

    ##########################################################################
    #
    # Name    : _get_active_controller_ip
    #
    # Purpose : Lookup the active controller's ip address.
    #
    # Updates : self.addr with the active controller's address or
    #           None if lookup fails.
    #
    # Returns : Nothing
    #
    ##########################################################################
    def _get_active_controller_ip(self):
        """Get the active controller host IP"""

        try:
            self.addr = socket.getaddrinfo('controller', None)[0][4][0]
            collectd.info("%s controller ip: %s" %
                          (PLUGIN_DEGRADE, self.addr))
        except Exception as ex:
            self.addr = None
            collectd.error("%s failed to get controller ip ; %s" %
                           (PLUGIN_DEGRADE, str(ex)))

    ##########################################################################
    #
    # Name       : mtce_degrade_notifier
    #
    # Purpose    : Message mtcAgent with its requested degrade state of
    #              the host.
    #
    # Description: If the degrade list is empty then a clear state is sent to
    #              maintenance.
    #
    #              If degrade list is NOT empty then an assert state is sent
    #              to maintenance.
    #
    # For logging and to ease debug the code below will create a list of
    # degraded resource instances to be included in the message to maintenance
    # for mtcAgent to optionally log it.
    #
    # Updates    : Preserves this state as last state
    #
    # Returns    : Nothing
    #
    ##########################################################################
    def mtce_degrade_notifier(self, nObject):
        """Message mtcAgent with collectd degrade state of the host"""

        resources = ""
        if self.degrade_list:
            # loop over the list,
            # limit the degraded resource list being sent to mtce to 2
            for r in self.degrade_list[0:2]:
                resources += r + ','
            resources = resources[:-1]
            state = "assert"
        else:
            state = "clear"

        # Degrade message throttling ....
        #
        # Avoid sending the same last state message for up to ONE_EVERY count.
        # Degrade state is refreshed every 10 minutes with audit at 30 seconds.
        # Just reduce load on mtcAgent.
        if self.last_state == state and self.msg_throttle < ONE_EVERY:
            self.msg_throttle += 1
            return 0
        else:
            # Clear the message throttle counter
            self.msg_throttle = 0

        if self.degrade_list:
            collectd.info("%s degrade list: %s" %
                          (PLUGIN_DEGRADE, self.degrade_list))

        # Save state for next time
        self.last_state = state

        # Send the degrade state ; assert or clear message to mtcAgent.
        # If we get a send failure then log it and set the addr to None
        # so it forces us to refresh the controller address on the next
        # notification
        try:
            mtce_socket = socket.socket(self.protocol, socket.SOCK_DGRAM)
            if mtce_socket:
                if self.addr is None:
                    self._get_active_controller_ip()
                    if self.addr is None:
                        collectd.error("%s cannot send degrade notification ; "
                                       "controller address lookup failed" %
                                       PLUGIN_DEGRADE)
                        return 0

                # Create the Maintenance message.
                message = "{\"service\":\"collectd_notifier\","
                message += "\"hostname\":\"" + nObject.host + "\","
                message += "\"degrade\":\"" + state + "\","
                message += "\"resource\":\"" + resources + "\"}"
                collectd.info("%s: %s" % (PLUGIN_DEGRADE, message))

                mtce_socket.settimeout(1.0)
                mtce_socket.sendto(message, (self.addr, self.port))
                mtce_socket.close()
            else:
                collectd.error("%s %s failed to open socket (%s)" %
                               (PLUGIN_DEGRADE, self.resource, self.addr))
        except socket.error as e:
            if e.args[0] == socket.EAI_ADDRFAMILY:
                # Handle IPV4 to IPV6 switchover:
                self.protocol = socket.AF_INET6
                collectd.info("%s %s ipv6 addressing (%s)" %
                              (PLUGIN_DEGRADE, self.resource, self.addr))
            else:
                collectd.error("%s %s socket error (%s) ; %s" %
                               (PLUGIN_DEGRADE,
                                self.resource,
                                self.addr,
                                str(e)))
                # try self correction
                self.addr = None
                self.protocol = socket.AF_INET

    ##########################################################################
    #
    # Name    : remove_degrade_for_missing_filesystems
    #
    # Purpose : Removes degraded filesystems that are no longer mounted.
    #
    # Updates : might update self.degrade_list
    #
    # Returns : Nothing
    #
    ##########################################################################
    def remove_degrade_for_missing_filesystems(self):
        """Remove file systems that are no longer mounted"""

        for df_inst in self.degrade_list:

            # Only file system plugins are looked at.
            # File system plugin instance names are prefixed with 'df:'
            # as the first 3 chars in the instance name.
            if df_inst[0:3] == 'df:':
                path = df_inst.split('filesystem=')[1]

                # check the mount point.
                # if the mount point no longer exists then remove
                # this instance from the degrade list.
                if os.path.ismount(path) is False:
                    collectd.info("%s clearing degrade for missing %s ; %s" %
                                  (PLUGIN_DEGRADE, path, self.degrade_list))
                    self.degrade_list.remove(df_inst)

    ##########################################################################
    #
    # Name       : manage_degrade_list
    #
    # Purpose    : Track the resources that require this host to be degraded.
    #
    # Description: Manages the 'degrade_list' based on collectd notifications.
    #
    # Updates    : self.degrade list with resource names that have severity
    #              levels that require the host to be degraded.
    #
    # Returns    : Nothing
    #
    ###########################################################################
    def manage_degrade_list(self, nObject):
        """Collectd Mtce Notifier Handler Function"""

        remove = False
        add = False

        # Create the degrade id from the notifier object.
        # Format: <plugin name>:host=<hostname>.<plugin_instance_name>
        resource = nObject.plugin + ':' + 'host=' + os.uname()[1]
        if nObject.plugin == PLUGIN__DF:
            df_inst = DF_MANGLED_DICT.get(nObject.plugin_instance)
            if df_inst:
                resource += ".filesystem="
                resource += df_inst
            else:
                collectd.error("%s df instance '%s' lookup failed; ignoring" %
                               (PLUGIN_DEGRADE, nObject.plugin_instance))
                return

        elif nObject.plugin_instance:
            resource += '.' + nObject.plugin + '=' + nObject.plugin_instance

        # This block looks at the current notification severity
        # and manages the degrade_list.
        # If the specified plugin name exists in each of the warnings
        # or failure lists and there is a current severity match then
        # add that resource instance to the degrade list.
        # Conversely, if this notification is OKAY then make sure this
        # resource instance is not in the degrade list (remove it if it is)
        if nObject.severity is NOTIF_OKAY:
            if self.degrade_list and resource in self.degrade_list:
                remove = True

        elif nObject.severity is NOTIF_FAILURE:
            if self.degrade_list__failure:
                if nObject.plugin in self.degrade_list__failure:
                    if resource not in self.degrade_list:
                        # handle dynamic filesystems going missing over a swact
                        # or unmount and being reported as a transient error by
                        # the df plugin. Don't add it to the failed list if the
                        # mountpoint is gone.
                        add = True
                        if nObject.plugin == PLUGIN__DF:
                            path = DF_MANGLED_DICT.get(nObject.plugin_instance)
                            add = os.path.ismount(path)

            else:
                # If severity is failure and no failures cause degrade
                # then make sure this plugin is not in the degrade list,
                # Should never occur.
                if resource in self.degrade_list:
                    remove = True

        elif nObject.severity is NOTIF_WARNING:
            if self.degrade_list__warning:
                if nObject.plugin in self.degrade_list__warning:
                    if resource not in self.degrade_list:
                        # handle dynamic filesystems going missing over a swact
                        # or unmount and being reported as a transient error by
                        # the df plugin. Don't add it to the failed list if the
                        # mountpoint is gone.
                        add = True
                        if nObject.plugin == PLUGIN__DF:
                            path = DF_MANGLED_DICT.get(nObject.plugin_instance)
                            add = os.path.ismount(path)

                elif resource in self.degrade_list:
                    remove = True
            else:
                # If severity is warning and no warnings cause degrade
                # then make sure this plugin is not in the degrade list.
                if resource in self.degrade_list:
                    remove = True
        else:
            collectd.info("%s unsupported severity %d" %
                          (PLUGIN_DEGRADE, nObject.severity))

        if remove is True:
            self.degrade_list.remove(resource)
            collectd.info("%s '%s' removed from degrade list" %
                          (PLUGIN_DEGRADE, resource))
        elif add is True:
            self.degrade_list.append(resource)
            collectd.info("%s '%s' added to degrade list" %
                          (PLUGIN_DEGRADE, resource))


# Instantiate the maintenance degrade object
# This object persists from notification to notification
mtcDegradeObj = DegradeObject(MTCE_CMD_RX_PORT)


# fmAlarmObject Class
class fmAlarmObject:

    dbObj = None                           # shared database connection obj
    host = None                            # saved hostname
    lock = None                            # global lock for mread_func mutex
    database_setup = False                 # state of database setup
    database_setup_in_progress = False     # connection mutex
    plugin_path = None
    fm_connectivity = False

    def __init__(self, id, plugin):
        """fmAlarmObject Class constructor"""

        # plugin specific static class members.
        self.id = id               # alarm id ; 100.1??
        self.plugin = plugin       # name of the plugin ; df, cpu, memory ...
        self.plugin_instance = ""  # the instance name for the plugin
        self.resource_name = ""    # The top level name of the resource
        self.instance_name = ""    # The instance name

        # Unique identifier used in the degrade list to represent
        # this alarm object.
        #
        # Base Object:
        #
        # Format : PLUGIN:host=<hostname>
        # Example: memory:host=controller-0
        #
        # Instance Object:
        #
        # Format: <Base Object>.instance>
        # Example: memory:host=controller-0.memory=platform
        self.degrade_id = plugin + ':' + 'host=' + os.uname()[1]

        # Instance specific learned static class members.
        self.entity_id = ""        # fm entity id host=<hostname>.<instance>
        self.instance = ""         # <plugin>_<instance>

        # [ 'float value string','float threshold string]
        self.values = []
        self.value = float(0)       # float value of reading

        # This member is used to help log change values using the
        # LOG_STEP threshold consant
        self.last_value = float(0)

        # float value of threshold
        self.threshold = float(INVALID_THRESHOLD)

        # Common static class members.
        self.reason_warning = ""
        self.reason_failure = ""
        self.repair = ""
        self.alarm_type = fm_constants.FM_ALARM_TYPE_7     # OPERATIONAL
        self.cause = fm_constants.ALARM_PROBABLE_CAUSE_50  # THRESHOLD CROSS
        self.suppression = True
        self.service_affecting = False

        # default most reading types are usage
        self.reading_type = READING_TYPE__PERCENT_USAGE

        # Severity tracking lists.
        # Maintains severity state between notifications.
        # Each is a list of entity ids for severity asserted alarms.
        # As alarms are cleared so is the entry in these lists.
        # The entity id should only be in one lists for any given raised alarm.
        self.warnings = []
        self.failures = []

        # alarm debounce control
        self.warnings_debounce_counter = 0
        self.failures_debounce_counter = 0

        # total notification count
        self.count = 0

        # audit counters
        self.alarm_audit_threshold = 0
        self.state_audit_count = 0

        # For plugins that have multiple instances like df (filesystem plugin)
        # we need to create an instance of this object for each one.
        # This dictionary is used to associate an instance with its object.
        self.instance_objects = {}

        self.fault = None

    def _ilog(self, string):
        """Create a collectd notifier info log with the string param"""
        collectd.info('%s %s : %s' % (PLUGIN, self.plugin, string))

    def _llog(self, string):
        """Create a collectd notifier info log when debug_lists not empty"""
        if debug_lists:
            collectd.info('%s %s : %s' % (PLUGIN, self.plugin, string))

    def _elog(self, string):
        """Create a collectd notifier error log with the string param"""
        collectd.error('%s %s : %s' % (PLUGIN, self.plugin, string))

    ##########################################################################
    #
    # Name    : _state_audit
    #
    # Purpose : Debug Tool to log plugin object info.
    #
    #           Not called in production code.
    #
    # Only the severity lists are dumped for now.
    # Other info can be added as needed.
    # Can be run as an audit or called directly.
    #
    ##########################################################################

    def _state_audit(self, location):
        """Log the state of the specified object"""

        if self.id == ALARM_ID__CPU:
            _print_state()

        self.state_audit_count += 1
        if self.warnings:
            collectd.info("%s AUDIT %d: %s warning list %s:%s" %
                          (PLUGIN,
                           self.state_audit_count,
                           self.plugin,
                           location,
                           self.warnings))
        if self.failures:
            collectd.info("%s AUDIT %d: %s failure list %s:%s" %
                          (PLUGIN,
                           self.state_audit_count,
                           self.plugin,
                           location,
                           self.failures))

    ##########################################################################
    #
    # Name    : manage_change
    #
    # Purpose : Manage sample value change.
    #
    #           Handle no sample update case.
    #           Parse the notification log.
    #           Handle base object instances.
    #           Generate a log entry if the sample value changes more than
    #             step value.
    #
    ##########################################################################

    def manage_change(self, nObject):
        """Log resource instance value on step state change"""

        # filter out messages to ignore ; notifications that have no value
        if "has not been updated for" in nObject.message:
            collectd.info("%s %s %s (%s)" %
                          (PLUGIN,
                           self.entity_id,
                           nObject.message,
                           nObject.severity))
            return "done"

        # Get the value from the notification message.
        # The location in the message is different based on the message type ;
        #   normal reading or overage reading
        #
        # message: Host controller-0, plugin memory type percent   ... [snip]
        #          All data sources are within range again.
        #          Current value of "value" is 51.412038.            <------
        #
        # message: Host controller-0, plugin df (instance scratch) ... [snip]
        #          Data source "value" is currently 97.464027.       <------
        #          That is above the failure threshold of 90.000000. <------

        # recognized strings - value only     value and threshold
        #                      ------------   -------------------
        value_sig_list = ['Current value of', 'is currently']

        # list of parsed 'string version' float values ['value','threshold']
        self.values = []
        for sig in value_sig_list:
            index = nObject.message.find(sig)
            if index != -1:
                self.values = \
                    re.findall(r"[-+]?\d*\.\d+|\d+", nObject.message[index:-1])

        # contains string versions of the float values extracted from
        # the notification message. The threshold value is included for
        # readings that are out of threshold.
        if len(self.values):
            # validate the reading
            try:
                self.value = round(float(self.values[0]), 2)
                # get the threshold if its there.
                if len(self.values) > 1:
                    self.threshold = float(self.values[1])
                else:
                    self.threshold = float(INVALID_THRESHOLD)  # invalid value

            except ValueError as ex:
                collectd.error("%s %s value not integer or float (%s) (%s)" %
                               (PLUGIN, self.entity_id, self.value, str(ex)))
                return "done"
            except TypeError as ex:
                collectd.info("%s %s value has no type (%s)" %
                              (PLUGIN, self.entity_id, str(ex)))
                return "done"
        else:
            collectd.info("%s %s reported no value (%s)" %
                          (PLUGIN, self.entity_id, nObject.message))
            return "done"

        # get the last reading
        if self.last_value:
            last = float(self.last_value)
        else:
            last = float(0)

        # Determine if the change is large enough to log and save the new value
        logit = False
        if self.count == 0 or LOG_STEP == 0:
            logit = True
        elif self.reading_type == "connections":
            if self.value != last:
                logit = True
        elif self.value > last:
            if (last + LOG_STEP) < self.value:
                logit = True
        elif last > self.value:
            if (self.value + LOG_STEP) < last:
                logit = True

        # Case on types.
        #
        # Note: only usage type so far
        if logit:

            resource = self.resource_name

            # setup resource name for filesystem instance usage log
            if self.plugin == PLUGIN__DF:
                resource = self.instance_name

            elif self.plugin == PLUGIN__MEM:
                if self.instance_name:
                    resource = self.instance_name

            # setup resource name for vswitch process instance name
            elif self.plugin == PLUGIN__VSWITCH_MEM:
                resource += ' Processor '
                resource += self.instance_name

            if self.reading_type == READING_TYPE__PERCENT_USAGE:
                tmp = str(self.value).split('.')
                if len(tmp[0]) == 1:
                    pre = ':  '
                else:
                    pre = ': '
                collectd.info("%s reading%s%2.2f %s - %s" %
                              (PLUGIN,
                               pre,
                               self.value,
                               self.reading_type,
                               resource))

            elif self.reading_type == "connections" and \
                    self.instance_objects and \
                    self.value != self.last_value:
                if self.instance_objects:
                    collectd.info("%s monitor: %2d %s - %s" %
                                  (PLUGIN,
                                   self.value,
                                   self.reading_type,
                                   resource))

            # update last logged value
            self.last_value = round(self.value, 2)

    ##########################################################################
    #
    # Name       : debounce
    #
    # Purpose    : Debounce alarm and degrade action handling based on
    #              severity notifications from plugins.
    #
    # Description: Clear to assert has a 3 minute debounce
    #              All other state changes have 1 minute debounce.

    #              A true return indicates that debounce is complete and the
    #              current alarm severity needs to be acted upon.
    #
    #              A false return means that there is no severity change or
    #              that debouning a severity change is in progress and the
    #              caller should not take action on the current notification.
    #
    # Returns    : True if the alarm needs state change.
    #              False during debounce of if no alarm state change needed.
    #
    ##########################################################################

    def debounce(self, base_obj, entity_id, severity, this_value):
        """Check for need to update alarm data"""

        rc = False
        logit = False

        # Only % Usage readings are debounced and alarmed
        if base_obj.reading_type != READING_TYPE__PERCENT_USAGE:
            return False

        if entity_id in base_obj.warnings:
            self._llog(entity_id + " is already in warnings list")
            current_severity_str = "warning"
        elif entity_id in base_obj.failures:
            self._llog(entity_id + " is already in failures list")
            current_severity_str = "failure"
        else:
            self._llog(entity_id + " is already OK")
            current_severity_str = "okay"

        # No severity change case
        # Always clear debounce counters with no severity level change
        if severity == current_severity_str:
            self.warnings_debounce_counter = 0
            self.failures_debounce_counter = 0

        # From Okay -> Warning Case - PASS
        elif current_severity_str == "okay" and severity == "warning":
            logit = True
            self.warnings_debounce_counter += 1
            if self.warnings_debounce_counter >= DEBOUNCE_FROM_CLEAR_THLD:
                rc = True

            # Special Case: failures debounce counter should clear in this case
            # so that ; max-x failures and then a warning followed by more
            # failures should not allow the failure alarm assertion.
            # Need back to back DEBOUNCE_FROM_CLEAR_THLD failures to
            # constitute a failure alarm.
            self.failures_debounce_counter = 0

        # From Okay -> Failure
        elif current_severity_str == "okay" and severity == "failure":
            logit = True
            self.failures_debounce_counter += 1
            if self.failures_debounce_counter >= DEBOUNCE_FROM_CLEAR_THLD:
                rc = True

            # Special Case: warning debounce counter should track failure
            # so that ; say 2 failures and then a warning would constitute
            # a valid okay to warning alarm assertion.
            self.warnings_debounce_counter += 1

        # From Failure -> Okay Case
        elif current_severity_str == "failure" and severity == "okay":
            logit = True
            self.failures_debounce_counter += 1
            if self.failures_debounce_counter >= DEBOUNCE_FROM_ASSERT_THLD:
                rc = True

            # Special Case: Recovery from failure can be to okay or warning
            # so that ; say at failure and we get 2 okay's and a warning
            # we should allow that as a valid debounce from failure to warning.
            self.warnings_debounce_counter += 1

        # From Failure -> Warning Case
        elif current_severity_str == "failure" and severity == "warning":
            logit = True
            self.failures_debounce_counter += 1
            if self.failures_debounce_counter >= DEBOUNCE_FROM_ASSERT_THLD:
                rc = True

        # From Warning -> Okay Case
        elif current_severity_str == "warning" and severity == "okay":
            logit = True
            self.warnings_debounce_counter += 1
            if self.warnings_debounce_counter >= DEBOUNCE_FROM_ASSERT_THLD:
                rc = True

            # Special Case: Any previously thresholded failure count
            # should be cleared. Say we are at this warning level but
            # started debouncing a failure severity. Then before the
            # failure debounce completed we got an okay (this clause).
            # Then on the next audit get another failure event.
            # Without clearing the failure count on this okay we would
            # mistakenly qualify for a failure debounce by continuing
            # to count up the failures debounce count.
            self.failures_debounce_counter = 0

        # From Warning -> Failure Case
        elif current_severity_str == "warning" and severity == "failure":
            logit = True
            self.failures_debounce_counter += 1
            if self.failures_debounce_counter >= DEBOUNCE_FROM_ASSERT_THLD:
                rc = True

            # Special Case: While in warning severity and debouncing to okay
            # we get a failure reading then we need to clear the warning
            # debounce count. Otherwise the next okay would qualify the clear
            # which it should not because we got a failure while the warning
            # to okay debounce.
            self.warnings_debounce_counter = 0

        if logit is True:
            collectd.info("%s %s %s debounce '%s -> %s' (%2.2f) (%d:%d) %s" % (
                          PLUGIN,
                          base_obj.resource_name,
                          entity_id,
                          current_severity_str,
                          severity,
                          this_value,
                          self.warnings_debounce_counter,
                          self.failures_debounce_counter,
                          rc))

        if rc is True:
            # clear both debounce counters on every state change
            self.warnings_debounce_counter = 0
            self.failures_debounce_counter = 0

        return rc

    ########################################################################
    #
    # Name    : manage_alarm_lists
    #
    # Purpose : Alarm Severity Tracking
    #
    # This class member function accepts a severity level and entity id.
    # It manages the content of the current alarm object's 'failures' and
    # 'warnings' lists ; aka Severity Lists.
    #
    # These Severity Lists are used to record current alarmed state for
    # each instance of a plugin.
    # If an alarm is raised then its entity id is added to the appropriate
    # severity list.
    #
    # A failure notification or critical alarm goes in the failures list.
    # A warning notification or major alarm goes into the warnings list.
    #
    # These lists are used to avoid making unnecessary calls to FM.
    #
    # Startup Behavior:
    #
    # The collectd daemon runs the init function of every plugin on startup.
    # That includes this notifier plugin. The init function queries the FM
    # database for any active alarms.
    #
    # This member function is called for any active alarms that are found.
    # The entity id for active alarms is added to the appropriate
    # Severity List. This way existing alarms are maintained over collectd
    # process startup.
    #
    # Runtime Behavior:
    #
    # The current severity state is first queried and compared to the
    # newly reported severity level. If they are the same then a "done"
    # is returned telling the caller that there is no further work to do.
    # Otherwise, the lists are managed in a way that has the entity id
    # of a raised alarm in the corresponding severity list.
    #
    # See inline comments below for each specific severity and state
    # transition case.
    #
    #########################################################################

    def manage_alarm_lists(self, entity_id, severity):
        """Manage the alarm severity lists and report state change"""

        collectd.debug("%s manage alarm %s %s %s" %
                       (PLUGIN,
                        self.id,
                        severity,
                        entity_id))

        # Get the instance's current state
        if entity_id in self.warnings:
            current_severity_str = "warning"
        elif entity_id in self.failures:
            current_severity_str = "failure"
        else:
            current_severity_str = "okay"

        # Compare to current state to previous state.
        # If they are the same then return done.
        if severity == current_severity_str:
            return "done"

        # Otherwise, manage the severity lists ; case by case.
        warnings_list_change = False
        failures_list_change = False

        # Case 1: Handle warning to failure severity change.
        if severity == "warning" and current_severity_str == "failure":

            if entity_id in self.failures:
                self.failures.remove(entity_id)
                failures_list_change = True
                self._llog(entity_id + " is removed from failures list")
            else:
                self._elog(entity_id + " UNEXPECTEDLY not in failures list")

            # Error detection
            if entity_id in self.warnings:
                self.warnings.remove(entity_id)
                self._elog(entity_id + " UNEXPECTEDLY in warnings list")

            self.warnings.append(entity_id)
            warnings_list_change = True
            self._llog(entity_id + " is added to warnings list")

        # Case 2: Handle failure to warning alarm severity change.
        elif severity == "failure" and current_severity_str == "warning":

            if entity_id in self.warnings:
                self.warnings.remove(entity_id)
                warnings_list_change = True
                self._llog(entity_id + " is removed from warnings list")
            else:
                self._elog(entity_id + " UNEXPECTEDLY not in warnings list")

            # Error detection
            if entity_id in self.failures:
                self.failures.remove(entity_id)
                self._elog(entity_id + " UNEXPECTEDLY in failures list")

            self.failures.append(entity_id)
            failures_list_change = True
            self._llog(entity_id + " is added to failures list")

        # Case 3: Handle new alarm.
        elif severity != "okay" and current_severity_str == "okay":
            if severity == "warning":
                self.warnings.append(entity_id)
                warnings_list_change = True
                self._llog(entity_id + " added to warnings list")
            elif severity == "failure":
                self.failures.append(entity_id)
                failures_list_change = True
                self._llog(entity_id + " added to failures list")

        # Case 4: Handle alarm clear.
        else:
            # plugin is okay, ensure this plugin's entity id
            # is not in either list
            if entity_id in self.warnings:
                self.warnings.remove(entity_id)
                warnings_list_change = True
                self._llog(entity_id + " removed from warnings list")
            if entity_id in self.failures:
                self.failures.remove(entity_id)
                failures_list_change = True
                self._llog(entity_id + " removed from failures list")

        if warnings_list_change is True:
            if self.warnings:
                collectd.info("%s %s warnings %s" %
                              (PLUGIN, self.plugin, self.warnings))
            else:
                collectd.info("%s %s no warnings" %
                              (PLUGIN, self.plugin))

        if failures_list_change is True:
            if self.failures:
                collectd.info("%s %s failures %s" %
                              (PLUGIN, self.plugin, self.failures))
            else:
                collectd.info("%s %s no failures" %
                              (PLUGIN, self.plugin))

    ##########################################################################
    #
    # Name    : _get_instance_object
    #
    # Purpose : Safely get an object from the self instance object list
    #           indexed by eid.
    #
    ##########################################################################
    def _get_instance_object(self, eid):
        """Safely get an object from the self instance object dict while locked

        :param eid: the index for the instance object dictionary
        :return: object or None
        """
        if eid is None:
            return None

        try:
            collectd.debug("%s %s Get   Lock ..." % (PLUGIN, self.plugin))
            with fmAlarmObject.lock:
                obj = self.instance_objects[eid]
                return obj
        except:
            collectd.error("%s failed to get instance from %s object list" %
                           (PLUGIN, self.plugin))
            return None

    ##########################################################################
    #
    # Name    : _add_instance_object
    #
    # Purpose : Safely add an object to the self instance object list
    #           indexed by eid while locked. if found locked the instance
    #           add will be re-attempted on next sample.
    #
    ##########################################################################
    def _add_instance_object(self, obj, eid):
        """Update self instance_objects list while locked

        :param obj: the object to add
        :param eid: index for instance_objects
        :return: nothing
        """
        try:
            collectd.debug("%s %s Add   Lock ..." % (PLUGIN, self.plugin))
            with fmAlarmObject.lock:
                self.instance_objects[eid] = obj
        except:
            collectd.error("%s failed to add instance to %s object list" %
                           (PLUGIN, self.plugin))

    ##########################################################################
    #
    # Name    : _copy_instance_object
    #
    # Purpose : Copy select members of self object to target object.
    #
    ##########################################################################
    def _copy_instance_object(self, object):
        """Copy select members of self object to target object"""

        object.resource_name = self.resource_name
        object.reading_type = self.reading_type

        object.reason_warning = self.reason_warning
        object.reason_failure = self.reason_failure
        object.repair = self.repair

        object.alarm_type = self.alarm_type
        object.cause = self.cause
        object.suppression = self.suppression
        object.service_affecting = self.service_affecting

    ##########################################################################
    #
    # Name    : create_instance_object
    #
    # Purpose : Create a new instance object and tack it on the supplied base
    #           object's instance object dictionary.
    #
    ##########################################################################
    def create_instance_object(self, instance):

        try:
            # create a new plugin object
            inst_obj = fmAlarmObject(self.id, self.plugin)
            self._copy_instance_object(inst_obj)

            # initialize the object with instance specific data
            inst_obj.instance_name = instance
            inst_obj.degrade_id += '.' + self.plugin + '=' + instance
            inst_obj.entity_id = _build_entity_id(self.plugin, instance)
            self._add_instance_object(inst_obj, inst_obj.entity_id)

            collectd.debug("%s created %s instance (%s) object %s" %
                           (PLUGIN, inst_obj.resource_name,
                            inst_obj.entity_id, inst_obj))

            collectd.info("%s monitoring %s %s %s" %
                          (PLUGIN,
                           inst_obj.resource_name,
                           inst_obj.instance_name,
                           inst_obj.reading_type))

            return inst_obj

        except:
            collectd.error("%s %s:%s inst object create failed [exception]" %
                           (PLUGIN, inst_obj.resource_name, instance))
        return None

    ##########################################################################
    #
    # Name    : create_instance_objects
    #
    # Purpose : Create a list of instance objects for 'self' type plugin and
    #           add those objects to the parent's instance_objects dictionary.
    #
    # Note    : This is currently only used for the DF (filesystem) plugin.
    #           All other instance creations/allocations are done on-demand.
    #
    ##########################################################################
    def create_instance_objects(self):
        """Create, initialize and add an instance object to this/self plugin"""

        # Create the File System subordinate instance objects.
        if self.id == ALARM_ID__DF:

            # read the df.conf file and return/get a list of mount points
            conf_file = fmAlarmObject.plugin_path + 'df.conf'
            if not os.path.exists(conf_file):
                collectd.error("%s cannot create filesystem "
                               "instance objects ; missing : %s" %
                               (PLUGIN, conf_file))
                return FAIL

            mountpoints = []
            with open(conf_file, 'r') as infile:
                for line in infile:
                    if 'MountPoint ' in line:

                        # get the mountpoint path from the line
                        try:
                            mountpoint = line.split('MountPoint ')[1][1:-2]
                            mountpoints.append(mountpoint)
                        except:
                            collectd.error("%s skipping invalid '%s' "
                                           "mountpoint line: %s" %
                                           (PLUGIN, conf_file, line))

            collectd.debug("%s MountPoints: %s" % (PLUGIN, mountpoints))

            # loop over the mount points
            for mp in mountpoints:
                # create a new plugin object
                inst_obj = fmAlarmObject(ALARM_ID__DF, PLUGIN__DF)

                # initialize the object with instance specific data
                inst_obj.resource_name = self.resource_name
                self._copy_instance_object(inst_obj)
                inst_obj.instance_name = mp
                inst_obj.degrade_id += '.' + 'filesystem=' + mp

                for plugin_instance in DF_MANGLED_DICT:
                    if DF_MANGLED_DICT[plugin_instance] == mp:
                        inst_obj.plugin_instance = plugin_instance
                        break
                else:
                    collectd.debug("%s no %s mountpoint" %
                                   (PLUGIN, mp))
                    continue
                inst_obj.entity_id = _build_entity_id(PLUGIN__DF,
                                                      inst_obj.plugin_instance)

                # add this subordinate object to the parent's
                # instance object list
                self._add_instance_object(inst_obj, inst_obj.entity_id)
                inst_obj.instance = inst_obj.instance_name

                collectd.info("%s monitoring %s usage" %
                              (PLUGIN, inst_obj.instance))


# ADD_NEW_PLUGIN: add plugin to this table
# This instantiates the plugin objects
PLUGINS = {
    PLUGIN__CPU: fmAlarmObject(ALARM_ID__CPU, PLUGIN__CPU),
    PLUGIN__MEM: fmAlarmObject(ALARM_ID__MEM, PLUGIN__MEM),
    PLUGIN__DF: fmAlarmObject(ALARM_ID__DF, PLUGIN__DF),
    PLUGIN__VSWITCH_CPU: fmAlarmObject(ALARM_ID__VSWITCH_CPU,
                                       PLUGIN__VSWITCH_CPU),
    PLUGIN__VSWITCH_MEM: fmAlarmObject(ALARM_ID__VSWITCH_MEM,
                                       PLUGIN__VSWITCH_MEM),
    PLUGIN__VSWITCH_PORT: fmAlarmObject(ALARM_ID__VSWITCH_PORT,
                                        PLUGIN__VSWITCH_PORT),
    PLUGIN__VSWITCH_IFACE: fmAlarmObject(ALARM_ID__VSWITCH_IFACE,
                                         PLUGIN__VSWITCH_IFACE)}


#####################################################################
#
# Name       : clear_alarm
#
# Description: Clear the specified alarm with the specified entity ID.
#
# Returns    : True if operation succeeded
#              False if there was an error exception.
#
# Assumptions: Caller can decide to retry based on return status.
#
#####################################################################
def clear_alarm(alarm_id, eid):
    """Clear the specified alarm:eid"""

    try:
        if api.clear_fault(alarm_id, eid) is True:
            collectd.info("%s %s:%s alarm cleared" %
                          (PLUGIN, alarm_id, eid))
        else:
            collectd.info("%s %s:%s alarm already cleared" %
                          (PLUGIN, alarm_id, eid))
        return True

    except Exception as ex:
        collectd.error("%s 'clear_fault' exception ; %s:%s ; %s" %
                       (PLUGIN, alarm_id, eid, ex))
        return False


def get_base_object(alarm_id):
    """Get the alarm object for the specified alarm id"""
    for plugin in PLUGIN_NAME_LIST:
        if PLUGINS[plugin].id == alarm_id:
            return PLUGINS[plugin]
    return None


def get_object(alarm_id, eid):
    """Get the plugin object for the specified alarm id and eid"""

    base_obj = get_base_object(alarm_id)
    if len(base_obj.instance_objects):
        try:
            return(base_obj.instance_objects[eid])
        except:
            collectd.debug("%s %s has no instance objects" %
                           (PLUGIN, base_obj.plugin))
    return base_obj


def _build_entity_id(plugin, plugin_instance):
    """Builds an entity id string based on the collectd notification object"""

    inst_error = False

    entity_id = 'host='
    entity_id += fmAlarmObject.host

    if plugin == PLUGIN__MEM:
        if 'node' in plugin_instance:
            entity_id += '.numa=' + plugin_instance
        elif plugin_instance:
            entity_id += '.' + PLUGIN__MEM + '=' + plugin_instance

    elif plugin == PLUGIN__CPU:
        if plugin_instance:
            entity_id += '.' + PLUGIN__CPU + '=' + plugin_instance

    elif plugin == PLUGIN__VSWITCH_MEM:

        # host=<hostname>.processor=<socket-id>
        if plugin_instance:
            entity_id += '.processor=' + plugin_instance
        else:
            inst_error = True

    elif plugin == PLUGIN__VSWITCH_IFACE:

        # host=<hostname>.interface=<if-uuid>
        if plugin_instance:
            entity_id += '.interface=' + plugin_instance
        else:
            inst_error = True

    elif plugin == PLUGIN__VSWITCH_PORT:

        # host=<hostname>.port=<port-uuid>
        if plugin_instance:
            entity_id += '.port=' + plugin_instance
        else:
            inst_error = True

    elif plugin == PLUGIN__DF:

        # host=<hostname>.filesystem=<mountpoint>
        if plugin_instance:
            # build the entity_id for this plugin
            path = DF_MANGLED_DICT.get(plugin_instance)
            if path:
                entity_id += ".filesystem="
                entity_id += path
            else:
                inst_error = True

    if inst_error is True:
        collectd.error("%s eid build failed; bad or missing instance '%s'" %
                       (plugin, plugin_instance))
        return None

    return entity_id


def _get_df_mountpoints():

    conf_file = fmAlarmObject.plugin_path + 'df.conf'
    if not os.path.exists(conf_file):
        collectd.error("%s cannot create filesystem "
                       "instance objects ; missing : %s" %
                       (PLUGIN, conf_file))
        return FAIL

    mountpoints = []
    with open(conf_file, 'r') as infile:
        for line in infile:
            if 'MountPoint ' in line:

                # get the mountpoint path from the line
                try:
                    mountpoint = line.split('MountPoint ')[1][1:-2]
                    mountpoints.append(mountpoint)
                except:
                    collectd.error("%s skipping invalid '%s' "
                                   "mountpoint line: %s" %
                                   (PLUGIN, conf_file, line))

    return(mountpoints)


def _print_obj(obj):
    """Print a single object"""
    base_object = False
    for plugin in PLUGIN_NAME_LIST:
        if PLUGINS[plugin] == obj:
            base_object = True
            break

    num = len(obj.instance_objects)
    if num > 0 or base_object is True:
        prefix = "BASE " + str(num)
    else:
        prefix = "......."

    collectd.info("%s %s %s - %s - %s\n" %
                  (PLUGIN, prefix, obj.resource_name, obj.plugin, obj.id))
    collectd.info("%s %s  fault obj: %s\n" % (PLUGIN, prefix, obj.fault))
    collectd.info("%s %s  entity id: %s\n" % (PLUGIN, prefix, obj.entity_id))
    collectd.info("%s %s degrade_id: %s\n" % (PLUGIN, prefix, obj.degrade_id))

    collectd.info("%s %s instance  : %s\n" %
                  (PLUGIN, prefix, obj.instance_name))

    if obj.plugin_instance:
        collectd.info("%s %s Plugin Ins: %s\n" %
                      (PLUGIN, prefix, obj.plugin_instance))
    if obj.warnings:
        collectd.info("%s %s   warnings: %s" %
                      (PLUGIN, prefix, obj.warnings))
    if obj.failures:
        collectd.info("%s %s   failures: %s" %
                      (PLUGIN, prefix, obj.failures))
    if obj.repair:
        collectd.info("%s %s     repair: %s" % (PLUGIN, prefix, obj.repair))

    if obj.cause != fm_constants.ALARM_PROBABLE_CAUSE_50:
        collectd.info("%s %s  reason: w: %s\n" %
                      (PLUGIN, prefix, obj.reason_warning))
        collectd.info("%s %s  reason: f: %s\n" %
                      (PLUGIN, prefix, obj.reason_failure))

    collectd.info("%s %s value:%2.1f thld:%2.1f cause:%s count:%d type:%s\n" %
                  (PLUGIN, prefix,
                   obj.value,
                   obj.threshold,
                   obj.cause,
                   obj.count,
                   obj.reading_type))

    collectd.info("\n")


def _print_state(obj=None):
    """Print the current object state"""
    try:
        objs = []
        if obj is None:
            for plugin in PLUGIN_NAME_LIST:
                objs.append(PLUGINS[plugin])
        else:
            objs.append(obj)

        collectd.debug("%s _print_state Lock ..." % PLUGIN)
        with fmAlarmObject.lock:
            for o in objs:
                _print_obj(o)
                if len(o.instance_objects):
                    for inst_obj in o.instance_objects:
                        _print_obj(o.instance_objects[inst_obj])

    except Exception as ex:
        collectd.error("%s _print_state exception ; %s" %
                       (PLUGIN, ex))


def _database_setup(database):
    """Setup the influx database for collectd resource samples"""

    collectd.info("%s setting up influxdb:%s database" %
                  (PLUGIN, database))

    error_str = ""

    # http://influxdb-python.readthedocs.io/en/latest/examples.html
    # http://influxdb-python.readthedocs.io/en/latest/api-documentation.html
    fmAlarmObject.dbObj = InfluxDBClient('127.0.0.1', '8086', database)
    if fmAlarmObject.dbObj:
        try:
            fmAlarmObject.dbObj.create_database('collectd')

            ############################################################
            #
            # TODO: Read current retention period from service parameter
            #       Make it a puppet implementation.
            #
            # Create a '1 week' samples retention policy
            # -----------------------------------------
            # name     = 'collectd samples'
            # duration = set retention period in time
            #               xm - minutes
            #               xh - hours
            #               xd - days
            #               xw - weeks
            #               xy - years
            # database = 'collectd'
            # default  = True ; make it the default
            #
            ############################################################

            fmAlarmObject.dbObj.create_retention_policy(
                DATABASE_NAME, '1w', 1, database, True)
        except Exception as ex:
            if str(ex) == 'database already exists':
                try:
                    collectd.info("%s influxdb:collectd %s" %
                                  (PLUGIN, str(ex)))
                    fmAlarmObject.dbObj.create_retention_policy(
                        DATABASE_NAME, '1w', 1, database, True)
                except Exception as ex:
                    if str(ex) == 'retention policy already exists':
                        collectd.info("%s influxdb:collectd %s" %
                                      (PLUGIN, str(ex)))
                    else:
                        error_str = "failure from influxdb ; "
                        error_str += str(ex)
            else:
                error_str = "failed to create influxdb:" + database
    else:
        error_str = "failed to connect to influxdb:" + database

    if not error_str:
            found = False
            retention = \
                fmAlarmObject.dbObj.get_list_retention_policies(database)
            for r in range(len(retention)):
                if retention[r]["name"] == DATABASE_NAME:
                    collectd.info("%s influxdb:%s samples retention "
                                  "policy: %s" %
                                  (PLUGIN, database, retention[r]))
                    found = True
            if found is True:
                collectd.info("%s influxdb:%s is setup" % (PLUGIN, database))
                fmAlarmObject.database_setup = True
            else:
                collectd.error("%s influxdb:%s retention policy NOT setup" %
                               (PLUGIN, database))


def _clear_alarm_for_missing_filesystems():
    """Clear alarmed file systems that are no longer mounted or present"""

    # get the DF (filesystem plugin) base object.
    df_base_obj = PLUGINS[PLUGIN__DF]
    # create a single alarm list from both wranings and failures list
    # to avoid having to duplicate the code below for each.
    # At this point we don't care about severity, we just need to
    # determine if an any-severity' alarmed filesystem no longer exists
    # so we can cleanup by clearing its alarm.
    # Note: the 2 lists should always contain unique data between them
    alarm_list = df_base_obj.warnings + df_base_obj.failures
    if len(alarm_list):
        for eid in alarm_list:
            # search for any of them that might be alarmed.
            obj = df_base_obj._get_instance_object(eid)

            # only care about df (file system plugins)
            if obj is not None and \
               obj.plugin == PLUGIN__DF and \
               obj.entity_id == eid and \
               obj.instance_name != '':

                if os.path.ismount(obj.instance_name) is False:
                    if clear_alarm(df_base_obj.id, obj.entity_id) is True:
                        collectd.info("%s cleared alarm for missing %s" %
                                      (PLUGIN, obj.instance_name))
                        df_base_obj.manage_alarm_lists(obj.entity_id, "okay")
                else:
                    collectd.debug("%s maintaining alarm for %s" %
                                   (PLUGIN, obj.instance_name))


# Collectd calls this function on startup.
# Initialize each plugin object with plugin specific data.
# Query FM for existing alarms and run with that starting state.
def init_func():
    """Collectd FM Notifier Initialization Function"""

    mtcDegradeObj.port = MTCE_CMD_RX_PORT
    collectd.info("%s mtce port %d" %
                  (PLUGIN, mtcDegradeObj.port))

    fmAlarmObject.lock = Lock()

    fmAlarmObject.host = pluginObject.gethostname()
    collectd.info("%s %s:%s init function" %
                  (PLUGIN, tsc.nodetype, fmAlarmObject.host))

    # The path to where collectd is looking for its plugins is specified
    # at the end of the /etc/collectd.conf file.
    # Because so we search for the 'Include' label in reverse order.
    for line in reversed(open("/etc/collectd.conf", 'r').readlines()):
        if line.startswith('Include'):
            plugin_path = line.split(' ')[1].strip("\n").strip('"') + '/'
            fmAlarmObject.plugin_path = plugin_path
            collectd.info("plugin path: %s" % fmAlarmObject.plugin_path)
            break

    # Constant CPU Plugin Object Settings
    obj = PLUGINS[PLUGIN__CPU]
    obj.resource_name = "Platform CPU"
    obj.instance_name = PLUGIN__CPU
    obj.repair = "Monitor and if condition persists, "
    obj.repair += "contact next level of support."
    collectd.info("%s monitoring %s usage" % (PLUGIN, obj.resource_name))

    ###########################################################################

    # Constant Memory Plugin Object settings
    obj = PLUGINS[PLUGIN__MEM]
    obj.resource_name = "Memory"
    obj.instance_name = PLUGIN__MEM
    obj.repair = "Monitor and if condition persists, "
    obj.repair += "contact next level of support; "
    obj.repair += "may require additional memory on Host."
    collectd.info("%s monitoring %s usage" % (PLUGIN, obj.resource_name))

    ###########################################################################

    # Constant FileSystem Plugin Object settings
    obj = PLUGINS[PLUGIN__DF]
    obj.resource_name = "File System"
    obj.instance_name = PLUGIN__DF
    obj.repair = "Reduce usage or resize filesystem."

    # The FileSystem (DF) plugin has multiple instances
    # One instance per file system mount point being monitored.
    # Create one DF instance object per mount point
    obj.create_instance_objects()

    # ntp query is for controllers only
    if want_vswitch is False:
        collectd.debug("%s vSwitch monitoring disabled" % PLUGIN)
    elif tsc.nodetype == 'worker' or 'worker' in tsc.subfunctions:

        #######################################################################

        # Constant vSwitch CPU Usage Plugin Object settings
        obj = PLUGINS[PLUGIN__VSWITCH_CPU]
        obj.resource_name = "vSwitch CPU"
        obj.instance_name = PLUGIN__VSWITCH_CPU
        obj.repair = "Monitor and if condition persists, "
        obj.repair += "contact next level of support."
        collectd.info("%s monitoring %s usage" % (PLUGIN, obj.resource_name))

        #######################################################################

        # Constant vSwitch Memory Usage Plugin Object settings
        obj = PLUGINS[PLUGIN__VSWITCH_MEM]
        obj.resource_name = "vSwitch Memory"
        obj.instance_name = PLUGIN__VSWITCH_MEM
        obj.repair = "Monitor and if condition persists, "
        obj.repair += "contact next level of support."
        collectd.info("%s monitoring %s usage" % (PLUGIN, obj.resource_name))

        #######################################################################

        # Constant vSwitch Port State Monitor Plugin Object settings
        obj = PLUGINS[PLUGIN__VSWITCH_PORT]
        obj.resource_name = "vSwitch Port"
        obj.instance_name = PLUGIN__VSWITCH_PORT
        obj.reading_type = "state"
        obj.reason_failure = "'Data' Port failed."
        obj.reason_warning = "'Data' Port failed."
        obj.repair = "Check cabling and far-end port configuration and "
        obj.repair += "status on adjacent equipment."
        obj.alarm_type = fm_constants.FM_ALARM_TYPE_4     # EQUIPMENT
        obj.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # LOSS_OF_SIGNAL
        obj.service_affecting = True
        collectd.info("%s monitoring %s state" % (PLUGIN, obj.resource_name))

        #######################################################################

        # Constant vSwitch Interface State Monitor Plugin Object settings
        obj = PLUGINS[PLUGIN__VSWITCH_IFACE]
        obj.resource_name = "vSwitch Interface"
        obj.instance_name = PLUGIN__VSWITCH_IFACE
        obj.reading_type = "state"
        obj.reason_failure = "'Data' Interface failed."
        obj.reason_warning = "'Data' Interface degraded."
        obj.repair = "Check cabling and far-end port configuration and "
        obj.repair += "status on adjacent equipment."
        obj.alarm_type = fm_constants.FM_ALARM_TYPE_4     # EQUIPMENT
        obj.cause = fm_constants.ALARM_PROBABLE_CAUSE_29  # LOSS_OF_SIGNAL
        obj.service_affecting = True
        collectd.info("%s monitoring %s state" % (PLUGIN, obj.resource_name))

    ###########################################################################

    # ...
    # ADD_NEW_PLUGIN: Add new plugin object initialization here ...
    # ...

    if tsc.nodetype == 'controller':
        fmAlarmObject.database_setup_in_progress = True
        _database_setup('collectd')
        fmAlarmObject.database_setup_in_progress = False

    pluginObject.init_completed()
    return 0


# The notifier function inspects the collectd notification and determines if
# the representative alarm needs to be asserted, severity changed, or cleared.
def notifier_func(nObject):

    # do nothing till config is complete.
    if pluginObject._config_complete is False:
        if pluginObject.config_complete() is False:
            return 0

    if pluginObject._node_ready is False:
        collectd.info("%s %s not ready ; from:%s:%s:%s" %
                      (PLUGIN,
                       fmAlarmObject.host,
                       nObject.host,
                       nObject.plugin,
                       nObject.plugin_instance))
        pluginObject.node_ready()
        return 0

    if fmAlarmObject.fm_connectivity is False:
        # handle multi threading startup
        with fmAlarmObject.lock:
            if fmAlarmObject.fm_connectivity is True:
                return 0

            ##################################################################
            #
            # With plugin objects initialized ...
            # Query FM for any resource alarms that may already be raised
            # Load the queries severity state into the appropriate
            # severity list for those that are.
            for alarm_id in ALARM_ID_LIST:
                collectd.debug("%s searching for all '%s' alarms " %
                               (PLUGIN, alarm_id))
                try:
                    alarms = api.get_faults_by_id(alarm_id)
                except Exception as ex:
                    collectd.warning("%s 'get_faults_by_id' exception ; %s" %
                                     (PLUGIN, ex))

                    # if fm is not responding then the node is not ready
                    pluginObject._node_ready = False
                    pluginObject.node_ready_count = 0
                    return 0

                if alarms:
                    for alarm in alarms:
                        want_alarm_clear = False
                        eid = alarm.entity_instance_id
                        # ignore alarms not for this host
                        if fmAlarmObject.host not in eid:
                            continue

                        # get the instance part of the eid
                        #  instance based alarms are cleared over a process
                        #  restart to avoid the potential for stuck alarms.
                        base_eid = 'host=' + os.uname()[1]
                        if eid.split(base_eid)[1]:
                            want_alarm_clear = True

                        collectd.info('%s alarm %s:%s:%s found at startup' %
                                      (PLUGIN,
                                       alarm.severity,
                                       alarm_id,
                                       eid))

                        if want_alarm_clear is True:
                            if clear_alarm(alarm_id, eid) is False:
                                collectd.error("%s alarm %s:%s:%s clear "
                                               "failed" %
                                               (PLUGIN, alarm.severity,
                                                alarm_id,
                                                eid))
                            continue

                        if alarm.severity == "critical":
                            sev = "failure"
                        elif alarm.severity == "major":
                            sev = "warning"
                        else:
                            sev = "okay"
                            continue

                        # Load the alarm severity by plugin/instance lookup.
                        base_obj = get_base_object(alarm_id)
                        if base_obj is not None:
                            base_obj.manage_alarm_lists(eid, sev)

                            # the eid at this point is really the plugin id
                            pid = eid

                            # here the eid is used to represent the degrade id
                            eid = base_obj.degrade_id

                            # handle degrade for alarmed resources
                            # over process startup.
                            add = False
                            if alarm.severity == "critical" and\
                                    pid in mtcDegradeObj.degrade_list__failure:
                                add = True
                            elif alarm.severity == "major" and\
                                    pid in mtcDegradeObj.degrade_list__warning:
                                add = True
                            if add is True:

                                mtcDegradeObj.degrade_list.append(eid)
                                collectd.info("%s '%s' plugin added to "
                                              "degrade list due to found "
                                              "startup alarm %s" %
                                              (PLUGIN_DEGRADE, eid, alarm_id))

        fmAlarmObject.fm_connectivity = True
        collectd.info("%s node ready" % PLUGIN)

    collectd.debug('%s notification: %s %s:%s - %s %s %s [%s]' % (
        PLUGIN,
        nObject.host,
        nObject.plugin,
        nObject.plugin_instance,
        nObject.type,
        nObject.type_instance,
        nObject.severity,
        nObject.message))

    # Load up severity variables and alarm actions based on
    # this notification's severity level.
    if nObject.severity == NOTIF_OKAY:
        severity_str = "okay"
        _severity_num = fm_constants.FM_ALARM_SEVERITY_CLEAR
        _alarm_state = fm_constants.FM_ALARM_STATE_CLEAR
    elif nObject.severity == NOTIF_FAILURE:
        severity_str = "failure"
        _severity_num = fm_constants.FM_ALARM_SEVERITY_CRITICAL
        _alarm_state = fm_constants.FM_ALARM_STATE_SET
    elif nObject.severity == NOTIF_WARNING:
        severity_str = "warning"
        _severity_num = fm_constants.FM_ALARM_SEVERITY_MAJOR
        _alarm_state = fm_constants.FM_ALARM_STATE_SET
    else:
        collectd.debug('%s with unsupported severity %d' %
                       (PLUGIN, nObject.severity))
        return 0

    if tsc.nodetype == 'controller':
        if fmAlarmObject.database_setup is False:
            if fmAlarmObject.database_setup_in_progress is False:
                fmAlarmObject.database_setup_in_progress = True
                _database_setup('collectd')
                fmAlarmObject.database_setup_in_progress = False

    # get plugin object
    if nObject.plugin in PLUGINS:
        base_obj = obj = PLUGINS[nObject.plugin]

        # if this notification is for a plugin instance then get that
        # instances's object instead.
        # If that object does not yet exists then create it.
        eid = ''

        # DF instances are statically allocated
        if nObject.plugin == PLUGIN__DF:
            eid = _build_entity_id(nObject.plugin, nObject.plugin_instance)

            # get this instances object
            obj = base_obj._get_instance_object(eid)
            if obj is None:
                # path should never be hit since all DF instances
                # are statically allocated.
                return 0

        elif nObject.plugin_instance:
            need_instance_object_create = False
            # Build the entity_id from the parent object if needed
            eid = _build_entity_id(nObject.plugin, nObject.plugin_instance)
            try:
                # Need lock when reading/writing any obj.instance_objects list
                with fmAlarmObject.lock:

                    # we will take an exception if this object is not
                    # in the list. The exception handling code below will
                    # create and add this object for success path the next
                    # time around.
                    inst_obj = base_obj.instance_objects[eid]

                    collectd.debug("%s %s instance %s already exists %s" %
                                   (PLUGIN, nObject.plugin, eid, inst_obj))
                    # _print_state(inst_obj)

            except:
                need_instance_object_create = True

            if need_instance_object_create is True:
                base_obj.create_instance_object(nObject.plugin_instance)
                inst_obj = base_obj._get_instance_object(eid)
                if inst_obj:
                    inst_obj.instance_name = nObject.plugin_instance
                    collectd.debug("%s %s:%s inst object created" %
                                   (PLUGIN,
                                    inst_obj.plugin,
                                    inst_obj.instance_name))
                else:
                    collectd.error("%s %s:%s inst object create failed" %
                                   (PLUGIN,
                                    nObject.plugin,
                                    nObject.plugin_instance_name))
                    return 0

            # re-assign the object
            obj = inst_obj
        else:
            if not len(base_obj.entity_id):
                # Build the entity_id from the parent object if needed
                eid = _build_entity_id(nObject.plugin, nObject.plugin_instance)

        # update the object with the eid if its not already set.
        if not len(obj.entity_id):
            obj.entity_id = eid

    else:
        collectd.debug("%s notification for unknown plugin: %s %s" %
                       (PLUGIN, nObject.plugin, nObject.plugin_instance))
        return 0

    # if obj.warnings or obj.failures:
    #     _print_state(obj)

    # manage reading value change ; store last and log if gt obj.step
    action = obj.manage_change(nObject)
    if action == "done":
        return 0

    # Handle degrade state update early in process start.
    # Ensure that a degrade condition that clears over a collectd
    # collectd process restart is cleared as soon as possible.
    if obj.count == 0:
        mtcDegradeObj.mtce_degrade_notifier(nObject)

    # increment just before any possible return for a valid sample
    obj.count += 1

    # audit file system presence every time we get the
    # notification for the root file system ; which will
    # always be there.
    if obj.instance_name == '/':
        _clear_alarm_for_missing_filesystems()
        if len(mtcDegradeObj.degrade_list):
            mtcDegradeObj.remove_degrade_for_missing_filesystems()

        obj.alarm_audit_threshold += 1
        if obj.alarm_audit_threshold >= AUDIT_RATE:
            if want_state_audit:
                obj._state_audit("audit")
            obj.alarm_audit_threshold = 0

            #################################################################
            #
            # Audit Asserted Alarms
            #
            # Loop over the list of auditable alarm ids building two
            # dictionaries, one containing warning (major) and the other
            # failure (critical) with alarm info needed to detect and
            # correct stale, missing or severity mismatched alarms for
            # the listed alarm ids <100.xxx>.
            #
            # Note: Conversion in terminology from
            #         warning -> major and
            #         failures -> critical
            #       is done because fm speaks in terms of major and critical
            #       while the plugin speaks in terms of warning and failure.
            #
            major_alarm_dict = {}
            critical_alarm_dict = {}
            for alarm_id in AUDIT_ALARM_ID_LIST:

                tmp_base_obj = get_base_object(alarm_id)
                if tmp_base_obj is None:
                    collectd.error("%s audit %s base object lookup failed" %
                                   (PLUGIN, alarm_id))
                    continue

                # Build 2 dictionaries containing current alarmed info.
                # Dictionary entries are indexed by entity id to fetch the
                # alarm id and last fault object used to create the alarm
                # for the mismatch and missing case handling.
                #
                # { eid : { alarm : <alarm id>, fault : <fault obj> }}, ... }

                # major list for base object from warnings list
                if tmp_base_obj.entity_id in tmp_base_obj.warnings:
                    info = {}
                    info[pc.AUDIT_INFO_ALARM] = alarm_id
                    info[pc.AUDIT_INFO_FAULT] = tmp_base_obj.fault
                    major_alarm_dict[tmp_base_obj.entity_id] = info

                # major list for instance objects from warnings list
                for _inst_obj in tmp_base_obj.instance_objects:
                    inst_obj = tmp_base_obj.instance_objects[_inst_obj]
                    if inst_obj.entity_id in tmp_base_obj.warnings:
                        info = {}
                        info[pc.AUDIT_INFO_ALARM] = alarm_id
                        info[pc.AUDIT_INFO_FAULT] = inst_obj.fault
                        major_alarm_dict[inst_obj.entity_id] = info

                # critical list for base object from failures list
                if tmp_base_obj.entity_id in tmp_base_obj.failures:
                    info = {}
                    info[pc.AUDIT_INFO_ALARM] = alarm_id
                    info[pc.AUDIT_INFO_FAULT] = tmp_base_obj.fault
                    critical_alarm_dict[tmp_base_obj.entity_id] = info

                # critical list for instance objects from failures list
                for _inst_obj in tmp_base_obj.instance_objects:
                    inst_obj = tmp_base_obj.instance_objects[_inst_obj]
                    if inst_obj.entity_id in tmp_base_obj.failures:
                        info = {}
                        info[pc.AUDIT_INFO_ALARM] = alarm_id
                        info[pc.AUDIT_INFO_FAULT] = inst_obj.fault
                        critical_alarm_dict[inst_obj.entity_id] = info

            pluginObject.alarms_audit(api, AUDIT_ALARM_ID_LIST,
                                      major_alarm_dict,
                                      critical_alarm_dict)
            # end alarms audit
            #################################################################

    # exit early if there is no alarm update to be made
    if obj.debounce(base_obj,
                    obj.entity_id,
                    severity_str,
                    obj.value) is False:
        # Call the degrade notifier at steady state,
        #  degrade or clear, so that the required collectd
        #  degrade state is periodically refreshed.
        # However, rather than do this refresh on every notification,
        #  just do it for the root filesystem instance case.
        if obj.instance_name == '/':
            mtcDegradeObj.mtce_degrade_notifier(nObject)
        return 0

    mtcDegradeObj.manage_degrade_list(nObject)
    mtcDegradeObj.mtce_degrade_notifier(nObject)

    if _alarm_state == fm_constants.FM_ALARM_STATE_CLEAR:
        if clear_alarm(obj.id, obj.entity_id) is False:
            return 0
    else:

        # manage addition of the failure reason text
        if obj.cause == fm_constants.ALARM_PROBABLE_CAUSE_50:
            # if this is a threshold alarm then build the reason text that
            # includes the threshold and the reading that caused the assertion.
            reason = obj.resource_name
            reason += " threshold exceeded ;"
            if obj.threshold != INVALID_THRESHOLD:
                reason += " threshold {:2.2f}".format(obj.threshold) + "%,"
            if obj.value:
                reason += " actual {:2.2f}".format(obj.value) + "%"

        elif _severity_num == fm_constants.FM_ALARM_SEVERITY_CRITICAL:
            reason = obj.reason_failure

        else:
            reason = obj.reason_warning

        # build the alarm object
        obj.fault = fm_api.Fault(
            alarm_id=obj.id,
            alarm_state=_alarm_state,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=obj.entity_id,
            severity=_severity_num,
            reason_text=reason,
            alarm_type=base_obj.alarm_type,
            probable_cause=base_obj.cause,
            proposed_repair_action=base_obj.repair,
            service_affecting=base_obj.service_affecting,
            suppression=base_obj.suppression)

        try:
            alarm_uuid = api.set_fault(obj.fault)
            if pc.is_uuid_like(alarm_uuid) is False:
                collectd.error("%s 'set_fault' failed ; %s:%s ; %s" %
                               (PLUGIN,
                                base_obj.id,
                                obj.entity_id,
                                alarm_uuid))
                return 0

        except Exception as ex:
            collectd.error("%s 'set_fault' exception ; %s:%s:%s ; %s" %
                           (PLUGIN,
                            obj.id,
                            obj.entity_id,
                            _severity_num,
                            ex))
            return 0

    # update the lists now that
    base_obj.manage_alarm_lists(obj.entity_id, severity_str)

    collectd.info("%s %s alarm %s:%s %s:%s value:%2.2f" % (
                  PLUGIN,
                  _alarm_state,
                  base_obj.id,
                  severity_str,
                  obj.instance_name,
                  obj.entity_id,
                  obj.value))

    # Debug only: comment out for production code.
    # obj._state_audit("change")

    return 0


collectd.register_init(init_func)
collectd.register_notification(notifier_func)
