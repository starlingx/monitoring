############################################################################
# Copyright (c) 2018-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#############################################################################
#
# This is the NTP connectivity monitor plugin for collectd.
#
# This plugin uses the industry standard ntpq exec to query NTP attributes.
#
# This plugin executes 'ntpq -np' to determined which provisioned servers
# are reachable. The ntpq output includes Tally Code. The tally Code is
# represented by the first character in each server's line item.
#
# The only ntpq output looked at by this plugin are the Tally Codes and
# associated IPs.
#
# Tally Code Summary:
#
# A server is considered reachable only when the Tally Code is a * or a +.
# A server is considered unreachable if the Tally Code is a ' ' (space)
# A server with a '*' Tally Code is the 'selected' server.
#
# Here is an example of the ntpq command output. The IP address is displayed on
# its own line to support displaying long IPV6 addresses.
#
#      remote           refid     st t when poll reach   delay   offset  jitter
# =============================================================================
# +192.168.204.3
#                  149.56.27.12    3 u  315  512  376    0.160  -28.910   3.993
# +154.11.146.39
#                  172.21.138.4    2 u  197  512  377   54.249  -20.327   7.677
# +129.250.35.251
#                  249.224.99.213  2 u  429  512  377   16.921  -35.557   5.930
# *206.108.0.132
#                  .PTP0.          1 u  442  512  377    8.057  -36.061   6.171
#
#
# The local controller node is not to be considered a reachable server and is
# never alarmed if it is not reachable.
#
# Normal running modes with no alarms include
#
# 0 - All NTP servers are reachable and one is selected
# 1 - No NTP servers are provisioned
#
# Failure modes that warrant alarms include
#
# 2 - None of the NTP servers are reachable - major alarm
# 3 - Some NTP servers reachable and one is selected - server IP minor alarm
# 4 - Some NTP servers reachable but none is selected - major alarm
#
# None of these failures result in a host being degraded.
#
# This script will only be run on the controller nodes.
#
# This script logs to daemon.log with the 'collectd' process label
#
###############################################################################

import os
import subprocess
import uuid
import collectd
import six
from fm_api import constants as fm_constants
from fm_api import fm_api
import tsconfig.tsconfig as tsc

import plugin_common as pc

import socket

api = fm_api.FaultAPIsV2()

PLUGIN = 'NTP query plugin'
PLUGIN_INTERVAL = 300          # audit interval in secs
PLUGIN_CONF = '/etc/ntp.conf'
PLUGIN_EXEC = '/usr/sbin/ntpq'
PLUGIN_EXEC_DEBIAN = '/usr/bin/ntpq'
PLUGIN_EXEC_OPTIONS = '-pn'
PLUGIN_EXEC_OPTIONS_ASSOC = '-pnc'
PLUGIN_EXEC_OPTIONS_ASSOC_RV = 'rv &'
PLUGIN_ALARMID = "100.114"
NTPQ_SRCADR_PARAM = "srcadr"


# define a class here that will persist over read calls
class NtpqObject(pc.PluginObject):

    alarm_raised = False            # True when the major alarm is asserted

    server_list_conf = []           # list of servers in the /etc/ntp.conf file
    server_list_ntpq = []           # list of servers in the ntpq -np output
    unreachable_servers = []        # list of unreachable servers
    reachable_servers = []          # list of reachable servers
    selected_server = 'None'        # the ip address of the selected server
    selected_server_save = 'None'   # the last selected server ; note change
    peer_selected = False           # true when peer is selected

    # variables used to raise alarms to FM
    suppression = True
    service_affecting = False
    name = "NTP"
    alarm_type = fm_constants.FM_ALARM_TYPE_1
    cause = fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN
    repair = "Monitor and if condition persists, "
    repair += "contact next level of support."


# This plugin's class object - persists over read calls
obj = NtpqObject(PLUGIN, '')


###############################################################################
#
# Name       : _add_unreachable_server
#
# Description: This private interface is used to add an ip to the
#              unreachable servers list.
#
# Parameters : IP address
#
###############################################################################

def _add_unreachable_server(ip=None):
    """Add ip to unreachable_servers list"""

    if ip:
        if ip not in obj.unreachable_servers:
            collectd.debug("%s adding '%s' to unreachable servers list: %s" %
                           (PLUGIN, ip, obj.unreachable_servers))

            obj.unreachable_servers.append(ip)

            collectd.info("%s added '%s' to unreachable servers list: %s" %
                          (PLUGIN, ip, obj.unreachable_servers))
        else:
            collectd.debug("%s ip '%s' already in unreachable_servers list" %
                           (PLUGIN, ip))
    else:
        collectd.error("%s _add_unreachable_server called with no IP" % PLUGIN)


###############################################################################
#
# Name       : _raise_alarm
#
# Description: This private interface is used to raise NTP alarms.
#
# Parameters : Optional IP address
#
# If called with no or empty IP then a generic major alarm is raised.
# If called with an IP then an IP specific minor alarm is raised.
#
# Returns    : Error indication.
#
#              True : is error. FM call failed to set the
#                     alarm and needs to be retried.
#
#              False: no error. FM call succeeds
#
###############################################################################

def _raise_alarm(ip=None):
    """Assert an NTP alarm"""

    if not ip:
        # Don't re-raise the alarm if its already raised
        if obj.alarm_raised is True:
            return False

        reason = "NTP configuration does not contain any valid "
        reason += "or reachable NTP servers."
        fm_severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        eid = obj.base_eid

    else:
        reason = "NTP address "
        reason += ip
        reason += " is not a valid or a reachable NTP server."
        eid = obj.base_eid + '=' + ip
        fm_severity = fm_constants.FM_ALARM_SEVERITY_MINOR

    try:
        fault = fm_api.Fault(
            alarm_id=PLUGIN_ALARMID,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=eid,
            severity=fm_severity,
            reason_text=reason,
            alarm_type=obj.alarm_type,
            probable_cause=obj.cause,
            proposed_repair_action=obj.repair,
            service_affecting=obj.service_affecting,
            suppression=obj.suppression)

        alarm_uuid = api.set_fault(fault)
        if _is_uuid_like(alarm_uuid) is False:

            # Don't _add_unreachable_server list if the fm call failed.
            # That way it will be retried at a later time.
            collectd.error("%s 'set_fault' failed ; %s:%s ; %s" %
                           (PLUGIN, PLUGIN_ALARMID, eid, alarm_uuid))
            return True
        else:
            collectd.info("%s raised alarm %s:%s" %
                          (PLUGIN,
                           PLUGIN_ALARMID,
                           eid))
            if ip:
                _add_unreachable_server(ip)
            else:
                obj.alarm_raised = True

    except Exception as ex:
        collectd.error("%s 'set_fault' exception ; %s:%s:%s ; %s" %
                       (PLUGIN,
                        PLUGIN_ALARMID,
                        eid,
                        fm_severity,
                        ex))
    return True


###############################################################################
#
# Name       : _clear_base_alarm
#
# Description: This private interface is used to clear the NTP base alarm.
#
# Parameters : None
#
# Returns    : Error indication.
#
#              False: is error. FM call failed to clear the
#                     alarm and needs to be retried.
#
#              True : no error. FM call succeeds
#
###############################################################################

def _clear_base_alarm():
    """Clear the NTP base alarm"""

    try:
        if api.clear_fault(PLUGIN_ALARMID, obj.base_eid) is False:
            collectd.info("%s %s:%s alarm already cleared" %
                          (PLUGIN, PLUGIN_ALARMID, obj.base_eid))
        else:
            collectd.info("%s %s:%s alarm cleared" %
                          (PLUGIN, PLUGIN_ALARMID, obj.base_eid))
        obj.alarm_raised = False
        return True

    except Exception as ex:
        collectd.error("%s 'clear_fault' exception ; %s:%s ; %s" %
                       (PLUGIN,
                        PLUGIN_ALARMID,
                        obj.base_eid,
                        ex))
        return False


###############################################################################
#
# Name       : _remove_ip_from_unreachable_list
#
# Description: This private interface is used to remove the specified IP
#              from the unreachable servers list and clear its alarm if raised.
#
# Parameters : IP address
#
###############################################################################

def _remove_ip_from_unreachable_list(ip):
    """Remove IP address from the unreachable list and clear its NTP alarms"""

    # remove from unreachable list if its there
    if ip and ip in obj.unreachable_servers:

        eid = obj.base_eid + '=' + ip
        collectd.debug("%s trying to clear alarm %s" % (PLUGIN, eid))

        try:
            # clear the alarm if its asserted
            if api.clear_fault(PLUGIN_ALARMID, eid) is True:
                collectd.info("%s %s:%s alarm cleared " %
                              (PLUGIN, PLUGIN_ALARMID, eid))
            else:
                # alarm does not exist
                collectd.info("%s %s:%s alarm clear" %
                              (PLUGIN, PLUGIN_ALARMID, eid))

            obj.unreachable_servers.remove(ip)

        except Exception as ex:
            collectd.error("%s 'clear_fault' exception ; %s:%s ; %s" %
                           (PLUGIN,
                            PLUGIN_ALARMID,
                            eid,
                            ex))


###############################################################################
#
# Name       : _add_ip_to_ntpq_server_list
#
# Description: This private interface is used to create a list if servers
#              found in the ntpq output.
#
#              This list is used to detect and handle servers that might come
#              and go between readings that might otherwise result in stuck
#              alarms.
#
# Parameters : IP address
#
# Returns    : nothing
#
###############################################################################

def _add_ip_to_ntpq_server_list(ip):
    """Add this IP to the list of servers that ntpq reports against"""

    if ip not in obj.server_list_ntpq:
        obj.server_list_ntpq.append(ip)


##############################################################################
#
# Name       : _cleanup_stale_servers
#
# Description: This private interface walks through each server tracking list
#              removing any that it finds that are not in the ntpq server list.
#
#              Alarms are cleared as needed to avoid stale alarms
#
# Parameters : None
#
# Returns    : nothing
#
###############################################################################

def _cleanup_stale_servers():
    """Cleanup the server IP tracking lists"""

    collectd.debug("%s CLEANUP   REACHABLE: %s %s" %
                   (PLUGIN, obj.server_list_ntpq, obj.reachable_servers))
    for ip in obj.reachable_servers:
        if ip not in obj.server_list_ntpq:
            collectd.info("%s removing missing '%s' server from reachable "
                          "server list" % (PLUGIN, ip))
            obj.reachable_servers.remove(ip)

    collectd.debug("%s CLEANUP UNREACHABLE: %s %s" %
                   (PLUGIN, obj.server_list_ntpq, obj.unreachable_servers))
    for ip in obj.unreachable_servers:
        if ip not in obj.server_list_ntpq:
            collectd.info("%s removing missing '%s' server from unreachable "
                          "server list" % (PLUGIN, ip))
            _remove_ip_from_unreachable_list(ip)


###############################################################################
#
# Name       : _get_ntp_servers
#
# Description: This private interface reads the list of ntp servers from the
#              ntp.conf file
#
# Parameters : None
#
# Returns    : nothing
#
# Updates    : server_list_conf
#
###############################################################################

def _get_ntp_servers():
    """Read the provisioned servers from the ntp conf file"""

    with open(PLUGIN_CONF, 'r') as infile:
        for line in infile:
            if line.startswith('server '):
                ip = line.rstrip().split(' ')[1]
                if ip not in obj.server_list_conf:
                    obj.server_list_conf.append(ip)
        if len(obj.server_list_conf):
            collectd.info("%s server list: %s" %
                          (PLUGIN, obj.server_list_conf))
        else:
            ##################################################################
            #
            # Handle NTP_NOT_PROVISIONED (1) case
            #
            # There is no alarming for this case.
            # Clear any that may have been raised.
            #
            ##################################################################
            collectd.info("%s NTP Service Disabled ; no provisioned servers" %
                          PLUGIN)

            # clear all alarms
            if obj.alarm_raised:
                _clear_base_alarm()

            if obj.unreachable_servers:
                for ip in obj.unreachable_servers:
                    _remove_ip_from_unreachable_list(ip)


###############################################################################
#
# Name       : is_controller
#
# Description: This private interface returns a True if the specified ip is
#              associated with a local controller.
#
# Parameters : IP address
#
# Returns    : True or False
#
###############################################################################

def _is_controller(ip):
    """Returns True if this IP corresponds to one of the controllers"""

    collectd.debug("%s check if '%s' is a controller ip" % (PLUGIN, ip))
    with open('/etc/hosts', 'r') as infile:
        for line in infile:
            # skip over file comment lines prefixed with '#'
            if line[0] == '#':
                continue
            # line format is 'ip' 'name' ....
            split_line = line.split()
            if len(split_line) >= 2:
                # look for exact match ip that contains controller in its name
                if split_line[0] == ip and 'controller' in line:
                    collectd.debug("%s %s is a controller" % (PLUGIN, ip))
                    return True
    return False


###############################################################################
#
# Name       : _is_ip_address
#
# Description: This private interface returns:
#               AF_INET if val is ipv4
#               AF_INET6 if val is ipv6
#               False if val is not a valid ip address
#
# Parameters : val is a uuid string
#
# Returns    : socket.AF_INET for ipv4, socket.AF_INET6 for ipv6
#              or False for invalid
#
###############################################################################

def _is_ip_address(val):
    try:
        socket.inet_pton(socket.AF_INET, val)
        return socket.AF_INET
    except socket.error:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, val)
        return socket.AF_INET6
    except socket.error:
        pass

    return False


###############################################################################
#
# Name       : is_uuid_like
#
# Description: This private interface returns a True if the specified value is
#              a valid uuid.
#
# Parameters : val is a uuid string
#
# Returns    : True or False
#
###############################################################################

def _is_uuid_like(val):
    """Returns validation of a value as a UUID"""
    try:
        return str(uuid.UUID(val)) == val
    except (TypeError, ValueError, AttributeError):
        return False


###############################################################################
#
# Name       : config_func
#
# Description: The configuration interface this plugin publishes to collectd.
#
#              collectd calls this interface one time on its process startup
#              when it loads this plugin.
#
#              There is currently no specific configuration options to parse
#              for this plugin.
#
# Parameters : collectd config object
#
# Returns    : zero
#
###############################################################################

def config_func(config):
    """Configure the plugin"""

    collectd.debug('%s config function' % PLUGIN)
    return 0


###############################################################################
#
# Name       : init_func
#
# Description: The initialization interface this plugin publishes to collectd.
#
#              collectd calls this interface one time on its process startup
#              when it loads this plugin.
#
#              1. get hostname
#              2. build base entity id for the NTP alarm
#              3. query FM for existing NTP alarms
#                 - base alarm is maintained and state loaded if it exists
#                 - ntp ip minor alalrms are cleared on init. This is done to
#                   auto correct ntp server IP address changes over process
#                   restart ; avoid stuck alarms.
#
# Parameters : None
#
# Returns    : zero
#
###############################################################################

def init_func():

    # ntp query is for controllers only
    if tsc.nodetype != 'controller':
        return 0

    # do nothing till config is complete.
    if obj.config_complete() is False:
        return 0

    if obj._node_ready is False:
        obj.node_ready()
        return 0

    # get current hostname
    obj.hostname = obj.gethostname()
    if not obj.hostname:
        collectd.error("%s failed to get hostname" % PLUGIN)
        return 1

    obj.base_eid = 'host=' + obj.hostname + '.ntp'
    collectd.debug("%s on %s with entity id '%s'" %
                   (PLUGIN, obj.hostname, obj.base_eid))

    # get a list of provisioned ntp servers
    _get_ntp_servers()

    # manage existing alarms.
    try:
        alarms = api.get_faults_by_id(PLUGIN_ALARMID)

    except Exception as ex:
        collectd.error("%s 'get_faults_by_id' exception ; %s ; %s" %
                       (PLUGIN, PLUGIN_ALARMID, ex))
        return 0

    if alarms:
        for alarm in alarms:
            eid = alarm.entity_instance_id
            # ignore alarms not for this host
            if obj.hostname not in eid:
                continue

            # maintain only the base alarm.
            if alarm.entity_instance_id != obj.base_eid:
                # clear any ntp server specific alarms over process restart
                # this is done to avoid the potential for stuck ntp ip alarms
                collectd.info("%s clearing found startup alarm '%s'" %
                              (PLUGIN, alarm.entity_instance_id))
                try:
                    api.clear_fault(PLUGIN_ALARMID, alarm.entity_instance_id)
                except Exception as ex:
                    collectd.error("%s 'clear_fault' exception ; %s:%s ; %s" %
                                   (PLUGIN,
                                    PLUGIN_ALARMID,
                                    alarm.entity_instance_id,
                                    ex))
                    return 0

            else:
                obj.alarm_raised = True
                collectd.info("%s found alarm %s:%s" %
                              (PLUGIN,
                               PLUGIN_ALARMID,
                               alarm.entity_instance_id))

                # ensure the base alarm is cleared if there are no
                # provisioned servers.
                if not obj.server_list_conf:
                    _clear_base_alarm()

    else:
        collectd.info("%s no major startup alarms found" % PLUGIN)

    obj.init_completed()
    return 0


###############################################################################
#
# Name       : _get_one_line_data
#
# Description: Original ntpq response possibly have 2 lines data for 1 record.
#              This function concatinate 2 lines into 1 line
#
# Example:
#
#     remote           refid      st t when poll reach   delay   offset  jitter
#==============================================================================
# 192.168.204.3
#                 127.0.0.1       12 u    3   64  373    0.003    2.711   0.847
#+162.159.200.1
#                 10.44.9.236      3 u   25   64  377   29.304   -1.645  11.298
#*162.159.200.123
#                 10.44.9.236      3 u   24   64  377   27.504   -0.865   9.443
#
# To
#     remote           refid      st t when poll reach   delay   offset  jitter
#==============================================================================
# 192.168.204.3   127.0.0.1       12 u    3   64  373    0.003    2.711   0.847
#+162.159.200.1   10.44.9.236      3 u   25   64  377   29.304   -1.645  11.298
#*162.159.200.123 10.44.9.236      3 u   24   64  377   27.504   -0.865   9.443
# (space before column refid would be more)
#
# Parameters : Original ntpq response
#
# Returns    : One lines ntpq response
#
###############################################################################
def _get_one_line_data(ntpq_lines):
    header = ntpq_lines[0].split()
    header_col_num = len(header)
    list_oneline = list(ntpq_lines[:2])

    line_skip = False
    for i in range(2, len(ntpq_lines)):
        if len(ntpq_lines[i]) > 0:
            if line_skip is False:
                one_line = ntpq_lines[i]
                cols_num = len(ntpq_lines[i].split())
                if cols_num != header_col_num and len(ntpq_lines) >= (i + 1):
                    next_cols_num = len(ntpq_lines[i + 1].split())
                    if header_col_num == (cols_num + next_cols_num):
                        one_line += ntpq_lines[i + 1]
                        line_skip = True
                list_oneline.append(one_line)
            else:
                line_skip = False
    return list_oneline


###############################################################################
#
# Name       : _get_assoc_srcadr
#
# Description: Retrieves the IP value from association.
# This function is useful for IPv6 cases, where the output of the ntp -np
# command shows it truncated, so when the alarm is triggered it also shows
# truncated.
# Through this function it will be possible to obtain the IPv6 without
# truncating, because the value is taken from srcadr param of association data.
#
# Example:
#
#     remote           refid      st t when poll reach   delay   offset  jitter
#==============================================================================
# 64:ff9b::7819:9 .XFAC.          16 u    - 1024    0    0.000   +0.000   0.000
#*fd01:11::3      94.52.184.17     2 s  846 1024  376    0.114   -1.600   1.610
#
# IPv6 64:ff9b::7819:9 is truncated. The function looks for the srcadr
# parameter to return the full IPv6 (64:ff9b::7819:9afd)
#
#     remote           refid      st t when poll reach   delay   offset  jitter
#==============================================================================
# 64:ff9b::7819:9 .XFAC.          16 u    - 1024    0    0.000   +0.000   0.000
#*fd01:11::3      94.52.184.17     2 s  899 1024  376    0.114   -1.600   1.610
#
#associd=2703 status=8011 conf, sel_reject, 1 event, mobilize,
#srcadr=64:ff9b::7819:9afd, srcport=123, dstadr=2620:10a:a001:a103::1065,
#dstport=123, leap=11, stratum=16, precision=-24, rootdelay=0.000,
#rootdisp=0.000, refid=XFAC, reftime=(no time), rec=(no time), reach=000,
#unreach=73, hmode=3, pmode=0, hpoll=10, ppoll=10, headway=0,
#flash=1600 peer_stratum, peer_dist, peer_unreach, keyid=0, offset=+0.000,
#delay=0.000, dispersion=15937.500, jitter=0.000, xleave=0.046,
#filtdelay=     0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00,
#filtoffset=   +0.00   +0.00   +0.00   +0.00   +0.00   +0.00   +0.00   +0.00,
#filtdisp=   16000.0 16000.0 16000.0 16000.0 16000.0 16000.0 16000.0 16000.0
#
# Parameters : index of association, current truncated ip value
#
# Returns    : if input IP value is a IPv4 format, returns same IPv4
#              if input IP value is a IPv6 format, returns full IPv6 value
#
###############################################################################

def _get_assoc_srcadr(assoc_id, ip):

    srcadr = ''

    # IPv4 no further processing required, returns same IP value
    if assoc_id < 1 or socket.AF_INET == _is_ip_address(ip):
        return ip

    # Do NTP Query to retrieve assoc information
    ntpq_assoc_param = PLUGIN_EXEC_OPTIONS_ASSOC_RV + str(assoc_id)
    if six.PY2:
        # Centos
        data = subprocess.check_output([PLUGIN_EXEC, PLUGIN_EXEC_OPTIONS_ASSOC, ntpq_assoc_param])
    else:
        # Debian
        data = subprocess.check_output([PLUGIN_EXEC_DEBIAN, PLUGIN_EXEC_OPTIONS_ASSOC, ntpq_assoc_param],
                                       encoding='utf-8')

    if not data:
        return srcadr

    ntpq = _get_one_line_data(data.split('\n'))

    #Iterate through the association information to filter the srcadr.
    for i in range(2, len(ntpq)):
        if NTPQ_SRCADR_PARAM in ntpq[i] and ip in ntpq[i]:
            src_ip_port = ntpq[i].split(",")
            for param in src_ip_port:
                if NTPQ_SRCADR_PARAM in param:
                    srcadr = param.split("=")[1]
                    break
            break

    return srcadr


###############################################################################
#
# Name       : read_func
#
# Description: The sample read interface this plugin publishes to collectd.
#
#              collectd calls this interface every audit interval.
#
#              Runs ntpq -np to query NTP status and manages alarms based on
#              the result.
#
#              See file header (above) for more specific behavioral detail.
#
#              Should only run on a controller ; both
#
# Parameters : None
#
# Returns    : zero or non-zero on significant error
#
###############################################################################

def read_func():

    # ntp query is for controllers only
    if tsc.nodetype != 'controller':
        return 0

    if obj.init_complete is False:
        init_func()
        return 0

    # get a list if provisioned ntp servers
    _get_ntp_servers()

    # nothing to do while there are no provisioned NTP servers
    if len(obj.server_list_conf) == 0:
        return 0

    # Do NTP Query
    if six.PY2:
        # Centos
        data = subprocess.check_output([PLUGIN_EXEC, PLUGIN_EXEC_OPTIONS])
    else:
        # Debian
        data = subprocess.check_output([PLUGIN_EXEC_DEBIAN, PLUGIN_EXEC_OPTIONS], encoding='utf-8')

    # Keep this FIT test code but make it commented out for security
    #
    # if os.path.exists('/var/run/fit/ntpq_data'):
    #    data = ''
    #    collectd.info("%s using ntpq FIT data" % PLUGIN)
    #    with open('/var/run/fit/ntpq_data', 'r') as infile:
    #        for line in infile:
    #            data += line

    if not data:
        collectd.error("%s no data from query" % PLUGIN)
        return 0

    # Get the ntp query output into a list of lines
    obj.ntpq = _get_one_line_data(data.split('\n'))

    # keep track of changes ; only log on changes
    reachable_list_changed = False
    unreachable_list_changed = False

    # Manage the selected server name
    #
    # save the old value so we can print a log if the selected server changes
    if obj.selected_server:
        obj.selected_server_save = obj.selected_server
    # always assume no selected server ; till its learned
    obj.selected_server = ''

    # start with a fresh empty list for this new run to populate
    obj.server_list_ntpq = []

    # Loop through the ntpq output.
    # Ignore the first 2 lines ; just header data.
    for i in range(2, len(obj.ntpq)):

        # Ignore empty or lines that are not long enough. IPV4 IP Address is at
        # least 7 characters long, IPV6 2. Adding 1 character for the
        # availability flag.
        if len(obj.ntpq[i]) < 3:
            continue

        # log the ntpq output ; minus the 2 lines of header
        collectd.info("NTPQ: %s" % obj.ntpq[i])

        # Unreachable servers are ones whose line start with a space
        ip = ''
        if obj.ntpq[i][0] == ' ':
            # get the ip address
            # example format of line:['', '132.163.4.102', '', '', '.INIT.',
            # get ip from index [1] of the list
            unreachable = obj.ntpq[i].split(' ')[1]
            # find the ip and adjust the index of assoc information
            unreachable = _get_assoc_srcadr(i - 1, unreachable)
            if unreachable:
                # check to see if its a controller ip
                # we skip over controller ips
                if _is_controller(unreachable) is False:
                    _add_ip_to_ntpq_server_list(unreachable)
                    if unreachable not in obj.unreachable_servers:
                        if _raise_alarm(unreachable) is False:
                            unreachable_list_changed = True
                            # if the FM call to raise the alarm worked then
                            # add this ip to the unreachable list if its not
                            # already in it
                            _add_unreachable_server(unreachable)

        # Reachable servers are ones whose line start with a '+'
        elif obj.ntpq[i][0] == '+':
            # remove the '+' and get the ip
            ip = obj.ntpq[i].split(' ')[0][1:]
            ip = _get_assoc_srcadr(i - 1, ip)

        elif obj.ntpq[i][0] == '*':
            # remove the '*' and get the ip
            cols = obj.ntpq[i].split(' ')
            ip = cols[0][1:]
            ip = _get_assoc_srcadr(i - 1, ip)
            if ip:
                ip_family = _is_ip_address(ip)
                obj.peer_selected = _is_controller(ip)
                if ip != obj.selected_server and obj.alarm_raised is True:
                    # a new ntp server is selected, old alarm may not be
                    # valid
                    _clear_base_alarm()
                if obj.peer_selected is False:
                    if obj.selected_server:
                        # done update the selected server if more selections
                        # are found. go with the first one found.
                        collectd.info("%s additional selected server found"
                                      " '%s'; current selection is '%s'" %
                                      (PLUGIN, ip, obj.selected_server))
                    else:
                        # update the selected server list
                        obj.selected_server = ip
                        collectd.debug("%s selected server is '%s'" %
                                       (PLUGIN, obj.selected_server))
                else:
                    collectd.info("%s selected server is peer" % PLUGIN)
                    # refer to peer
                    refid = ''
                    for i in range(1, len(cols)):
                        if cols[i] != '':
                            refid = cols[i]
                            break

                    if refid not in ('', '127.0.0.1') and \
                            not _is_controller(refid) and \
                            socket.AF_INET == _is_ip_address(refid):
                        # ipv4, peer controller refer to a time source is not
                        # itself or a controller (this node)
                        obj.selected_server = ip
                        collectd.info("%s peer controller has a reliable "
                                      "source: %s" % (PLUGIN, refid))

        # anything else is unreachable
        else:
            unreachable = obj.ntpq[i][1:].split(' ')[0]
            # find the ip and adjust the index of assoc information
            unreachable = _get_assoc_srcadr(i - 1, unreachable)
            if _is_controller(unreachable) is False:
                _add_ip_to_ntpq_server_list(unreachable)
                if unreachable not in obj.unreachable_servers:
                    if _raise_alarm(unreachable) is False:
                        unreachable_list_changed = True
                        # if the FM call to raise the alarm worked then
                        # add this ip to the unreachable list if its not
                        # already in it
                        _add_unreachable_server(unreachable)

        if ip:
            # if the ip is valid then manage it
            if _is_controller(ip) is False:
                _add_ip_to_ntpq_server_list(ip)
                # add the ip to the reachable servers list
                # if its not already there
                if ip not in obj.reachable_servers:
                    obj.reachable_servers.append(ip)
                    reachable_list_changed = True
                # make sure this IP is no longer in the unreachable
                # list and that alarms for it are cleared
                _remove_ip_from_unreachable_list(ip)

    _cleanup_stale_servers()

    if obj.selected_server:
        if obj.selected_server != obj.selected_server_save:
            collectd.info("%s selected server changed from '%s' to '%s'" %
                          (PLUGIN,
                           obj.selected_server_save,
                           obj.selected_server))
        obj.selected_server_save = obj.selected_server
        if obj.alarm_raised is True:
            _clear_base_alarm()

    elif obj.alarm_raised is False:
        if obj.peer_selected:
            collectd.info("%s peer is selected" % PLUGIN)
        else:
            collectd.error("%s no selected server" % PLUGIN)
        if _raise_alarm() is False:
            obj.selected_server_save = 'None'

    # only log and act on changes
    if reachable_list_changed is True:
        if obj.reachable_servers:
            collectd.info("%s reachable servers: %s" %
                          (PLUGIN, obj.reachable_servers))
            if obj.alarm_raised is True:
                if obj.selected_server and obj.reachable_servers:
                    _clear_base_alarm()
        else:
            collectd.error("%s no reachable servers" % PLUGIN)
            _raise_alarm()

    # only log changes
    if unreachable_list_changed is True:
        if obj.unreachable_servers:
            collectd.info("%s unreachable servers: %s" %
                          (PLUGIN, obj.unreachable_servers))
        else:
            collectd.info("%s all servers are reachable" % PLUGIN)

    # The sample published to the database is simply the number
    # of reachable servers if one is selected
    if not obj.selected_server:
        sample = 0
    else:
        sample = len(obj.reachable_servers)

    # Dispatch usage value to collectd
    val = collectd.Values(host=obj.hostname)
    val.plugin = 'ntpq'
    val.type = 'absolute'
    val.type_instance = 'reachable'
    val.dispatch(values=[sample])

    return 0


# register the config, init and read functions
collectd.register_config(config_func)
collectd.register_init(init_func)
collectd.register_read(read_func, interval=PLUGIN_INTERVAL)
