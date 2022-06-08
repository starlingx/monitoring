#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import collectd

import os
import six
import subprocess
import plugin_common as pc
from datetime import datetime

from fm_api import constants as fm_constants
from fm_api import fm_api


LSB_RETURN_WARNING = 160
LSB_RETURN_DEGRADE = 161

# Fault manager API Object
api = fm_api.FaultAPIsV2()

# name of the plugin - all logs produced by this plugin are prefixed with this
PLUGIN = 'service resource plugin'

# define a struct for monitoring individual service with service plugin
# and react (raise or clear alarm) with specified return code.
services = [
    {
        "service_name": "open-ldap",
        "service_type": "lsb",
        "service_plugin": "/etc/init.d/openldap",
        "service_plugin_cmdline": "/etc/init.d/openldap status > 2; echo -n $?",
        "service_plugin_env": {"SYSTEMCTL_SKIP_REDIRECT": "1"},
        "alarm": None,
        "current_status": 0,  # init status, actual status will be string
        "service_status": [
            {
                "status": "0",
                "alarm": None,
            },
            {
                "status": "160",
                "alarm": {
                    "severity": "major",
                    "id": "100.150",
                    "entity_id": "resource_type=file-descriptor.service_name=open-ldap",
                    "reason": "Number of open file descriptor is approaching to its limit",
                    "repair": "Consider to swact to the other controller if available",
                }
            },
            {
                "status": "161",
                "alarm": {
                    "severity": "critical",
                    "id": "100.150",
                    "entity_id": "resource_type=file-descriptor.service_name=open-ldap",
                    "reason": "Number of open file descriptor has reached its limit",
                    "repair": "Consider to swact to the other controller if available",
                }

            }
        ],
        "alarms_to_clear": [
            {
                "id": "100.150",
                "entity_id": "resource_type=file-descriptor.service_name=open-ldap"
            }
        ],
        "alarm_to_raise": None,
        "alarm_raised": None
    }
]


def clear_alarm(alarm):
    alarm_id = alarm["id"]
    eid = 'host=' + obj.hostname + "." + alarm["entity_id"]
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


def raise_alarm(service_name, alarm):
    """raise alarms"""

    alarm_id = alarm["id"]
    alarm_state = fm_constants.FM_ALARM_STATE_SET
    eid = 'host=' + obj.hostname + "." + alarm["entity_id"]
    severity = alarm["severity"]
    reason = alarm["reason"]
    repair = alarm["repair"]
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    fault = fm_api.Fault(
        uuid="",
        alarm_id=alarm_id,
        alarm_state=alarm_state,
        entity_type_id=fm_constants.FM_ENTITY_TYPE_SYSTEM,
        entity_instance_id=eid,
        severity=severity,
        reason_text=reason,
        alarm_type=fm_constants.FM_ALARM_TYPE_0,
        probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_42,
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


# Plugin Control Object
obj = pc.PluginObject(PLUGIN, "")


def init_func():
    """Init the plugin"""

    # do nothing till config is complete.
    if obj.config_complete() is False:
        return 0

    for service in services:
        if not os.path.exists(service["service_plugin"]):
            return 1

    obj.hostname = obj.gethostname()
    obj.init_completed()
    return 0


def check_service_status(service):
    cmd = service["service_plugin_cmdline"]
    env = service["service_plugin_env"]
    if six.PY2:
        # Centos
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env=env, shell=True)
    else:
        # Debian
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env=env, shell=True,
                                encoding='utf-8')
    proc.wait()
    new_status = (proc.communicate()[0] or "").strip()

    if service["current_status"] == new_status:
        return

    current_alarm = service["alarm_raised"]
    if current_alarm is not None:
        if current_alarm not in service["alarms_to_clear"]:
            service["alarms_to_clear"].append(current_alarm)

    for status in service["service_status"]:
        if status["status"] == new_status:
            alarm = status["alarm"]
            if alarm is not None and alarm != service["alarm_to_raise"]:
                service["alarm_to_raise"] = alarm
            break
    else:
        collectd.error("undefined service status %s[%s]" %
                       (service["service_name"], new_status))


def process_service_alarm(service):
    alarms_to_clear = service["alarms_to_clear"][:]
    for alarm in alarms_to_clear:
        if clear_alarm(alarm):
            service["alarms_to_clear"].remove(alarm)

    alarm = service["alarm_to_raise"]
    if alarm is not None:
        if raise_alarm(service["service_name"], alarm):
            alarm_raised = {"id": alarm["id"], "entity_id": alarm["entity_id"]}
            service["alarm_raised"] = alarm_raised
            service["alarm_to_raise"] = None


# The read function - called on every audit interval
def read_func():
    """collectd service resource monitor plugin read function"""

    if obj.init_complete is False:
        init_func()
        return 0

    if obj._node_ready is False:
        obj.node_ready()
        return 0

    for service in services:
        check_service_status(service)
        process_service_alarm(service)

collectd.register_init(init_func)
collectd.register_read(read_func)
