#
# Copyright (c) 2019-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
############################################################################
#
# This file contains common collectd plugin constructs and utilities
#
############################################################################

import collectd
import itertools as it
import json
import uuid
import httplib2
import six
import socket
import subprocess
import time
import os
from oslo_concurrency import processutils
from fm_api import constants as fm_constants
import tsconfig.tsconfig as tsc

from kubernetes import __version__ as K8S_MODULE_VERSION
from kubernetes import client
from kubernetes import config
from kubernetes.client import Configuration
import urllib3


# http request constants
PLUGIN_TIMEOUT = 10
PLUGIN_HTTP_HEADERS = {'Accept': 'application/json', 'Connection': 'close'}

MIN_AUDITS_B4_FIRST_QUERY = 2

# Kubernetes client constants
K8S_MODULE_MAJOR_VERSION = int(K8S_MODULE_VERSION.split('.')[0])
KUBELET_CONF = '/etc/kubernetes/kubelet.conf'
SSL_TLS_SUPPRESS = True

# Standard units' conversion parameters (mebi, kibi)
# Reference: https://en.wikipedia.org/wiki/Binary_prefix
Mi = 1048576
Ki = 1024

# Standard units conversion
ONE_MILLION = 1000000
ONE_THOUSAND = 1000
ONE_HUNDRED = 100

# cgroup definitions
CGROUP_ROOT = '/sys/fs/cgroup'
K8S_ROOT = 'k8s-infra'
KUBEPODS = 'kubepods'

# High level grouping categories
GROUP_OVERALL = 'overall'
GROUP_FIRST = 'first'
GROUP_PODS = 'pods'

# Overall cpuacct groupings
GROUP_TOTAL = 'cgroup-total'
GROUP_PLATFORM = 'platform'
GROUP_BASE = 'base'
GROUP_K8S_SYSTEM = 'kube-system'
GROUP_K8S_ADDON = 'kube-addon'
GROUP_CONTAINERS = 'containers'
GROUP_OVERHEAD = 'overhead'

# Overall memory goupings
GROUP_PROCESSES = 'cgroup-processes'

# Groups included in platform - this excludes apps
PLATFORM_GROUPS = [GROUP_OVERHEAD, GROUP_BASE, GROUP_K8S_SYSTEM]
OVERALL_GROUPS = [GROUP_PLATFORM, GROUP_K8S_ADDON, GROUP_CONTAINERS]
OVERALL_GROUPS.extend(PLATFORM_GROUPS)

# Groups with cpuacct aggregated from multiple groups
GROUPS_AGGREGATED = [GROUP_PLATFORM, GROUP_BASE, GROUP_K8S_SYSTEM,
                     GROUP_K8S_ADDON, GROUP_CONTAINERS]

# First level cgroups -- these are the groups we know about
CGROUP_SYSTEM = 'system.slice'
CGROUP_USER = 'user.slice'
CGROUP_MACHINE = 'machine.slice'
CGROUP_DOCKER = 'docker'
CGROUP_K8S = K8S_ROOT

# Second level cgroups of system.slice for containerization
CGROUP_SYSTEM_CONTAINERD = 'containerd.service'
CGROUP_SYSTEM_DOCKER = 'docker.service'
CGROUP_SYSTEM_KUBELET = 'kubelet.service'
CGROUP_SYSTEM_ETCD = 'etcd.service'
CONTAINERS_CGROUPS = [CGROUP_SYSTEM_CONTAINERD, CGROUP_SYSTEM_DOCKER,
                      CGROUP_SYSTEM_KUBELET, CGROUP_SYSTEM_ETCD]

# Groupings by first level cgroup
BASE_GROUPS = [CGROUP_DOCKER, CGROUP_SYSTEM, CGROUP_USER]
BASE_GROUPS_EXCLUDE = [CGROUP_K8S, CGROUP_MACHINE]

# Groupings of pods by kubernetes namespace
K8S_NAMESPACE_SYSTEM = ['kube-system', 'armada', 'cert-manager', 'portieris',
                        'vault', 'notification', 'platform-deployment-manager',
                        'flux-helm', 'metrics-server', 'node-feature-discovery',
                        'intel-power', 'power-metrics', 'sriov-fec-system']
K8S_NAMESPACE_ADDON = ['monitor', 'openstack']
PLATFORM_LABEL_KEY = "app.starlingx.io/component"

# Pod parent cgroup name based on annotation.
# e.g., used by: kube-controller-manager, kube-scheduler, kube-apiserver
POD_ANNOTATION_KEY = 'kubernetes.io/config.hash'

# Worker reserved file and keyname
RESERVED_CONF = '/etc/platform/worker_reserved.conf'
RESERVED_MEM_KEY = 'WORKER_BASE_RESERVED'
RESERVED_CPULIST_KEY = 'PLATFORM_CPU_LIST'

# plugin return values
PLUGIN_PASS = 0
PLUGIN_FAIL = 1

AUDIT_INFO_ALARM = 'alarm'
AUDIT_INFO_FAULT = 'fault'


class PluginObject(object):

    def __init__(self, plugin, url=""):

        # static variables set in init_func
        self.plugin = plugin             # the name of this plugin
        self.hostname = ''               # the name of this host
        self.port = 0                    # the port number for this plugin
        self.base_eid = ''               # the base entity id host=<hostname>
        self.controller = False          # set true if node is controller

        # dynamic gate variables
        self.virtual = False             # set to True if host is virtual
        self._config_complete = False    # set to True once config is complete
        self.config_done = False         # set true if config_func completed ok
        self.init_complete = False       # set true if init_func completed ok
        self._node_ready = False         # set true when node is ready

        self.alarm_type = fm_constants.FM_ALARM_TYPE_7     # OPERATIONAL
        self.cause = fm_constants.ALARM_PROBABLE_CAUSE_50  # THRESHOLD CROSS
        self.suppression = True
        self.service_affecting = False

        # dynamic variables set in read_func
        self.usage = float(0)            # last usage value recorded as float
        self.value = float(0)            # last read value
        self.audits = 0                  # number of audit since init
        self.enabled = False             # tracks a plugin's enabled state
        self.alarmed = False             # tracks the current alarmed state
        self.mode = ''                   # mode specific to plugin
        self.capabilities = {}           # capabilities specific to plugin

        # http and json specific variables
        self.url = url                   # target url
        self.jresp = None                # used to store the json response
        self.resp = ''

        self.objects = []                # list of plugin specific objects
        self.cmd = ''                    # plugin specific command string

        # Log controls
        self.config_logged = False       # used to log once the plugin config
        self.error_logged = False        # used to prevent log flooding
        self.log_throttle_count = 0      # used to count throttle logs
        self.INIT_LOG_THROTTLE = 10      # the init log throttle threshold
        self.CONFIG_LOG_THROTTLE = 50    # the config log throttle threshold
        self.http_retry_count = 0        # track http error cases
        self.HTTP_RETRY_THROTTLE = 6     # http retry threshold
        self.phase = 0                   # tracks current phase; init, sampling
        self.node_ready_threshold = 3    # wait for node ready before sampling
        self.node_ready_count = 0        # node ready count up counter

    ###########################################################################
    #
    # Name       : init_completed
    #
    # Description: Declare init completed
    #
    # Parameters : plugin name
    #
    ###########################################################################

    def init_completed(self):
        """Declare plugin init complete"""
        self.hostname = self.gethostname()
        self.base_eid = 'host=' + self.hostname
        collectd.info("%s %s initialization completed" %
                      (self.plugin, self.hostname))
        self.init_complete = True

    ###########################################################################
    #
    # Name       : config_complete
    #
    # Description: Test for config complete condition
    #
    # Parameters : plugin name
    #
    # Returns    : False if config is not complete
    #              True if config is complete
    #
    ###########################################################################

    def config_complete(self):
        """Test for config complete state"""

        if self._config_complete is False:
            if tsc.nodetype == 'worker' or 'worker' in tsc.subfunctions:
                flag_file = tsc.VOLATILE_WORKER_CONFIG_COMPLETE
            elif tsc.nodetype == 'storage':
                flag_file = tsc.VOLATILE_STORAGE_CONFIG_COMPLETE
            else:
                flag_file = tsc.VOLATILE_CONTROLLER_CONFIG_COMPLETE

            if os.path.exists(flag_file) is False:
                self._config_complete = False
                self.log_throttle_count += 1
                if self.log_throttle_count > self.CONFIG_LOG_THROTTLE:
                    collectd.info("%s configuration check needs retry" %
                                  self.plugin)
                    self.log_throttle_count = 0
                time.sleep(1)
                return False
            else:
                self._config_complete = True
                self.log_throttle_count = 0
                collectd.info("%s configuration completed" % self.plugin)

        return True

    ###########################################################################
    #
    # Name       : node_ready
    #
    # Description: Test for node ready condition.
    #              Currently, that's just a threshold count
    #
    # Parameters : plugin name
    #
    # Returns    : False if node is not ready
    #              True if node is ready
    #
    ###########################################################################

    def node_ready(self):
        """Check for node ready state"""

        if tsc.nodetype == 'controller':
            self.node_ready_count += 1
            if self.node_ready_count < self.node_ready_threshold:
                collectd.info("%s node ready count %d of %d" %
                              (self.plugin,
                               self.node_ready_count,
                               self.node_ready_threshold))
                return False

        self._node_ready = True
        return True

    ###########################################################################
    #
    # Name       : gethostname
    #
    # Description: load the hostname
    #
    # Parameters : plugin name
    #
    # Returns    : Success - hostname
    #              Failure - None
    #
    # Updates    : obj.hostname
    #
    ###########################################################################
    def gethostname(self):
        """Fetch the hostname"""

        # get current hostname
        try:
            hostname = socket.gethostname()
            if hostname:
                return hostname
        except:
            collectd.error("%s failed to get hostname" % self.plugin)

        return None

    ###########################################################################
    #
    # Name       : is_virtual
    #
    # Description: Execute facter command with output filter on 'is_virtual'
    #
    # Parameters : None
    #
    # Returns    :  True if current host is virtual.
    #              False if current host is NOT virtual
    #
    ###########################################################################
    def is_virtual(self):
        """Check for virtual host"""

        try:
            cmd = '/usr/bin/facter is_virtual'
            res, err = processutils.execute(cmd, shell=True)
            if err:
                return False
            elif res:
                # remove the trailing '\n' with strip()
                if res.strip() == 'true':
                    collectd.info("%s %s is virtual" %
                                  (self.plugin, self.hostname))
                    return True

        except Exception as ex:
            collectd.info("%s failed to execute '/usr/bin/facter' ; %s" %
                          self.plugin, ex)

        return False

    ###########################################################################
    #
    # Name       : check_for_fit
    #
    # Description: load FIT data if it is present
    #
    # Fit Format : unit data -> 0 89
    #              - instance 0 value 89
    #
    # Parameters : plugin name
    #              object to update with fit
    #              name in fit file
    #              unit
    #
    # Returns    : Did a failure occur ?
    #              False = no
    #              True  = yes
    #
    # Updates    : self.usage with FIT value if FIT conditions are present
    #              and apply
    #
    ###########################################################################
    def check_for_fit(self, name, unit):
        """Load FIT data into usage if it exists"""

        fit_file = '/var/run/fit/' + name + '_data'

        if os.path.exists(fit_file):
            valid = False
            with open(fit_file, 'r') as infile:
                for line in infile:
                    try:
                        inst, val = line.split(' ')
                        if int(unit) == int(inst):
                            self.usage = float(val)
                            valid = True

                    except:
                        try:
                            val = float(line)
                            self.usage = float(val)
                            valid = True

                        except:
                            collectd.error("%s bad FIT data; ignoring" %
                                           self.plugin)

                    if valid is True:
                        collectd.info("%s %.2f usage (unit %d) (FIT)" %
                                      (self.plugin, unit, self.usage))
                        return False

        return True

    #####################################################################
    #
    # Name       : clear_alarm
    #
    # Description: Clear the specified alarm.
    #
    # Returns    : True if operation succeeded
    #              False if there was an error exception.
    #
    # Assumptions: Caller can decide to retry based on return status.
    #
    #####################################################################
    def clear_alarm(self, fm, alarm_id, eid):
        """Clear the specified alarm:eid

        :param fm  The Fault Manager's API Object
        :param alarm_id The alarm identifier , ie 100.103
        :param eid The entity identifier ; host=<hostname>.<instance>
        """

        try:
            if fm.clear_fault(alarm_id, eid) is True:
                collectd.info("%s %s:%s alarm cleared" %
                              (self.plugin, alarm_id, eid))
            else:
                collectd.info("%s %s:%s alarm already cleared" %
                              (self.plugin, alarm_id, eid))
            return True

        except Exception as ex:
            collectd.error("%s 'clear_fault' exception ; %s:%s ; %s" %
                           (self.plugin, alarm_id, eid, ex))
            return False

    #########################################################################
    #
    # Name : __missing_or_mismatch_alarm_handler
    #
    # Purpose: Find and correct missing or mismatch alarms
    #
    # Scope: Private
    #
    #########################################################################
    def __missing_or_mismatch_alarm_handler(self,
                                            fm,
                                            alarms,
                                            alarm_id,
                                            severity,
                                            sev_alarm_dict):
        """Find and correct missing or mismatch alarms

        :param fm  The Fault Manager's API Object
        :param alarms List of database alarms for alarm id and this host
        :param alarm_id The alarm id in context
        :param severity Specifies the severity level of sev_alarm_dict
        :param sev_alarm_dict An alarm dictionary for either (not both) major
                              or critical alarms
        """
        plugin_prefix = self.plugin + ' audit'
        for eid in sev_alarm_dict:
            found = False
            if alarm_id == sev_alarm_dict[eid].get(AUDIT_INFO_ALARM):
                error_case = "missing"
                if alarms:
                    for alarm in alarms:
                        if alarm.entity_instance_id == eid:
                            if alarm.severity == severity:
                                collectd.info("%s alarm %s:%s:%s is correct" %
                                              (plugin_prefix, severity,
                                               alarm_id, eid))
                                found = True
                            else:
                                error_case = "mismatch"
                            break

                if found is False:

                    fault = sev_alarm_dict[eid].get(AUDIT_INFO_FAULT)
                    if fault:
                        collectd.info("%s alarm %s:%s:%s %s ; refreshing" %
                                      (plugin_prefix,
                                       severity, alarm_id, eid, error_case))
                        fm.set_fault(fault)
                    else:
                        collectd.info("%s alarm %s:%s:%s %s" %
                                      (plugin_prefix,
                                       severity, alarm_id, eid, error_case))

    #########################################################################
    #
    # Name: alarms_audit
    #
    # Purpose: Ensure the alarm state in the FM database matches the plugin
    #
    # Description: Query FM for the specified alarm id list. Handle missing,
    #              stale or severity mismatched alarms.
    #
    # Algorithm  : Each alarm id is queried and the response is filtered by
    #              current host. The plugin's running state takes precedence.
    #              This audit will only ever raise, modify or clear alarms in
    #              the database, never change the alarm state of the plugin.
    #
    #                - clear any asserted alarms that have a clear state
    #                  in the plugin.
    #                - raise an alarm that is cleared in fm but asserted
    #                  in the plugin.
    #                - correct alarm severity in fm database to align with
    #                  the plugin.
    #
    # Assumptions: The severity dictionary arguments (major and critical)
    #              are used to detect severity mismatches and support alarm
    #              ids with varying entity ids.
    #
    #              The dictionaries are a list of key value pairs ; aid:eid
    #                - alarm id as 'aid'
    #                - entity_id as 'eid'
    #
    #              No need to check for fm api call success and retry on
    #              failure. Stale alarm clear will be retried on next audit.
    #
    #########################################################################
    def alarms_audit(self,
                     fm,
                     audit_alarm_id_list,
                     major_alarm_dict,
                     critical_alarm_dict):
        """Audit the fm database for this plugin's alarms state

        :param fm The Fault Manager's API Object
        :param audit_alarm_id_list A list of alarm ids to query
        :param major_alarm_dict    A dictionary of major    alarms by aid:eid
        :param critical_alarm_dict A dictionary of critical alarms by aid:eid
        """

        if len(audit_alarm_id_list) == 0:
            return

        plugin_prefix = self.plugin + ' audit'

        if len(major_alarm_dict):
            collectd.debug("%s major_alarm_dict: %s" %
                           (plugin_prefix, major_alarm_dict))

        if len(critical_alarm_dict):
            collectd.debug("%s critical_alarm_dict: %s" %
                           (plugin_prefix, critical_alarm_dict))

        for alarm_id in audit_alarm_id_list:
            collectd.debug("%s searching for all '%s' alarms" %
                           (plugin_prefix, alarm_id))
            try:
                database_alarms = []
                tmp = fm.get_faults_by_id(alarm_id)
                if tmp is not None:
                    database_alarms = tmp

                # database alarms might contain same alarm id for other
                # hosts and needs to be filtered
                alarms = []
                for alarm in database_alarms:
                    base_eid = alarm.entity_instance_id.split('.')[0]
                    if self.base_eid == base_eid:
                        collectd.debug("%s alarm %s:%s:%s in fm" %
                                       (plugin_prefix,
                                        alarm.severity, alarm_id,
                                        alarm.entity_instance_id))
                        alarms.append(alarm)

            except Exception as ex:
                collectd.error("%s get_faults_by_id %s failed "
                               "with exception ; %s" %
                               (plugin_prefix, alarm_id, ex))
                continue

            # Service database alarms case

            # Stale database alarms handling case
            remove_alarms_list = []
            if alarms:
                for alarm in alarms:
                    found = False
                    for eid in major_alarm_dict:
                        if alarm.entity_instance_id == eid:
                            found = True
                            break
                    if found is False:
                        for eid in critical_alarm_dict:
                            if alarm.entity_instance_id == eid:
                                found = True
                                break

                    if found is False:
                        collectd.info("%s alarm %s:%s:%s is stale ; clearing" %
                                      (plugin_prefix,
                                       alarm.severity, alarm_id,
                                       alarm.entity_instance_id))

                        # clear stale alarm.
                        self.clear_alarm(fm, alarm_id,
                                         alarm.entity_instance_id)
                        remove_alarms_list.append(alarm)
                for alarm in remove_alarms_list:
                    alarms.remove(alarm)
            else:
                collectd.debug("%s database has no %s alarms" %
                               (plugin_prefix, alarm_id))

            # If major alarms exist then check for
            # missing or mismatch state in fm database
            if len(major_alarm_dict):
                self.__missing_or_mismatch_alarm_handler(fm,
                                                         alarms,
                                                         alarm_id,
                                                         'major',
                                                         major_alarm_dict)
            # If critical alarms exist then check for
            # missing or mismatch state in fm database.
            if len(critical_alarm_dict):
                self.__missing_or_mismatch_alarm_handler(fm,
                                                         alarms,
                                                         alarm_id,
                                                         'critical',
                                                         critical_alarm_dict)

    ###########################################################################
    #
    # Name       : make_http_request
    #
    # Description: Issue a http request to the specified URL.
    #              Load and return the response
    #              Handling execution errors
    #
    # Parameters : self as current context.
    #
    #    Optional:
    #
    #              url  - override the default self url with http address to
    #                     issue the get request to.
    #              to   - timeout override
    #              hdrs - override use of the default header list
    #
    # Updates    : self.jresp with the json string response from the request.
    #
    # Returns    : Error indication (True/False)
    #              True on success
    #              False on error
    #
    ###########################################################################
    def make_http_request(self, url=None, to=None, hdrs=None):
        """Make a blocking HTTP Request and return result"""

        try:

            # handle timeout override
            if to is None:
                to = PLUGIN_TIMEOUT

            # handle url override
            if url is None:
                url = self.url

            # handle header override
            if hdrs is None:
                hdrs = PLUGIN_HTTP_HEADERS

            http = httplib2.Http(timeout=to)
            resp = http.request(url, headers=hdrs)

        except Exception as ex:
            collectd.info("%s http request exception ; %s" %
                          (self.plugin, str(ex)))
            return False

        try:
            collectd.debug("%s Resp: %s" %
                           (self.plugin, resp[1]))

            self.resp = resp[1]
            self.jresp = json.loads(resp[1])

        except Exception as ex:
            collectd.error("%s http response parse exception ; %s" %
                           (self.plugin, str(ex)))
            if len(self.resp):
                collectd.error("%s response: %s" %
                               (self.plugin, self.resp))
            return False
        return True


class K8sClient(object):

    def __init__(self):

        self._host = socket.gethostname()
        self._kube_client_core = None

    def _as_kube_metadata(self, metadata):
        # metadata (json) dictionary has the following keys:
        #'annotations', 'creationTimestamp', 'labels', 'name', 'namespace',
        # 'ownerReferences', 'resourceVersion', 'uid'
        return client.models.v1_object_meta.V1ObjectMeta(
            name=metadata.get('name'),
            namespace=metadata.get('namespace'),
            annotations=metadata.get('annotations'),
            uid=metadata.get('uid'),
            labels=metadata.get('labels'))

    def _as_kube_pod(self, pod):
        # pod (json) dictionary has the following keys:
        # 'apiVersion', 'kind', 'metadata', 'spec', 'status'
        return client.V1Pod(
            api_version=pod.get('apiVersion'),
            kind=pod.get('kind'),
            metadata=self._as_kube_metadata(pod.get('metadata')),
            spec=pod.get('spec'),
            status=self._as_kube_status(pod.get('status')))

    def _as_kube_status(self, status):
        # status (json) dictionary has the following keys:
        # 'conditions', 'containerStatuses', 'hostIP', 'phase',
        # 'podIP', 'podIPs', 'qosClass', 'startTime'
        return client.models.v1_pod_status.V1PodStatus(
            conditions=status.get('conditions'),
            container_statuses=status.get('containerStatuses'),
            host_ip=status.get('hostIP'),
            phase=status.get('phase'),
            pod_ip=status.get('podIP'),
            pod_i_ps=status.get('podIPs'),
            qos_class=status.get('qosClass'),
            start_time=status.get('startTime')
        )

    def _load_kube_config(self):

        config.load_kube_config(KUBELET_CONF)

        # WORKAROUND: Turn off SSL/TLS verification
        if SSL_TLS_SUPPRESS:
            # Suppress the "InsecureRequestWarning: Unverified HTTPS request"
            # seen with each kubelet client API call.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            if K8S_MODULE_MAJOR_VERSION < 12:
                c = Configuration()
            else:
                c = Configuration().get_default_copy()
            c.verify_ssl = False
            Configuration.set_default(c)

    def _get_k8sclient_core(self):
        if not self._kube_client_core:
            self._load_kube_config()
            self._kube_client_core = client.CoreV1Api()
        return self._kube_client_core

    def kube_get_local_pods(self):
        # The Debian collectd leaks file descriptors calling the kube API
        # the workaround is to use subprocess
        field_selector = 'spec.nodeName=' + self._host
        try:
            if six.PY2:
                # Centos
                api_response = self._get_k8sclient_core().\
                    list_pod_for_all_namespaces(
                        watch=False,
                        field_selector=field_selector)
                return api_response.items
            else:
                # Debian
                # kubectl --kubeconfig KUBELET_CONF get pods --all-namespaces \
                # --selector spec.nodeName=the_host -o json
                kube_results = subprocess.check_output(
                    ['kubectl', '--kubeconfig', KUBELET_CONF,
                     '--field-selector', field_selector,
                     'get', 'pods', '--all-namespaces',
                     '-o', 'json'
                     ]).decode()
                json_results = json.loads(kube_results)
                # convert the items to: kubernetes.client.V1Pod
                api_items = [self._as_kube_pod(x) for x in json_results['items']]
                return api_items
        except Exception as err:
            collectd.error("kube_get_local_pods: %s" % (err))
            raise


class POD_object:
    def __init__(self, uid, name, namespace, qos_class, labels=None):
        self.uid = uid
        self.name = name
        self.namespace = namespace
        self.qos_class = qos_class
        self.labels = labels

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def __repr__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def is_platform_resource(self):
        """Check whether pod contains platform namespace or platform label"""

        if (self.namespace in K8S_NAMESPACE_SYSTEM
                or self.labels.get(PLATFORM_LABEL_KEY) == GROUP_PLATFORM):
            return True
        return False


def is_uuid_like(val):
    """Returns validation of a value as a UUID

    For our purposes, a UUID is a canonical form string:
    aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    """
    try:
        return str(uuid.UUID(val)) == val
    except (TypeError, ValueError, AttributeError):
        return False


def get_severity_str(severity):
    """get string that represents the specified severity"""

    if severity == fm_constants.FM_ALARM_SEVERITY_CLEAR:
        return "clear"
    elif severity == fm_constants.FM_ALARM_SEVERITY_CRITICAL:
        return "critical"
    elif severity == fm_constants.FM_ALARM_SEVERITY_MAJOR:
        return "major"
    elif severity == fm_constants.FM_ALARM_SEVERITY_MINOR:
        return "minor"
    else:
        return "unknown"


def convert2boolean(v):
    """Convert an object to boolean result"""

    if type(v) == bool:
        return v
    if isinstance(v, (int, float)):
        return bool(int(v))
    if isinstance(v, str):
        return v.lower() in ("yes", "true", "t", "1",)
    else:
        return False


def log_dictionary(plugin='', name='', d={}):
    """Log a line of output for each key-value pair for dictionary d.

    i.e., d[key] = value
    """

    for key in sorted(d.keys()):
        collectd.info('%s: %s: %s = %s'
                      % (plugin, name, key, d[key]))


def log_dictionary_nodes(plugin='', name='', d={}):
    """Log a line of output for each key-value pair for nested dictionary d.

    i.e., For each node, for each key-value pair: d[node][key] = value
    """

    for node in sorted(d.keys()):
        for key, val in sorted(d[node].items()):
            collectd.info('%s: %s: %s %s = %s'
                          % (plugin, name, node, key, val))


def walklevel(some_dir, level=1):
    """Recursively walk directories to a specified level.

    Provides the same functionality as os.walk(), just limits the walk to a
    specified level of recursion.
    """

    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]


def range_to_list(csv_range=None):
    """Convert a string of comma separated ranges into integer list.

    e.g., '1-3,8-9,15' is converted to [1,2,3,8,9,15]
    """

    if not csv_range:
        return []
    ranges = [(lambda L: range(L[0], L[-1] + 1))(list(map(int, r.split('-'))))
              for r in csv_range.split(',')]
    return [y for x in ranges for y in x]


def format_range_set(items):
    """Generate pretty-printed value of ranges, such as 3-6,12-17."""

    ranges = []
    for k, iterable in it.groupby(enumerate(sorted(items)),
                                  lambda x: x[1] - x[0]):
        rng = list(iterable)
        if len(rng) == 1:
            s = str(rng[0][1])
        else:
            s = "%s-%s" % (rng[0][1], rng[-1][1])
        ranges.append(s)
    return ','.join(ranges)
