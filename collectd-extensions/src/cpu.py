#
# Copyright (c) 2018-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
############################################################################
#
# This file is the collectd 'Platform CPU Usage' Monitor.
#
# The Platform CPU Usage is calculated as an averaged occupancy percentage
# of platform logical cpus since the previous sample.
#
# Example commands to read samples from the database:
# SELECT * FROM cpu_value WHERE type='percent' AND type_instance='used'
# SELECT * FROM cpu_value WHERE type='percent' AND type_instance='occupancy'
#
############################################################################
import collectd
import copy
import os
import plugin_common as pc
import re
import socket
import time

PLUGIN = 'platform cpu usage plugin'
PLUGIN_DEBUG = 'DEBUG platform cpu'

TIMESTAMP = 'timestamp'
PLATFORM_CPU_PERCENT = 'platform-occupancy'
CGROUP_PLATFORM_CPU_PERCENT = 'cgroup-platform-occupancy'
SCHEDSTAT_SUPPORTED_VERSION = 15

# Linux per-cpu info
CPUINFO = '/proc/cpuinfo'
SCHEDSTAT = '/proc/schedstat'

# cpuacct cgroup controller
CPUACCT = pc.CGROUP_ROOT + '/cpuacct'
CPUACCT_USAGE = 'cpuacct.usage'

# Common regex pattern match groups
re_uid = re.compile(r'^pod(\S+)')
re_processor = re.compile(r'^[Pp]rocessor\s+:\s+(\d+)')
re_schedstat = re.compile(r'^cpu(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+')
re_schedstat_version = re.compile(r'^version\s+(\d+)')
re_keyquoteval = re.compile(r'^\s*(\S+)\s*[=:]\s*\"(\S+)\"\s*')


# Plugin specific control class and object.
class CPU_object(pc.PluginObject):

    def __init__(self):
        super(CPU_object, self).__init__(PLUGIN, '')
        self.debug = True
        self.verbose = True
        self._cache = {}
        self._k8s_client = pc.K8sClient()
        self.k8s_pods = set()

        self.schedstat_version = 0
        self.schedstat_supported = True
        self.number_platform_cpus = 0

        # Platform CPU monitor
        now = time.time()  # epoch time in floating seconds
        self._t0 = {}      # cputime state info at start of sample interval
        self._t0[TIMESTAMP] = now
        self._t0_cpuacct = {}

        self._data = {}    # derived measurements at end of sample interval
        self._data[PLATFORM_CPU_PERCENT] = 0.0
        self.elapsed_ms = 0.0


# Instantiate the class
obj = CPU_object()


def read_schedstat():
    """Read current hiresolution times per cpu from /proc/schedstats.

    Return dictionary of cputimes in nanoseconds per cpu.
    """

    cputime = {}

    # Obtain cumulative cputime (nanoseconds) from 7th field of
    # /proc/schedstat. This is the time running tasks on this cpu.
    try:
        with open(SCHEDSTAT, 'r') as f:
            for line in f:
                match = re_schedstat.search(line)
                if match:
                    k = int(match.group(1))
                    v = int(match.group(2))
                    cputime[k] = v
    except Exception as err:
        collectd.error('%s Cannot read schedstat, error=%s' % (PLUGIN, err))

    return cputime


def get_logical_cpus():
    """Get the list of logical cpus from /proc/cpuinfo."""

    cpus = set([])
    try:
        with open(CPUINFO, 'r') as infile:
            for line in infile:
                match = re_processor.search(line)
                if match:
                    cpus.add(int(match.group(1)))
    except Exception as err:
        collectd.error('%s Cannot parse file, error=%s' % (PLUGIN, err))
    return list(cpus)


def get_platform_cpulist():
    """Get the platform configured cpu list from worker_reserved.conf.

    This value is provided by puppet resource file which is populated
    via sysinv query.

    Returns list of platform cpus.
    Returns empty list if worker_reserved.conf does not exist.
    """

    cpulist = []

    # Match key=value, the value is quoted cpulist without spaces.
    # E.g., PLATFORM_CPU_LIST="0-3"
    m = {}
    if os.path.exists(pc.RESERVED_CONF):
        try:
            with open(pc.RESERVED_CONF, 'r') as f:
                for line in f:
                    match = re_keyquoteval.search(line)
                    if match:
                        k = match.group(1)
                        v = match.group(2)
                        m[k] = v
        except Exception as err:
            collectd.error('%s Cannot parse file, error=%s' % (PLUGIN, err))
            return cpulist
    else:
        return cpulist

    if pc.RESERVED_CPULIST_KEY in m:
        cpus = m[pc.RESERVED_CPULIST_KEY]
        cpulist = pc.range_to_list(csv_range=cpus)
    else:
        collectd.warning('%s %s not found in file: %s'
                         % (PLUGIN,
                            pc.RESERVED_CPULIST_KEY, pc.RESERVED_CONF))

    return cpulist


def get_cgroup_cpuacct(path):
    """Get cgroup cpuacct usage for a specific cgroup path.

    This represents the aggregate usage for child cgroups.

    Returns cumulative usage in nanoseconds.
    """

    acct = 0

    fstat = '/'.join([path, CPUACCT_USAGE])
    try:
        with open(fstat, 'r') as f:
            line = f.readline().rstrip()
            acct = int(line)
    except IOError:
        # Silently ignore IO errors. It is likely the cgroup disappeared.
        pass

    return acct


def get_cpuacct():
    """Get cpuacct usage based on cgroup hierarchy."""

    cpuacct = {}
    cpuacct[pc.GROUP_OVERALL] = {}
    cpuacct[pc.GROUP_FIRST] = {}
    cpuacct[pc.GROUP_PODS] = {}

    # Overall cpuacct usage
    acct = get_cgroup_cpuacct(CPUACCT)
    cpuacct[pc.GROUP_OVERALL][pc.GROUP_TOTAL] = acct

    # Walk the first level cgroups and get cpuacct usage
    # (e.g., docker, k8s-infra, user.slice, system.slice, machine.slice)
    dir_list = os.walk(CPUACCT).next()[1]
    for name in dir_list:
        cg_path = '/'.join([CPUACCT, name])
        acct = get_cgroup_cpuacct(cg_path)
        cpuacct[pc.GROUP_FIRST][name] = acct

    # Walk the kubepods hierarchy to the pod level and get cpuacct usage.
    # We can safely ignore reading this if the path does not exist.
    # The path wont exist on non-K8S nodes. The path is created as part of
    # kubernetes configuration.
    path = '/'.join([CPUACCT, pc.K8S_ROOT, pc.KUBEPODS])
    if os.path.isdir(path):
        for root, dirs, files in pc.walklevel(path, level=1):
            for name in dirs:
                if name.startswith('pod') and CPUACCT_USAGE in files:
                    match = re_uid.search(name)
                    if match:
                        uid = match.group(1)
                        cg_path = os.path.join(root, name)
                        acct = get_cgroup_cpuacct(cg_path)
                        cpuacct[pc.GROUP_PODS][uid] = acct
    return cpuacct


def update_cpu_data(init=False):
    """Gather cputime info and Update platform cpu occupancy metrics.

    This gathers current per-cpu cputime information from schedstats
    and per-cgroup cputime information from cgroup cpuacct.

    This calculates the average cpu occupancy of the platform cores
    since this routine was last run.
    """

    # Get epoch time in floating seconds
    now = time.time()

    # Calculate elapsed time delta since last run
    obj.elapsed_ms = float(pc.ONE_THOUSAND) * (now - obj._t0[TIMESTAMP])

    # Prevent calling this routine too frequently (<= 1 sec)
    if not init and obj.elapsed_ms <= 1000.0:
        return

    t1 = {}
    t1[TIMESTAMP] = now
    if obj.schedstat_supported:
        # Get current per-cpu cumulative cputime usage from /proc/schedstat.
        cputimes = read_schedstat()
        for cpu in obj.cpu_list:
            t1[cpu] = cputimes[cpu]
    else:
        return

    # Get current cpuacct usages based on cgroup hierarchy
    t1_cpuacct = get_cpuacct()

    # Refresh the k8s pod information if we have discovered new cgroups
    cg_pods = set(t1_cpuacct[pc.GROUP_PODS].keys())
    if not cg_pods.issubset(obj.k8s_pods):
        if obj.debug:
            collectd.info('%s Refresh k8s pod information.' % (PLUGIN_DEBUG))
        obj.k8s_pods = set()
        pods = obj._k8s_client.kube_get_local_pods()
        for i in pods:
            # NOTE: parent pod cgroup name contains annotation config.hash as
            # part of its name, otherwise it contains the pod uid.
            uid = i.metadata.uid
            if ((i.metadata.annotations) and
                    (pc.POD_ANNOTATION_KEY in i.metadata.annotations)):
                hash_uid = i.metadata.annotations.get(pc.POD_ANNOTATION_KEY,
                                                      None)
                if hash_uid:
                    if obj.debug:
                        collectd.info('%s POD_ANNOTATION_KEY: '
                                      'hash=%s, uid=%s, '
                                      'name=%s, namespace=%s, qos_class=%s'
                                      % (PLUGIN_DEBUG,
                                         hash_uid,
                                         i.metadata.uid,
                                         i.metadata.name,
                                         i.metadata.namespace,
                                         i.status.qos_class))
                    uid = hash_uid

            obj.k8s_pods.add(uid)
            if uid not in obj._cache:
                obj._cache[uid] = pc.POD_object(i.metadata.uid,
                                                i.metadata.name,
                                                i.metadata.namespace,
                                                i.status.qos_class)
    # Remove stale _cache entries
    remove_uids = set(obj._cache.keys()) - obj.k8s_pods
    for uid in remove_uids:
        del obj._cache[uid]

    # Save initial state information
    if init:
        obj._t0 = copy.deepcopy(t1)
        obj._t0_cpuacct = copy.deepcopy(t1_cpuacct)
        return

    # Aggregate cputime delta for platform logical cpus using integer math
    cputime_ms = 0.0
    for cpu in obj.cpu_list:
        # Paranoia check, we should never hit this.
        if cpu not in obj._t0:
            collectd.error('%s cputime initialization error' % (PLUGIN))
            break
        cputime_ms += float(t1[cpu] - obj._t0[cpu])
    cputime_ms /= float(pc.ONE_MILLION)

    # Calculate average occupancy of platform logical cpus
    occupancy = 0.0
    if obj.number_platform_cpus > 0 and obj.elapsed_ms > 0:
        occupancy = float(pc.ONE_HUNDRED) * float(cputime_ms) \
            / float(obj.elapsed_ms) / obj.number_platform_cpus
    else:
        occupancy = 0.0
    obj._data[PLATFORM_CPU_PERCENT] = occupancy
    if obj.debug:
        collectd.info('%s %s elapsed = %.1f ms, cputime = %.1f ms, '
                      'n_cpus = %d, occupancy = %.2f %%'
                      % (PLUGIN_DEBUG,
                         PLATFORM_CPU_PERCENT,
                         obj.elapsed_ms,
                         cputime_ms,
                         obj.number_platform_cpus,
                         occupancy))

    # Calculate cpuacct delta for cgroup hierarchy, dropping transient cgroups
    cpuacct = {}
    for i in t1_cpuacct.keys():
        cpuacct[i] = {}
        for k, v in t1_cpuacct[i].items():
            if k in obj._t0_cpuacct[i]:
                cpuacct[i][k] = v - obj._t0_cpuacct[i][k]
            else:
                cpuacct[i][k] = v

    # Summarize cpuacct usage for various groupings
    for g in pc.OVERALL_GROUPS:
        cpuacct[pc.GROUP_OVERALL][g] = 0.0

    # Aggregate cpuacct usage by K8S pod
    for uid in cpuacct[pc.GROUP_PODS]:
        acct = cpuacct[pc.GROUP_PODS][uid]
        if uid in obj._cache:
            pod = obj._cache[uid]
        else:
            collectd.warning('%s uid %s not found' % (PLUGIN, uid))
            continue

        # K8S platform system usage, i.e., essential: kube-system
        if pod.namespace in pc.K8S_NAMESPACE_SYSTEM:
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_K8S_SYSTEM] += acct

        # K8S platform addons usage, i.e., non-essential: monitor, openstack
        if pod.namespace in pc.K8S_NAMESPACE_ADDON:
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_K8S_ADDON] += acct

    # Calculate base cpuacct usage (i.e., base tasks, exclude K8S and VMs)
    # e.g., docker, system.slice, user.slice
    for name in cpuacct[pc.GROUP_FIRST]:
        if name in pc.BASE_GROUPS:
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_BASE] += \
                cpuacct[pc.GROUP_FIRST][name]
        elif name not in pc.BASE_GROUPS_EXCLUDE:
            collectd.warning('%s could not find cgroup: %s' % (PLUGIN, name))

    # Calculate platform cpuacct usage (this excludes apps)
    for g in pc.PLATFORM_GROUPS:
        cpuacct[pc.GROUP_OVERALL][pc.GROUP_PLATFORM] += \
            cpuacct[pc.GROUP_OVERALL][g]

    # Calculate cgroup based occupancy for overall groupings
    for g in pc.OVERALL_GROUPS:
        cputime_ms = \
            float(cpuacct[pc.GROUP_OVERALL][g]) / float(pc.ONE_MILLION)
        occupancy = float(pc.ONE_HUNDRED) * float(cputime_ms) \
            / float(obj.elapsed_ms) / obj.number_platform_cpus
        obj._data[g] = occupancy
        if obj.debug:
            collectd.info('%s %s elapsed = %.1f ms, cputime = %.1f ms, '
                          'n_cpus = %d, occupancy = %.2f %%'
                          % (PLUGIN_DEBUG,
                             g,
                             obj.elapsed_ms,
                             cputime_ms,
                             obj.number_platform_cpus,
                             occupancy))

    # Update t0 state for the next sample collection
    obj._t0 = copy.deepcopy(t1)
    obj._t0_cpuacct = copy.deepcopy(t1_cpuacct)


def config_func(config):
    """Configure the cpu usage plugin."""

    for node in config.children:
        key = node.key.lower()
        val = node.values[0]
        if key == 'debug':
            obj.debug = pc.convert2boolean(val)
        elif key == 'verbose':
            obj.verbose = pc.convert2boolean(val)

    collectd.info('%s debug=%s, verbose=%s'
                  % (PLUGIN, obj.debug, obj.verbose))

    return pc.PLUGIN_PASS


# Get the platform cpu list and number of cpus reported by /proc/cpuinfo
def init_func():
    """Init the plugin."""

    # do nothing till config is complete.
    if obj.config_complete() is False:
        return False

    obj.hostname = socket.gethostname()

    # Determine the full list of logical cpus for this host
    obj.logical_cpus = get_logical_cpus()

    # Determine the subset of logical platform cpus that we want to monitor
    obj.cpu_list = get_platform_cpulist()
    if obj.debug:
        collectd.info('%s configured platform cpu list: %r'
                      % (PLUGIN_DEBUG, obj.cpu_list))

    # Ensure that the platform cpus are a subset of actual logical cpus
    if not (all(x in obj.logical_cpus for x in obj.cpu_list)):
        collectd.error('%s cpulist %r is not a subset of host logical cpus %r'
                       % (PLUGIN, obj.cpu_list, obj.logical_cpus))
        return pc.PLUGIN_FAIL

    # Monitor all logical cpus if no platform cpus have been specified
    if not obj.cpu_list:
        obj.cpu_list = obj.logical_cpus
    obj.number_platform_cpus = len(obj.cpu_list)

    collectd.info('%s found %d cpus total; monitoring %d cpus, cpu list: %s'
                  % (PLUGIN,
                     len(obj.logical_cpus),
                     obj.number_platform_cpus,
                     pc.format_range_set(obj.cpu_list)))

    # Check schedstat version
    version = 0
    try:
        with open(SCHEDSTAT, 'r') as f:
            line = f.readline()
            match = re_schedstat_version.search(line)
            if match:
                version = int(match.group(1))
    except Exception as err:
        collectd.error('%s Cannot read schedstat, error=%s' % (PLUGIN, err))
        return pc.PLUGIN_FAIL
    if version != SCHEDSTAT_SUPPORTED_VERSION:
        obj.schedstat_supported = False
        collectd.error('%s unsupported schedstat version [%d]'
                       % (PLUGIN, version))
        return pc.PLUGIN_FAIL

    # Gather initial cputime state information.
    update_cpu_data(init=True)

    obj.init_completed()
    return pc.PLUGIN_PASS


# Calculate the CPU usage sample
def read_func():

    if obj.init_complete is False:
        init_func()
        return 0

    # epoch time in floating seconds
    now0 = time.time()

    if not obj.schedstat_supported:
        return pc.PLUGIN_FAIL

    if not obj.cpu_list:
        collectd.info('%s no cpus to monitor' % PLUGIN)
        return pc.PLUGIN_PASS

    # Gather current cputime state information, and calculate occupancy since
    # this routine was last run.
    update_cpu_data()

    # Prevent dispatching measurements at plugin startup
    if obj.elapsed_ms <= 1000.0:
        return pc.PLUGIN_PASS

    if obj.verbose:
        collectd.info('%s Usage: %.1f%% (avg per cpu); '
                      'cpus: %d, Platform: %.1f%% '
                      '(Base: %.1f, k8s-system: %.1f), k8s-addon: %.1f'
                      % (PLUGIN, obj._data[PLATFORM_CPU_PERCENT],
                         obj.number_platform_cpus,
                         obj._data[pc.GROUP_PLATFORM],
                         obj._data[pc.GROUP_BASE],
                         obj._data[pc.GROUP_K8S_SYSTEM],
                         obj._data[pc.GROUP_K8S_ADDON]))

    # Fault insertion code to assis in regression UT
    #
    # if os.path.exists('/var/run/fit/cpu_data'):
    #     with open('/var/run/fit/cpu_data', 'r') as infile:
    #         for line in infile:
    #             obj._data[PLATFORM_CPU_PERCENT] = float(line)
    #             collectd.info("%s using FIT data:%.2f" %
    #                           (PLUGIN, obj._data[PLATFORM_CPU_PERCENT] ))
    #             break

    # Dispatch overall platform cpu usage percent value
    val = collectd.Values(host=obj.hostname)
    val.plugin = 'cpu'
    val.type = 'percent'
    val.type_instance = 'used'
    val.dispatch(values=[obj._data[PLATFORM_CPU_PERCENT]])

    # Dispatch grouped platform cpu usage values
    val = collectd.Values(host=obj.hostname)
    val.plugin = 'cpu'
    val.type = 'percent'
    val.type_instance = 'occupancy'
    for g in pc.OVERALL_GROUPS:
        val.plugin_instance = g
        val.dispatch(values=[obj._data[g]])

    # Calculate overhead cost of gathering metrics
    if obj.debug:
        now = time.time()
        elapsed_ms = float(pc.ONE_THOUSAND) * (now - now0)
        collectd.info('%s overhead sampling cost = %.3f ms'
                      % (PLUGIN_DEBUG, elapsed_ms))

    return pc.PLUGIN_PASS


# Register the config, init and read functions
collectd.register_config(config_func)
collectd.register_init(init_func)
collectd.register_read(read_func)
