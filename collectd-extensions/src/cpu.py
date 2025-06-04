#
# Copyright (c) 2018-2025 Wind River Systems, Inc.
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
import numpy as np
import os
import plugin_common as pc
import re
import socket
import time
import tsconfig.tsconfig as tsc

from kubernetes.client.rest import ApiException

#PLUGIN = 'platform cpu usage plugin'
PLUGIN = 'platform cpu'
PLUGIN_HISTOGRAM = 'histogram'
PLUGIN_DEBUG = 'DEBUG platform cpu'
PLUGIN_HIRES_INTERVAL = 1        # hi-resolution sample interval in secs
PLUGIN_DISPATCH_INTERVAL = 30    # dispatch interval in secs
PLUGIN_HISTOGRAM_INTERVAL = 300  # histogram interval in secs

TIMESTAMP = 'timestamp'
PLATFORM_CPU_PERCENT = 'platform-occupancy'
CGROUP_PLATFORM_CPU_PERCENT = 'cgroup-platform-occupancy'
SCHEDSTAT_SUPPORTED_VERSION = 16

# Linux per-cpu info
CPUINFO = '/proc/cpuinfo'
SCHEDSTAT = '/proc/schedstat'

# cpuacct cgroup controller
CPUACCT = pc.CGROUP_ROOT + '/cpuacct'
CPUACCT_USAGE = 'cpuacct.usage'
CPUACCT_USAGE_PERCPU = 'cpuacct.usage_percpu'
CPU_STAT = 'cpu.stat'

# Common regex pattern match groups
re_uid = re.compile(r'^pod(\S+)')
re_processor = re.compile(r'^[Pp]rocessor\s+:\s+(\d+)')
re_schedstat = re.compile(r'^cpu(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+')
re_schedstat_version = re.compile(r'^version\s+(\d+)')
re_keyquoteval = re.compile(r'^\s*(\S+)\s*[=:]\s*\"(\S+)\"\s*')
re_cpu_wait_sum = re.compile(r'^wait_sum\s+(\d+)')

# hirunner minimum cpu occupancy threshold
HIRUNNER_MINIMUM_CPU_PERCENT = 0.1

# Set numpy format for printing bins
np.set_printoptions(formatter={'int': '{: 4d}'.format})


# Plugin specific control class and object.
class CPU_object(pc.PluginObject):

    def __init__(self):
        super(CPU_object, self).__init__(PLUGIN, '')
        # CPU Plugin flags
        self.dispatch = False   # print occupancy and dispatch this sample
        self.histogram = False  # print occupancy histogram this sample

        # CPU plugin configurable settings
        self.debug = True
        self.verbose = True
        self.hires = False

        # Cache Kubernetes pods data
        self._cache = {}
        self._k8s_client = pc.K8sClient()
        self.k8s_pods = set()

        self.schedstat_version = 0
        self.schedstat_supported = True
        self.number_platform_cpus = 0

        now = time.time()  # epoch time in floating seconds

        # CPU State information at start of dispatch interval
        self.d_t0 = {}  # per-cpu cputime at dispatch time 0
        self.d_w0 = {}  # per-cpu cpuwait at dispatch time 0
        self.d_t0[TIMESTAMP] = now  # timestamp dispatch time 0
        self.d_w0[TIMESTAMP] = now  # timestamp dispatch time 0
        self.d_t0_cpuacct = {}  # per-cgroup cpuacct at dispatch time 0
        self.d_t0_cpuwait = {}  # per-cgroup cpuwait at dispatch time 0

        # Derived measurements over dispatch interval
        self.d_occ = {}   # dispatch occupancy per cgroup or derived aggregate
        self.d_occw = {}  # dispatch occupancy wait per cgroup or derived aggregate
        self.d_occ[PLATFORM_CPU_PERCENT] = 0.0   # dispatch platform occupancy
        self.d_occw[PLATFORM_CPU_PERCENT] = 0.0  # dispatch platform occupancy wait
        for g in pc.OVERALL_GROUPS:
            self.d_occ[g] = 0.0
            self.d_occw[g] = 0.0
        self.d_elapsed_ms = 0.0  # dispatch elapsed time

        # CPU State information at start of read sample interval
        self._t0 = {}  # per-cpu cputime at time 0
        self._w0 = {}  # per-cpu cpuwait at time 0
        self._t0[TIMESTAMP] = now  # timestamp time 0
        self._w0[TIMESTAMP] = now  # timestamp time 0
        self._t0_cpuacct = {}  # per-cgroup cpuacct at time 0
        self._t0_cpuwait = {}  # per-cgroup cpuwait at time 0

        # Derived measurements over read sample interval
        self._occ = {}   # occupancy per cgroup or derived aggregate
        self._occw = {}  # occupancy wait per cgroup or derived aggregate
        self._occ[PLATFORM_CPU_PERCENT] = 0.0   # platform occupancy
        self._occw[PLATFORM_CPU_PERCENT] = 0.0  # platform occupancy wait
        for g in pc.OVERALL_GROUPS:
            self._occ[g] = 0.0
            self._occw[g] = 0.0
        self.elapsed_ms = 0.0  # elapsed time

        # Derived measurements over histogram interval
        self.hist_t0 = now          # histogram timestamp time 0
        self.hist_elapsed_ms = 0.0  # histogram elapsed time
        self.hist_occ = {}          # histogram bin counts per cgroup or derived aggregate
        self.shared_bins = np.histogram_bin_edges(
            np.array([0, 100], dtype=np.float64), bins=10, range=(0, 100))


# Instantiate the class
obj = CPU_object()


def read_schedstat():
    """Read current hiresolution times per cpu from /proc/schedstats.

    Return dictionary of cputimes in nanoseconds per cpu,
    dictionary of cpuwaits in nanoseconds per cpu.
    """

    cputime = {}
    cpuwait = {}

    # Obtain cumulative cputime (nanoseconds) from 7th field,
    # and cumulative cpuwait (nanoseconds) from 8th field,
    # from /proc/schedstat. This is the time running and  waiting
    # for tasks on this cpu.
    try:
        with open(SCHEDSTAT, 'r') as f:
            for line in f:
                match = re_schedstat.search(line)
                if match:
                    k = int(match.group(1))
                    v = int(match.group(2))
                    w = int(match.group(3))
                    cputime[k] = v
                    cpuwait[k] = w
    except Exception as err:
        collectd.error('%s Cannot read schedstat, error=%s' % (PLUGIN, err))

    return cputime, cpuwait


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


def get_cgroup_cpuacct(path, cpulist=None):
    """Get cgroup cpuacct usage for a specific cgroup path.

    This represents the aggregate usage for child cgroups.
    Scope of the cpuacct spans all cpus, or a subset of cpus
    when cpulist is specified.

    Returns cumulative usage in nanoseconds.
    """

    acct = 0

    if not cpulist:
        # Get the aggregate value for all cpus
        fstat = '/'.join([path, CPUACCT_USAGE])
        try:
            with open(fstat, 'r') as f:
                line = f.readline().rstrip()
                acct = int(line)
        except IOError:
            # Silently ignore IO errors. It is likely the cgroup disappeared.
            pass
    else:
        # Get the aggregate value for specified cpus
        fstat = '/'.join([path, CPUACCT_USAGE_PERCPU])
        try:
            with open(fstat, 'r') as f:
                line = f.readline().rstrip()
                acct_percpu = list(map(int, line.split()))
                for cpu in cpulist:
                    acct += acct_percpu[cpu]
        except IOError:
            # Silently ignore IO errors. It is likely the cgroup disappeared.
            pass

    return acct


def get_cgroup_cpu_wait_sum(path):
    """Get cgroup cpu.stat wait_sum usage for a specific cgroup path.

    This represents the aggregate of all tasks wait time cfs_rq.
    This tells us how suffering a task group is in the fight of
    cpu resources.

    Returns cumulative wait_sum in nanoseconds.
    """

    wait_sum = 0

    # Get the aggregate wait_sum for all cpus
    fstat = '/'.join([path, CPU_STAT])
    try:
        with open(fstat, 'r') as f:
            for line in f:
                match = re_cpu_wait_sum.search(line)
                if match:
                    v = int(match.group(1))
                    wait_sum = int(v)
    except IOError:
        # Silently ignore IO errors. It is likely the cgroup disappeared.
        pass

    return wait_sum


def get_cpuacct():
    """Get cpuacct usage and wait_sum based on cgroup hierarchy."""

    cpuacct = {}
    cpuacct[pc.GROUP_OVERALL] = {}
    cpuacct[pc.GROUP_FIRST] = {}
    cpuacct[pc.GROUP_PODS] = {}
    cpuacct[pc.CGROUP_SYSTEM] = {}
    cpuacct[pc.CGROUP_USER] = {}
    cpuacct[pc.CGROUP_UTILS] = {}
    cpuacct[pc.CGROUP_INIT] = {}
    cpuacct[pc.CGROUP_K8SPLATFORM] = {}

    cpuwait = {}
    cpuwait[pc.GROUP_OVERALL] = {}
    cpuwait[pc.GROUP_FIRST] = {}
    cpuwait[pc.GROUP_PODS] = {}
    cpuwait[pc.CGROUP_SYSTEM] = {}
    cpuwait[pc.CGROUP_USER] = {}
    cpuwait[pc.CGROUP_UTILS] = {}
    cpuwait[pc.CGROUP_INIT] = {}
    cpuwait[pc.CGROUP_K8SPLATFORM] = {}

    exclude_types = ['.mount']

    # Overall cpuacct usage
    acct = get_cgroup_cpuacct(CPUACCT, cpulist=obj.cpu_list)
    wait = get_cgroup_cpu_wait_sum(CPUACCT)
    cpuacct[pc.GROUP_OVERALL][pc.GROUP_TOTAL] = acct
    cpuwait[pc.GROUP_OVERALL][pc.GROUP_TOTAL] = wait

    # Initialize 'overhead' time (derived measurement). This will contain
    # the remaining cputime not specifically tracked by first-level cgroups.
    cpuacct[pc.GROUP_OVERALL][pc.GROUP_OVERHEAD] = acct
    cpuwait[pc.GROUP_OVERALL][pc.GROUP_OVERHEAD] = wait

    # Walk the first level cgroups and get cpuacct usage
    # (e.g., docker, k8s-infra, user.slice, system.slice, machine.slice)
    dir_list = next(os.walk(CPUACCT))[1]
    for name in dir_list:
        if any(name.endswith(x) for x in exclude_types):
            continue
        cg_path = '/'.join([CPUACCT, name])
        acct = get_cgroup_cpuacct(cg_path, cpulist=obj.cpu_list)
        wait = get_cgroup_cpu_wait_sum(cg_path)
        cpuacct[pc.GROUP_FIRST][name] = acct
        cpuwait[pc.GROUP_FIRST][name] = wait

        # Subtract out first-level cgroups. The remaining cputime represents
        # systemd 'init' pid and kthreads on Platform cpus.
        cpuacct[pc.GROUP_OVERALL][pc.GROUP_OVERHEAD] -= acct
        cpuwait[pc.GROUP_OVERALL][pc.GROUP_OVERHEAD] -= wait

    # Walk the system.slice cgroups and get cpuacct usage
    path = '/'.join([CPUACCT, pc.CGROUP_SYSTEM])
    dir_list = next(os.walk(path))[1]
    for name in dir_list:
        if any(name.endswith(x) for x in exclude_types):
            continue
        cg_path = '/'.join([path, name])
        acct = get_cgroup_cpuacct(cg_path, cpulist=obj.cpu_list)
        wait = get_cgroup_cpu_wait_sum(cg_path)
        cpuacct[pc.CGROUP_SYSTEM][name] = acct
        cpuwait[pc.CGROUP_SYSTEM][name] = wait

    # Walk the utils.slice cgroups and get cpuacct usage
    path = '/'.join([CPUACCT, pc.CGROUP_UTILS])
    dir_list = next(os.walk(path))[1]
    for name in dir_list:
        if any(name.endswith(x) for x in exclude_types):
            continue
        cg_path = '/'.join([path, name])
        acct = get_cgroup_cpuacct(cg_path, cpulist=obj.cpu_list)
        wait = get_cgroup_cpu_wait_sum(cg_path)
        cpuacct[pc.CGROUP_UTILS][name] = acct
        cpuwait[pc.CGROUP_UTILS][name] = wait

    # Walk the k8splatform.slice cgroups and get cpuacct usage
    path = '/'.join([CPUACCT, pc.CGROUP_K8SPLATFORM])
    if os.path.isdir(path):
        dir_list = next(os.walk(path))[1]
    else:
        dir_list = []
    for name in dir_list:
        if any(name.endswith(x) for x in exclude_types):
            continue
        cg_path = '/'.join([path, name])
        acct = get_cgroup_cpuacct(cg_path, cpulist=obj.cpu_list)
        wait = get_cgroup_cpu_wait_sum(cg_path)
        cpuacct[pc.CGROUP_K8SPLATFORM][name] = acct
        cpuwait[pc.CGROUP_K8SPLATFORM][name] = wait

    # Walk the user.slice cgroups and get cpuacct usage
    path = '/'.join([CPUACCT, pc.CGROUP_USER])
    dir_list = next(os.walk(path))[1]
    for name in dir_list:
        if any(name.endswith(x) for x in exclude_types):
            continue
        cg_path = '/'.join([path, name])
        acct = get_cgroup_cpuacct(cg_path, cpulist=obj.cpu_list)
        wait = get_cgroup_cpu_wait_sum(cg_path)
        cpuacct[pc.CGROUP_USER][name] = acct
        cpuwait[pc.CGROUP_USER][name] = wait

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
                        wait = get_cgroup_cpu_wait_sum(cg_path)
                        cpuacct[pc.GROUP_PODS][uid] = acct
                        cpuwait[pc.GROUP_PODS][uid] = wait
    return cpuacct, cpuwait


def calculate_occupancy(
        prefix, hires, dispatch,
        cache,
        t0, t1,
        w0, w1,
        t0_cpuacct, t1_cpuacct,
        t0_cpuwait, t1_cpuwait,
        occ, occw,
        elapsed_ms,
        number_platform_cpus,
        cpu_list, debug):
    """Calculate average occupancy and wait for platform cpus and cgroups.

    This calculates:
    - per-cpu cputime delta between time 0 and time 1 (ms)
    - per-cpu cpuwait delta between time 0 and time 1 (ms)
    - average platform occupancy based on cputime (%)
    - average platform occupancy wait based on cpuwait (%)
    - per-cgroup cpuacct delta between time 0 and time 1
    - per-cgroup cpuwait delta between time 0 and time 1
    - average per-cgroup occupancy based on cpuacct (%)
    - average per-cgroup occupancy wait based on cpuwait (%)
    - aggregate occupancy of specific cgroup groupings (%)
    - aggregate occupancy wait of specific cgroup groupings (%)

    This logs platform occupancy and aggregate cgroup groupings.
    This logs of hirunner occupancy for base cgroups.
    """

    # Aggregate cputime and cpuwait delta for platform logical cpus
    cputime_ms = 0.0
    cpuwait_ms = 0.0
    for cpu in cpu_list:
        # Paranoia check, we should never hit this.
        if cpu not in t0 or cpu not in w0:
            collectd.error('%s cputime initialization error' % (PLUGIN))
            break
        cputime_ms += float(t1[cpu] - t0[cpu])
        cpuwait_ms += float(w1[cpu] - w0[cpu])
    cputime_ms /= float(pc.ONE_MILLION)
    cpuwait_ms /= float(pc.ONE_MILLION)

    # Calculate average occupancy and wait of platform logical cpus
    p_occ = 0.0
    p_occw = 0.0
    if number_platform_cpus > 0 and elapsed_ms > 0:
        p_occ = float(pc.ONE_HUNDRED) * float(cputime_ms) \
            / float(elapsed_ms) / number_platform_cpus
        p_occw = float(pc.ONE_HUNDRED) * float(cpuwait_ms) \
            / float(elapsed_ms) / number_platform_cpus
    else:
        p_occ = 0.0
        p_occw = 0.0

    if debug:
        collectd.info('%s %s %s elapsed = %.1f ms, '
                      'cputime = %.1f ms, cpuwait = %.1f ms, '
                      'n_cpus = %d, '
                      'occupancy = %.2f %%, wait = %.2f %%'
                      % (PLUGIN_DEBUG,
                         prefix,
                         PLATFORM_CPU_PERCENT,
                         elapsed_ms,
                         cputime_ms, cpuwait_ms,
                         number_platform_cpus,
                         p_occ, p_occw))

    occ[PLATFORM_CPU_PERCENT] = p_occ
    occw[PLATFORM_CPU_PERCENT] = p_occw

    # Calculate cpuacct and cpuwait delta for cgroup hierarchy, dropping transient cgroups
    cpuacct = {}
    for i in t1_cpuacct.keys():
        cpuacct[i] = {}
        for k, v in t1_cpuacct[i].items():
            if i in t0_cpuacct.keys() and k in t0_cpuacct[i].keys():
                cpuacct[i][k] = v - t0_cpuacct[i][k]
            else:
                cpuacct[i][k] = v
    cpuwait = {}
    for i in t1_cpuwait.keys():
        cpuwait[i] = {}
        for k, v in t1_cpuwait[i].items():
            if i in t0_cpuwait.keys() and k in t0_cpuwait[i].keys():
                cpuwait[i][k] = v - t0_cpuwait[i][k]
            else:
                cpuwait[i][k] = v

    # Summarize cpuacct usage for various groupings we aggregate
    for g in pc.GROUPS_AGGREGATED:
        cpuacct[pc.GROUP_OVERALL][g] = 0.0
        cpuwait[pc.GROUP_OVERALL][g] = 0.0

    # Aggregate cpuacct usage by K8S pod
    for uid in cpuacct[pc.GROUP_PODS]:
        acct = cpuacct[pc.GROUP_PODS][uid]
        wait = cpuwait[pc.GROUP_PODS][uid]
        if uid in cache:
            pod = cache[uid]
        else:
            collectd.warning('%s uid %s not found' % (PLUGIN, uid))
            continue

        # K8S platform system usage, i.e., essential: kube-system
        # check for component label app.starlingx.io/component=platform
        if pod.is_platform_resource():
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_K8S_SYSTEM] += acct
            cpuwait[pc.GROUP_OVERALL][pc.GROUP_K8S_SYSTEM] += wait

        # K8S platform addons usage, i.e., non-essential: monitor, openstack
        if pod.namespace in pc.K8S_NAMESPACE_ADDON:
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_K8S_ADDON] += acct
            cpuwait[pc.GROUP_OVERALL][pc.GROUP_K8S_ADDON] += wait

    # Calculate base cpuacct usage (i.e., base tasks, exclude K8S and VMs)
    # e.g., docker, system.slice, user.slice, init.scope
    for name in cpuacct[pc.GROUP_FIRST].keys():
        if name in pc.BASE_GROUPS:
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_BASE] += \
                cpuacct[pc.GROUP_FIRST][name]
            cpuwait[pc.GROUP_OVERALL][pc.GROUP_BASE] += \
                cpuwait[pc.GROUP_FIRST][name]
        elif name not in pc.BASE_GROUPS_EXCLUDE:
            collectd.warning('%s could not find cgroup: %s' % (PLUGIN, name))

    # Calculate system.slice container cpuacct usage
    for g in pc.CONTAINERS_CGROUPS:
        if g in cpuacct[pc.CGROUP_SYSTEM].keys():
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_CONTAINERS] += \
                cpuacct[pc.CGROUP_SYSTEM][g]
            cpuwait[pc.GROUP_OVERALL][pc.GROUP_CONTAINERS] += \
                cpuwait[pc.CGROUP_SYSTEM][g]
        if g in cpuacct[pc.CGROUP_K8SPLATFORM].keys():
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_CONTAINERS] += \
                cpuacct[pc.CGROUP_K8SPLATFORM][g]
            cpuwait[pc.GROUP_OVERALL][pc.GROUP_CONTAINERS] += \
                cpuwait[pc.CGROUP_K8SPLATFORM][g]
        if g in cpuacct[pc.CGROUP_UTILS].keys():
            cpuacct[pc.GROUP_OVERALL][pc.GROUP_CONTAINERS] += \
                cpuacct[pc.CGROUP_UTILS][g]
            cpuwait[pc.GROUP_OVERALL][pc.GROUP_CONTAINERS] += \
                cpuwait[pc.CGROUP_UTILS][g]

    # Calculate platform cpuacct usage (this excludes apps)
    for g in pc.PLATFORM_GROUPS:
        cpuacct[pc.GROUP_OVERALL][pc.GROUP_PLATFORM] += \
            cpuacct[pc.GROUP_OVERALL][g]
        cpuwait[pc.GROUP_OVERALL][pc.GROUP_PLATFORM] += \
            cpuwait[pc.GROUP_OVERALL][g]

    # Calculate cgroup based occupancy and wait for overall groupings
    for g in pc.OVERALL_GROUPS:
        cputime_ms = \
            float(cpuacct[pc.GROUP_OVERALL][g]) / float(pc.ONE_MILLION)
        g_occ = float(pc.ONE_HUNDRED) * float(cputime_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occ[g] = g_occ
        cpuwait_ms = \
            float(cpuwait[pc.GROUP_OVERALL][g]) / float(pc.ONE_MILLION)
        g_occw = float(pc.ONE_HUNDRED) * float(cpuwait_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occw[g] = g_occw
        if obj.debug:
            collectd.info('%s %s %s elapsed = %.1f ms, '
                          'cputime = %.1f ms, cpuwait = %.1f ms, '
                          'n_cpus = %d, '
                          'occupancy = %.2f %%, wait = %.2f %%'
                          % (PLUGIN_DEBUG,
                             prefix,
                             g,
                             elapsed_ms,
                             cputime_ms, cpuwait_ms,
                             number_platform_cpus,
                             g_occ, g_occ))

    # Store occupancy hirunners
    h_occ = {}
    h_occw = {}

    # Calculate cgroup based occupancy for first-level groupings
    for g in cpuacct[pc.GROUP_FIRST]:
        cputime_ms = \
            float(cpuacct[pc.GROUP_FIRST][g]) / float(pc.ONE_MILLION)
        g_occ = float(pc.ONE_HUNDRED) * float(cputime_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occ[g] = g_occ
        cpuwait_ms = \
            float(cpuwait[pc.GROUP_FIRST][g]) / float(pc.ONE_MILLION)
        g_occw = float(pc.ONE_HUNDRED) * float(cpuwait_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occw[g] = g_occw

        if g != pc.CGROUP_INIT:
            continue

        # Keep hirunners exceeding minimum threshold.
        if g_occ >= HIRUNNER_MINIMUM_CPU_PERCENT:
            h_occ[g] = g_occ
        if g_occw >= HIRUNNER_MINIMUM_CPU_PERCENT:
            h_occw[g] = g_occw

    # Calculate cgroup based occupancy for cgroups within system.slice.
    for g in cpuacct[pc.CGROUP_SYSTEM]:
        cputime_ms = \
            float(cpuacct[pc.CGROUP_SYSTEM][g]) / float(pc.ONE_MILLION)
        g_occ = float(pc.ONE_HUNDRED) * float(cputime_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occ[g] = g_occ
        cpuwait_ms = \
            float(cpuwait[pc.CGROUP_SYSTEM][g]) / float(pc.ONE_MILLION)
        g_occw = float(pc.ONE_HUNDRED) * float(cpuwait_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occw[g] = g_occw

        # Keep hirunners exceeding minimum threshold.
        if g_occ >= HIRUNNER_MINIMUM_CPU_PERCENT:
            h_occ[g] = g_occ
        if g_occw >= HIRUNNER_MINIMUM_CPU_PERCENT:
            h_occw[g] = g_occw

    # Calculate cgroup based occupancy for cgroups within k8splatform.slice.
    if pc.CGROUP_K8SPLATFORM in cpuacct.keys():
        for g in cpuacct[pc.CGROUP_K8SPLATFORM]:
            cputime_ms = \
                float(cpuacct[pc.CGROUP_K8SPLATFORM][g]) / float(pc.ONE_MILLION)
            g_occ = float(pc.ONE_HUNDRED) * float(cputime_ms) \
                / float(elapsed_ms) / number_platform_cpus
            occ[g] = g_occ
            cpuwait_ms = \
                float(cpuwait[pc.CGROUP_K8SPLATFORM][g]) / float(pc.ONE_MILLION)
            g_occw = float(pc.ONE_HUNDRED) * float(cpuwait_ms) \
                / float(elapsed_ms) / number_platform_cpus
            occw[g] = g_occw

            # Keep hirunners exceeding minimum threshold.
            if g_occ >= HIRUNNER_MINIMUM_CPU_PERCENT:
                h_occ[g] = g_occ
            if g_occw >= HIRUNNER_MINIMUM_CPU_PERCENT:
                h_occw[g] = g_occw

    # Calculate cgroup based occupancy for cgroups within user.slice.
    for g in cpuacct[pc.CGROUP_USER]:
        cputime_ms = \
            float(cpuacct[pc.CGROUP_USER][g]) / float(pc.ONE_MILLION)
        g_occ = float(pc.ONE_HUNDRED) * float(cputime_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occ[g] = g_occ
        cpuwait_ms = \
            float(cpuwait[pc.CGROUP_USER][g]) / float(pc.ONE_MILLION)
        g_occw = float(pc.ONE_HUNDRED) * float(cpuwait_ms) \
            / float(elapsed_ms) / number_platform_cpus
        occw[g] = g_occw

        # Keep hirunners exceeding minimum threshold.
        if g_occ >= HIRUNNER_MINIMUM_CPU_PERCENT:
            h_occ[g] = g_occ
        if g_occw >= HIRUNNER_MINIMUM_CPU_PERCENT:
            h_occw[g] = g_occw

    # Calculate cgroup based occupancy for cgroups within utils.slice.
    if pc.CGROUP_UTILS in cpuacct.keys():
        for g in cpuacct[pc.CGROUP_UTILS]:
            cputime_ms = \
                float(cpuacct[pc.CGROUP_UTILS][g]) / float(pc.ONE_MILLION)
            g_occ = float(pc.ONE_HUNDRED) * float(cputime_ms) \
                / float(elapsed_ms) / number_platform_cpus
            occ[g] = g_occ
            cpuwait_ms = \
                float(cpuwait[pc.CGROUP_UTILS][g]) / float(pc.ONE_MILLION)
            g_occw = float(pc.ONE_HUNDRED) * float(cpuwait_ms) \
                / float(elapsed_ms) / number_platform_cpus
            occw[g] = g_occw

            # Keep hirunners exceeding minimum threshold.
            if g_occ >= HIRUNNER_MINIMUM_CPU_PERCENT:
                h_occ[g] = g_occ
            if g_occw >= HIRUNNER_MINIMUM_CPU_PERCENT:
                h_occw[g] = g_occw

    if (hires and prefix == 'hires') or (dispatch and prefix == 'dispatch'):
        # Print cpu occupancy usage for high-level groupings
        collectd.info('%s %s Usage: %.1f%% (avg per cpu); '
                      'cpus: %d, Platform: %.1f%% '
                      '(Base: %.1f, k8s-system: %.1f), k8s-addon: %.1f, '
                      '%s: %.1f, %s: %.1f'
                      % (PLUGIN, prefix,
                         occ[PLATFORM_CPU_PERCENT],
                         number_platform_cpus,
                         occ[pc.GROUP_PLATFORM],
                         occ[pc.GROUP_BASE],
                         occ[pc.GROUP_K8S_SYSTEM],
                         occ[pc.GROUP_K8S_ADDON],
                         pc.GROUP_CONTAINERS,
                         occ[pc.GROUP_CONTAINERS],
                         pc.GROUP_OVERHEAD,
                         occ[pc.GROUP_OVERHEAD]))

        # Print hirunner cpu occupancy usage for base cgroups
        occs = ', '.join(
            '{}: {:.1f}'.format(k.split('.', 1)[0], v) for k, v in sorted(
                h_occ.items(), key=lambda t: -float(t[1]))
        )
        collectd.info('%s %s %s: %.1f%%; cpus: %d, (%s)'
                      % (PLUGIN,
                         prefix, 'Base usage',
                         occ[pc.GROUP_BASE],
                         number_platform_cpus,
                         occs))

        # Print hirunner cpu wait for base cgroups
        occws = ', '.join(
            '{}: {:.1f}'.format(k.split('.', 1)[0], v) for k, v in sorted(
                h_occw.items(), key=lambda t: -float(t[1]))
        )
        collectd.info('%s %s %s: %.1f%%; cpus: %d, (%s)'
                      % (PLUGIN,
                         prefix, 'Base wait',
                         occw[pc.GROUP_BASE],
                         number_platform_cpus,
                         occws))


def aggregate_histogram(histogram, occ, shared_bins, hist_occ, debug):
    """Aggregate occupancy histogram bins for platform cpus and cgroups.

    This aggregates occupancy histogram bins for each key measurement.

    When 'histogram' flag is True, this will:
    - calculate mean, 95th-percentime, and max statistics, and bins
      the measurements
    - log histograms and statistics per measurement in hirunner order
    """

    # Aggregate each key, value into histogram bins
    for k, v in occ.items():
        # Get abbreviated name (excludes: .service, .scope, .socket, .mount)
        # eg, 'k8splatform.slice' will shorten to 'k8splatform'
        key = k.split('.', 1)[0]
        if key not in hist_occ:
            hist_occ[key] = np.array([], dtype=np.float64)
        if v is not None:
            hist_occ[key] = np.append(hist_occ[key], v)

    if histogram:
        # Calculate histograms and statistics for each key measurement
        H = {}
        for k, v in hist_occ.items():
            H[k] = {}
            H[k]['count'] = hist_occ[k].size
            if H[k]['count'] > 0:
                H[k]['mean'] = np.mean(hist_occ[k])
                H[k]['p95'] = np.percentile(hist_occ[k], 95)
                H[k]['pmax'] = np.max(hist_occ[k])
                H[k]['hist'], _ = np.histogram(hist_occ[k], bins=shared_bins)
            else:
                H[k]['mean'] = 0
                H[k]['p95'] = 0.0
                H[k]['pmax'] = 0.0
                H[k]['hist'] = []

        # Print out each histogram, sort by cpu occupancy hirunners
        bins = ' '.join('{:4d}'.format(int(x)) for x in shared_bins[1:])
        collectd.info('%s: %26.26s : bins=[%s]'
                      % (PLUGIN_HISTOGRAM, 'component', bins))
        for k, v in sorted(H.items(), key=lambda t: -float(t[1]['mean'])):
            if v['mean'] > HIRUNNER_MINIMUM_CPU_PERCENT:
                collectd.info('%s: %26.26s : hist=%s : cnt: %3d, '
                              'mean: %5.1f %%, p95: %5.1f %%, max: %5.1f %%'
                              % (PLUGIN_HISTOGRAM, k, v['hist'], v['count'],
                                 v['mean'], v['p95'], v['pmax']))


def update_cpu_data(init=False):
    """Gather cputime info and Update platform cpu occupancy metrics.

    This gathers current per-cpu cputime information from schedstats
    and per-cgroup cputime information from cgroup cpuacct.

    This calculates the average cpu occupancy of the platform cores
    since this routine was last run.
    """

    global obj

    # Get epoch time in floating seconds
    now = time.time()

    # Calculate elapsed time delta since last run
    obj.elapsed_ms = float(pc.ONE_THOUSAND) * (now - obj._t0[TIMESTAMP])
    obj.d_elapsed_ms = float(pc.ONE_THOUSAND) * (now - obj.d_t0[TIMESTAMP])
    obj.hist_elapsed_ms = float(pc.ONE_THOUSAND) * (now - obj.hist_t0)

    # Prevent calling this routine too frequently (<= 1 sec)
    if not init and obj.elapsed_ms <= 1000.0:
        return

    # Check whether this is a dispatch interval
    if obj.d_elapsed_ms >= 1000.0 * PLUGIN_DISPATCH_INTERVAL:
        obj.dispatch = True

    # Check whether this is a histogram interval
    if obj.hist_elapsed_ms >= 1000.0 * PLUGIN_HISTOGRAM_INTERVAL:
        obj.histogram = True

    t1 = {}
    w1 = {}
    t1[TIMESTAMP] = now
    w1[TIMESTAMP] = now
    if obj.schedstat_supported:
        # Get current per-cpu cumulative cputime usage from /proc/schedstat.
        cputime, cpuwait = read_schedstat()
        for cpu in obj.cpu_list:
            t1[cpu] = cputime[cpu]
            w1[cpu] = cpuwait[cpu]
    else:
        return

    # Get current cpuacct usages and wait_sum based on cgroup hierarchy
    t1_cpuacct, t1_cpuwait = get_cpuacct()

    # Refresh the k8s pod information if we have discovered new cgroups
    cg_pods = set(t1_cpuacct[pc.GROUP_PODS].keys())
    obj = pc.pods_monitoring(cg_pods, obj, PLUGIN_DEBUG)

    # Save initial state information
    if init:
        obj.d_t0 = copy.deepcopy(t1)
        obj.d_w0 = copy.deepcopy(w1)
        obj.d_t0_cpuacct = copy.deepcopy(t1_cpuacct)
        obj.d_t0_cpuwait = copy.deepcopy(t1_cpuwait)

        obj._t0 = copy.deepcopy(t1)
        obj._w0 = copy.deepcopy(w1)
        obj._t0_cpuacct = copy.deepcopy(t1_cpuacct)
        obj._t0_cpuwait = copy.deepcopy(t1_cpuwait)
        return

    # Calculate average cpu occupancy for hi-resolution read sample
    prefix = 'hires'
    calculate_occupancy(
        prefix, obj.hires, obj.dispatch,
        obj._cache,
        obj._t0, t1,
        obj._w0, w1,
        obj._t0_cpuacct, t1_cpuacct,
        obj._t0_cpuwait, t1_cpuwait,
        obj._occ, obj._occw,
        obj.elapsed_ms,
        obj.number_platform_cpus,
        obj.cpu_list,
        obj.debug)

    # Aggregate occupancy histogram bins
    aggregate_histogram(
        obj.histogram, obj._occ, obj.shared_bins, obj.hist_occ, obj.debug)

    # Clear histogram data for next interval
    if obj.histogram:
        obj.histogram = False
        obj.hist_occ = {}
        obj.hist_t0 = now

    # Calculate average cpu occupancy for dispatch interval
    if obj.dispatch:
        prefix = 'dispatch'
        calculate_occupancy(
            prefix, obj.hires, obj.dispatch,
            obj._cache,
            obj.d_t0, t1,
            obj.d_w0, w1,
            obj.d_t0_cpuacct, t1_cpuacct,
            obj.d_t0_cpuwait, t1_cpuwait,
            obj.d_occ, obj.d_occw,
            obj.d_elapsed_ms,
            obj.number_platform_cpus,
            obj.cpu_list,
            obj.debug)

    # Update t0 state for the next sample collection
    obj._t0 = copy.deepcopy(t1)
    obj._w0 = copy.deepcopy(w1)
    obj._t0_cpuacct = copy.deepcopy(t1_cpuacct)
    obj._t0_cpuwait = copy.deepcopy(t1_cpuwait)
    if obj.dispatch:
        obj.d_t0 = copy.deepcopy(t1)
        obj.d_w0 = copy.deepcopy(w1)
        obj.d_t0_cpuacct = copy.deepcopy(t1_cpuacct)
        obj.d_t0_cpuwait = copy.deepcopy(t1_cpuwait)


def config_func(config):
    """Configure the cpu usage plugin."""

    for node in config.children:
        key = node.key.lower()
        val = node.values[0]
        if key == 'debug':
            obj.debug = pc.convert2boolean(val)
        elif key == 'verbose':
            obj.verbose = pc.convert2boolean(val)
        elif key == 'hires':
            obj.hires = pc.convert2boolean(val)

    collectd.info('%s debug=%s, verbose=%s, hires=%s'
                  % (PLUGIN, obj.debug, obj.verbose, obj.hires))

    return pc.PLUGIN_PASS


# Get the platform cpu list and number of cpus reported by /proc/cpuinfo
def init_func():
    """Init the plugin."""

    # do nothing till config is complete.
    if obj.config_complete() is False:
        return pc.PLUGIN_PASS

    if obj._node_ready is False:
        obj.node_ready()
        return pc.PLUGIN_PASS

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
        return pc.PLUGIN_PASS

    # epoch time in floating seconds
    now0 = time.time()

    if not obj.schedstat_supported:
        return pc.PLUGIN_FAIL

    if not obj.cpu_list:
        collectd.info('%s no cpus to monitor' % PLUGIN)
        return pc.PLUGIN_PASS

    # Gather current cputime state information, and calculate occupancy
    # since this routine was last run.
    update_cpu_data()

    # Prevent dispatching measurements at plugin startup
    if obj.elapsed_ms <= 500.0:
        return pc.PLUGIN_PASS

    # Fault insertion code to assis in regression UT
    #
    # if os.path.exists('/var/run/fit/cpu_data'):
    #     with open('/var/run/fit/cpu_data', 'r') as infile:
    #         for line in infile:
    #             obj._occ[PLATFORM_CPU_PERCENT] = float(line)
    #             collectd.info("%s using FIT data:%.2f" %
    #                           (PLUGIN, obj._occ[PLATFORM_CPU_PERCENT] ))
    #             break

    if obj.dispatch:
        # Dispatch overall platform cpu usage percent value
        val = collectd.Values(host=obj.hostname)
        val.plugin = 'cpu'
        val.type = 'percent'
        val.type_instance = 'used'
        val.dispatch(values=[obj.d_occ[PLATFORM_CPU_PERCENT]])

        # Dispatch grouped platform cpu usage values
        val = collectd.Values(host=obj.hostname)
        val.plugin = 'cpu'
        val.type = 'percent'
        val.type_instance = 'occupancy'
        for g in pc.OVERALL_GROUPS:
            val.plugin_instance = g
            val.dispatch(values=[obj.d_occ[g]])
        obj.dispatch = False

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
collectd.register_read(read_func, interval=PLUGIN_HIRES_INTERVAL)
