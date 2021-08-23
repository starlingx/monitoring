#
# Copyright (c) 2018-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
############################################################################
#
# This file is the collectd 'Platform Memory Usage' Monitor.
#
# This gathers the following memory metrics:
# - Platform memory usage in percent of platform reserved memory.
# - Platform Memory and breakdown (base, kube-system, kube-addon).
# - Overall 4K memory usage (anon, avail, total, and cgroup-rss).
# - Per-numa node 4K memory usage (anon, avail, total).
#
# Example commands to read samples from the influx database:
# SELECT * FROM memory_value WHERE type='percent' AND type_instance='used'
# SELECT * FROM memory_value WHERE type='absolute' AND type_instance='used'
#
############################################################################
import os
import collectd
import plugin_common as pc
import re
import socket
import time

from kubernetes.client.rest import ApiException

PLUGIN = 'platform memory usage'
PLUGIN_NORM = '4K memory usage'
PLUGIN_NUMA = '4K numa memory usage'
PLUGIN_DEBUG = 'DEBUG memory'

# Memory cgroup controller
MEMCONT = pc.CGROUP_ROOT + '/memory'
MEMORY_STAT = 'memory.stat'

# Linux memory
MEMINFO = '/proc/meminfo'
NODEINFO = '/sys/devices/system/node'
OVERCOMMIT = '/proc/sys/vm/overcommit_memory'

# Common regex pattern match groups
re_dict = re.compile(r'^(\w+)\s+(\d+)')
re_word = re.compile(r'^(\w+)')
re_uid = re.compile(r'^pod(\S+)')
re_blank = re.compile(r'^\s*$')
re_comment = re.compile(r'^\s*[#!]')
re_nonword = re.compile(r'^\s*\W')
re_keyval = re.compile(r'^\s*(\S+)\s*[=:]\s*(\d+)')
re_keyval_arr = re.compile(r'^\s*(\S+)\s*[=:]\s*\(\s*(.*)\s*\)')
re_nodekeyval = re.compile(r'^Node\s+(\d+)\s+(\S+)\s*[=:]\s*(\d+)')
re_base_mem = re.compile('\"node\d+:(\d+)MB:\d+\"')


# Plugin specific control class and object.
class MEM_object(pc.PluginObject):

    def __init__(self):
        super(MEM_object, self).__init__(PLUGIN, '')
        self.debug = False
        self.verbose = False
        self._cache = {}
        self._k8s_client = pc.K8sClient()
        self.k8s_pods = set()
        self.reserved_MiB = 0.0
        self.reserve_all = False
        self.strict_memory_accounting = False

        self.meminfo = {}
        self.meminfo_nodes = {}
        self.normal = {}
        self.normal_nodes = {}
        self.platform_memory_percent = 0.0

# Instantiate the class
obj = MEM_object()


def is_strict_memory_accounting():
    """Determine whether system is using strict memory accounting.

    Assume strict is True when value is 2.
    - value of 0 means 'heuristic overcommit'
    - value of 1 means 'always overcommit'
    - value of 2 means 'don't overcommit'
    NOTE: Default configurations use non-strict memory accounting.

    Returns True if using strict memory accounting.
    """

    strict = False

    try:
        with open(OVERCOMMIT, 'r') as infile:
            for line in infile:
                if int(line) == 2:
                    strict = True
                break
    except Exception as err:
        collectd.error('%s: Cannot determine strict accounting, error=%s'
                       % (PLUGIN, err))

    return strict


def get_platform_reserved_memory():
    """Get platform reserved memory MiB by parsing worker_reserved.conf file.

    This value is provided by puppet resource file which is populated
    via sysinv query.

    Returns total platform reserved MiB.
    Returns 0.0 if worker_reserved.conf does not exist.
    """

    reserved_MiB = 0.0

    # Match key=("value1" "value2" ...), a bash array of quoted strings.
    m = {}
    if os.path.exists(pc.RESERVED_CONF):
        try:
            with open(pc.RESERVED_CONF, 'r') as infile:
                for line in infile:
                    # skip lines we don't care about
                    match = re_blank.search(line)
                    if match:
                        continue
                    match = re_comment.search(line)
                    if match:
                        continue
                    match = re_nonword.search(line)
                    if match:
                        continue

                    # match key value array pairs
                    match = re_keyval_arr.search(line)
                    if match:
                        k = match.group(1)
                        v = match.group(2)
                        m[k] = v
        except Exception as err:
            collectd.error('%s: Cannot parse file, error=%s' % (PLUGIN, err))
            return 0.0

    # Parse and aggregate reserved memory from pattern like this:
    # WORKER_BASE_MEMORY=("node0:1500MB:1" "node1:1500MB:1")
    if pc.RESERVED_MEM_KEY in m:
        values = m.get(pc.RESERVED_MEM_KEY)
        nodes_MB = [int(x.group(1)) for x in re.finditer(re_base_mem, values)]
        if obj.debug:
            collectd.info('%s: %s elements = %r; nodes_MB = %r'
                          % (PLUGIN_DEBUG,
                             pc.RESERVED_MEM_KEY, values, nodes_MB))
        reserved_MiB = float(sum(x for x in nodes_MB))
    else:
        # This is not fatal. Assume reserved memory not defined.
        collectd.warning('%s: %s not found in file: %s'
                         % (PLUGIN,
                            pc.RESERVED_MEM_KEY, pc.RESERVED_CONF))

    return reserved_MiB


def get_cgroup_memory(path):
    """Get memory usage in MiB for a specific cgroup path.

    This represents the aggregate usage for child cgroups.

    Returns dictionary containing entries: 'rss_MiB', 'rss_huge_MiB'.
    """

    memory = {}

    fstat = '/'.join([path, MEMORY_STAT])
    m = {}
    try:
        with open(fstat, 'r') as fd:
            for line in fd:
                match = re_dict.search(line)
                if match:
                    k = match.group(1)
                    v = match.group(2)
                    m[k] = v
    except IOError:
        # Silently ignore IO errors. It is likely the cgroup disappeared.
        pass

    # Calculate RSS usage in MiB
    memory['rss_MiB'] = float(m.get('total_rss', 0)) / float(pc.Mi)

    return memory


def get_meminfo():
    """Get contents of /proc/meminfo.

    Returns dictionary containing each meminfo field integer.
    i.e., m[field]
    """

    m = {}
    try:
        with open(MEMINFO, 'r') as fd:
            for line in fd:
                match = re_keyval.search(line)
                if match:
                    k = match.group(1)
                    v = match.group(2)
                    m[k] = int(v)
    except IOError as err:
        collectd.error('%s: Cannot read meminfo, error=%s' % (PLUGIN, err))
        return m

    return m


def get_meminfo_nodes():
    """Get contents of /sys/devices/system/node/<nodex>/meminfo.

    Returns dictionary per numa node containing each meminfo field integer.
    i.e., m['nodeX'][field]
    """

    nodes = []
    for name in os.listdir(NODEINFO):
        if 'node' in name:
            nodes.append(name)

    m = {}
    for node in nodes:
        m[node] = {}
        meminfo = NODEINFO + '/' + node + '/meminfo'
        try:
            with open(meminfo, 'r') as fd:
                for line in fd:
                    match = re_nodekeyval.search(line)
                    if match:
                        n = match.group(1)
                        k = match.group(2)
                        v = match.group(3)
                        m[node][k] = int(v)
        except IOError as err:
            collectd.error('%s: Cannot read meminfo, error=%s'
                           % (PLUGIN, err))
            return m

    return m


def get_platform_memory():
    """Get memory usage based on cgroup hierarchy."""

    memory = {}
    memory[pc.GROUP_OVERALL] = {}
    memory[pc.GROUP_FIRST] = {}
    memory[pc.GROUP_PODS] = {}

    # Overall memory usage
    m = get_cgroup_memory(MEMCONT)
    memory[pc.GROUP_OVERALL][pc.GROUP_TOTAL] = m.get('rss_MiB', 0.0)

    # Walk the first level cgroups and get memory usage
    # (e.g., docker, k8s-infra, user.slice, system.slice, machine.slice)
    dir_list = next(os.walk(MEMCONT))[1]
    for name in dir_list:
        cg_path = '/'.join([MEMCONT, name])
        m = get_cgroup_memory(cg_path)
        memory[pc.GROUP_FIRST][name] = m.get('rss_MiB', 0.0)

    # Walk the kubepods hierarchy to the pod level and get memory usage.
    # We can safely ignore reading this if the path does not exist.
    # The path wont exist on non-K8S nodes. The path is created as part of
    # kubernetes configuration.
    path = '/'.join([MEMCONT, pc.K8S_ROOT, pc.KUBEPODS])
    if os.path.isdir(path):
        for root, dirs, files in pc.walklevel(path, level=1):
            for name in dirs:
                if name.startswith('pod') and MEMORY_STAT in files:
                    match = re_uid.search(name)
                    if match:
                        uid = match.group(1)
                        cg_path = os.path.join(root, name)
                        m = get_cgroup_memory(cg_path)
                        memory[pc.GROUP_PODS][uid] = m.get('rss_MiB', 0.0)
    return memory


def calc_normal_memory():
    """Calculate normal memory usage totals.

    Returns dictionary containing derived fields:
    'anon_MiB', 'avail_MiB', 'total_MiB', 'anon_percent'.
    i.e., normal[field]
    """

    anon_MiB = float(obj.meminfo['Active(anon)'] +
                     obj.meminfo['Inactive(anon)']) / float(pc.Ki)
    avail_MiB = float(obj.meminfo['MemAvailable']) / float(pc.Ki)
    total_MiB = float(anon_MiB + avail_MiB)

    if obj.strict_memory_accounting:
        anon_percent = float(pc.ONE_HUNDRED) \
            * float(obj.meminfo['Committed_AS']) \
            / float(obj.meminfo['CommitLimit'])
    else:
        if total_MiB > 0:
            anon_percent = float(pc.ONE_HUNDRED) * anon_MiB / total_MiB
        else:
            anon_percent = 0.0

    normal = {}
    normal['anon_MiB'] = anon_MiB
    normal['avail_MiB'] = avail_MiB
    normal['total_MiB'] = total_MiB
    normal['anon_percent'] = anon_percent

    return normal


def calc_normal_memory_nodes():
    """Calculate normal memory usage totals per-numa node.

    Returns dictionary containing derived fields:
    'anon_MiB', 'avail_MiB', 'total_MiB', 'anon_percent'.
    i.e., normal['nodeX'][field]
    """

    normal_nodes = {}
    for node, meminfo in obj.meminfo_nodes.items():
        normal_nodes[node] = {}
        anon_MiB = float(meminfo['Active(anon)'] +
                         meminfo['Inactive(anon)']) / float(pc.Ki)
        avail_MiB = float(meminfo['MemFree'] +
                          meminfo['FilePages'] +
                          meminfo['SReclaimable']) / float(pc.Ki)
        total_MiB = float(anon_MiB + avail_MiB)

        if total_MiB > 0:
            anon_percent = float(pc.ONE_HUNDRED) * anon_MiB / total_MiB
        else:
            anon_percent = 0.0

        normal_nodes[node]['anon_MiB'] = anon_MiB
        normal_nodes[node]['avail_MiB'] = avail_MiB
        normal_nodes[node]['total_MiB'] = total_MiB
        normal_nodes[node]['anon_percent'] = anon_percent

    return normal_nodes


def config_func(config):
    """Configure the memory usage plugin."""

    for node in config.children:
        key = node.key.lower()
        val = node.values[0]
        if key == 'debug':
            obj.debug = pc.convert2boolean(val)
        elif key == 'verbose':
            obj.verbose = pc.convert2boolean(val)

    collectd.info('%s: debug=%s, verbose=%s'
                  % (PLUGIN, obj.debug, obj.verbose))

    return pc.PLUGIN_PASS


# The memory plugin init function - called once on collectd process startup
def init_func():
    """Init the plugin."""

    # do nothing till config is complete.
    if obj.config_complete() is False:
        return 0

    # override node ready threshold for this plugin
    obj.node_ready_threshold = 1

    obj.hostname = socket.gethostname()
    collectd.info('%s: init function for %s' % (PLUGIN, obj.hostname))

    obj.strict_memory_accounting = is_strict_memory_accounting()
    collectd.info('%s: strict_memory_accounting: %s'
                  % (PLUGIN, obj.strict_memory_accounting))

    obj.reserved_MiB = get_platform_reserved_memory()
    if obj.reserved_MiB == 0.0:
        obj.reserve_all = True
    collectd.info('%s: reserve_all: %s, reserved_MiB: %d'
                  % (PLUGIN, obj.reserve_all, obj.reserved_MiB))

    obj.init_completed()
    return pc.PLUGIN_PASS


# The memory plugin read function - called every audit interval
def read_func():
    """collectd memory monitor plugin read function"""

    if obj.init_complete is False:
        init_func()
        return 0

    if obj._node_ready is False:
        obj.node_ready()
        return 0

    # Get epoch time in floating seconds
    now0 = time.time()

    # Calculate normal memory usage derived from meminfo
    obj.meminfo = get_meminfo()
    obj.meminfo_nodes = get_meminfo_nodes()
    obj.normal = calc_normal_memory()
    obj.normal_nodes = calc_normal_memory_nodes()
    if obj.reserve_all:
        obj.reserved_MiB = obj.normal['total_MiB']

    # Walk cgroup memory heirarchy to deduce usage breakdown
    memory = get_platform_memory()

    # Refresh the k8s pod information if we have discovered new cgroups
    cg_pods = set(memory[pc.GROUP_PODS].keys())
    if not cg_pods.issubset(obj.k8s_pods):
        if obj.debug:
            collectd.info('%s: Refresh k8s pod information.' % (PLUGIN_DEBUG))
        obj.k8s_pods = set()
        try:
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
                            collectd.info('%s: POD_ANNOTATION_KEY: '
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
        except ApiException:
            # continue with remainder of calculations, keeping cache
            collectd.warning("memory plugin encountered kube ApiException")
            pass

    # Summarize memory usage for various groupings
    for g in pc.OVERALL_GROUPS:
        memory[pc.GROUP_OVERALL][g] = 0.0

    # Aggregate memory usage by K8S pod
    for uid in memory[pc.GROUP_PODS]:
        MiB = memory[pc.GROUP_PODS][uid]
        if uid in obj._cache:
            pod = obj._cache[uid]
        else:
            collectd.warning('%s: uid %s not found' % (PLUGIN, uid))
            continue

        # K8S platform system usage, i.e., essential: kube-system
        if pod.namespace in pc.K8S_NAMESPACE_SYSTEM:
            memory[pc.GROUP_OVERALL][pc.GROUP_K8S_SYSTEM] += MiB

        # K8S platform addons usage, i.e., non-essential: monitor, openstack
        if pod.namespace in pc.K8S_NAMESPACE_ADDON:
            memory[pc.GROUP_OVERALL][pc.GROUP_K8S_ADDON] += MiB

    # Calculate base memory usage (i.e., normal memory, exclude K8S and VMs)
    # e.g., docker, system.slice, user.slice
    for name in memory[pc.GROUP_FIRST]:
        if name in pc.BASE_GROUPS:
            memory[pc.GROUP_OVERALL][pc.GROUP_BASE] += \
                memory[pc.GROUP_FIRST][name]
        elif name not in pc.BASE_GROUPS_EXCLUDE:
            collectd.warning('%s: could not find cgroup: %s' % (PLUGIN, name))

    # Calculate platform memory usage (this excludes apps)
    for g in pc.PLATFORM_GROUPS:
        memory[pc.GROUP_OVERALL][pc.GROUP_PLATFORM] += \
            memory[pc.GROUP_OVERALL][g]

    # Calculate platform memory in terms of percent reserved
    if obj.reserved_MiB > 0.0:
        obj.platform_memory_percent = float(pc.ONE_HUNDRED) \
            * float(memory[pc.GROUP_OVERALL][pc.GROUP_PLATFORM]) \
            / float(obj.reserved_MiB)
    else:
        obj.platform_memory_percent = 0.0

    # Dispatch overall platform usage percent value
    if obj.platform_memory_percent > 0.0:
        val = collectd.Values(host=obj.hostname)
        val.type = 'memory'
        val.type_instance = 'used'
        val.plugin = 'memory'
        val.plugin_instance = 'platform'
        val.dispatch(values=[obj.platform_memory_percent])

    # Dispatch grouped platform usage values
    val = collectd.Values(host=obj.hostname)
    val.type = 'absolute'
    val.type_instance = 'used'
    val.plugin = 'memory'
    val.plugin_instance = 'reserved'
    val.dispatch(values=[obj.reserved_MiB])
    for g, v in sorted(memory[pc.GROUP_OVERALL].items()):
        val.plugin_instance = g
        val.dispatch(values=[v])

    # Dispatch normal memory usage values derived from meminfo
    val = collectd.Values(host=obj.hostname)
    val.type = 'absolute'
    val.type_instance = 'used'
    val.plugin = 'memory'

    val.plugin_instance = 'anon'
    val.dispatch(values=[obj.normal['anon_MiB']])

    val.plugin_instance = 'avail'
    val.dispatch(values=[obj.normal['avail_MiB']])

    val.plugin_instance = 'total'
    val.dispatch(values=[obj.normal['total_MiB']])

    val = collectd.Values(host=obj.hostname)
    val.type = 'percent'
    val.type_instance = 'used'
    val.plugin = 'memory'
    val.plugin_instance = 'total'
    val.dispatch(values=[obj.normal['anon_percent']])

    # Dispatch per-numa normal memory usage values derived from meminfo
    for node in sorted(obj.normal_nodes.keys()):
        val = collectd.Values(host=obj.hostname)
        val.type = 'percent'
        val.type_instance = 'used'
        val.plugin = 'memory'
        val.plugin_instance = node
        val.dispatch(values=[obj.normal_nodes[node]['anon_percent']])

    # Display debug memory logs
    if obj.debug:
        # First-level cgroup memory summary
        first_level = ', '.join(
            "{0}: {1:.1f}".format(k, v)
            for k, v in sorted(memory[pc.GROUP_FIRST].items()))
        collectd.info('%s: First level cgroup (MiB): %s'
                      % (PLUGIN_DEBUG, first_level))

        # Meminfo parsed input
        pc.log_dictionary(
            plugin=PLUGIN_DEBUG, name='meminfo', d=obj.meminfo)
        pc.log_dictionary_nodes(
            plugin=PLUGIN_DEBUG, name='meminfo_nodes', d=obj.meminfo_nodes)

        # Derived calculations
        pc.log_dictionary(
            plugin=PLUGIN_DEBUG, name='normal', d=obj.normal)
        pc.log_dictionary_nodes(
            plugin=PLUGIN_DEBUG, name='normal_nodes', d=obj.normal_nodes)

    # Display verbose memory summary logs
    if obj.verbose:
        collectd.info('%s: Usage: %.1f%%; '
                      'Reserved: %.1f MiB, Platform: %.1f MiB '
                      '(Base: %.1f, k8s-system: %.1f), k8s-addon: %.1f'
                      % (PLUGIN, obj.platform_memory_percent,
                         obj.reserved_MiB,
                         memory[pc.GROUP_OVERALL][pc.GROUP_PLATFORM],
                         memory[pc.GROUP_OVERALL][pc.GROUP_BASE],
                         memory[pc.GROUP_OVERALL][pc.GROUP_K8S_SYSTEM],
                         memory[pc.GROUP_OVERALL][pc.GROUP_K8S_ADDON]))

        collectd.info('%s: Anon: %.1f%%, Anon: %.1f MiB, '
                      'cgroup-rss: %.1f MiB, '
                      'Avail: %.1f MiB, Total: %.1f MiB'
                      % (PLUGIN_NORM,
                         obj.normal['anon_percent'],
                         obj.normal['anon_MiB'],
                         memory[pc.GROUP_OVERALL][pc.GROUP_TOTAL],
                         obj.normal['avail_MiB'],
                         obj.normal['total_MiB']))
        for node in sorted(obj.normal_nodes.keys()):
            collectd.info('%s: %s, Anon: %.2f%%, Anon: %.1f MiB, '
                          'Avail: %.1f MiB, Total: %.1f MiB'
                          % (PLUGIN_NUMA, node,
                             obj.normal_nodes[node]['anon_percent'],
                             obj.normal_nodes[node]['anon_MiB'],
                             obj.normal_nodes[node]['avail_MiB'],
                             obj.normal_nodes[node]['total_MiB']))

    # Calculate overhead cost of gathering metrics
    if obj.debug:
        now = time.time()
        elapsed_ms = float(pc.ONE_THOUSAND) * (now - now0)
        collectd.info('%s: overhead sampling cost = %.3f ms'
                      % (PLUGIN_DEBUG, elapsed_ms))

    return pc.PLUGIN_PASS

# Register the config, init and read functions
collectd.register_config(config_func)
collectd.register_init(init_func)
collectd.register_read(read_func)
