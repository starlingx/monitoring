#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
This tool gathers cpuset usage information for all kubernetes containers
that are running on the current host.

With kubernetes CPUManager policy 'none', the k8s-infra cpuset is used for
all pods. For policy 'static', pods get an exclusive cpuset in the case of
QoS Guaranteed or using isolcpus, otherwise pods inherit DefaultCPUSet.

This displays the cpusets per container and the mapping to numa nodes.
This displays the aggregate cpuset usage per system-level groupings
(i.e., platform, isolated, guaranteed, default), per numa-node.

Usage: kube-cpusets [-h] [--debug]
"""

import argparse
import itertools as it
import json
import logging
import logging.handlers
import os
import re
import socket
import subprocess
import sys

import prettytable

# Constants
statefile = '/var/lib/kubelet/cpu_manager_state'
platformconf = '/etc/platform/platform.conf'
reservedfile = '/etc/platform/worker_reserved.conf'

LOG = logging.getLogger(__name__)


def format_range_set(items):
    """Generate a pretty-printed value of ranges from a set of integers.

       e.g., given a set or list of integers, format as '3-6,8-9,12-17'
    """
    ranges = []
    for _, iterable in it.groupby(enumerate(sorted(items)),
                                  lambda x: x[1] - x[0]):
        rng = list(iterable)
        if len(rng) == 1:
            s = str(rng[0][1])
        else:
            s = "%s-%s" % (rng[0][1], rng[-1][1])
        ranges.append(s)
    return ','.join(ranges)


def range_to_list(csv_range=None):
    """Convert a string of comma separate ranges into an expanded list.

       e.g., '1-3,8-9,15' is converted to [1,2,3,8,9,15]
    """
    if not csv_range:
        return []
    ranges = [(lambda L: range(L[0], L[-1] + 1))(map(int, r.split('-')))
              for r in csv_range.split(',')]
    return [y for x in ranges for y in x]


def cpuset_from_cpulist_file(filename):
    """Read cpulist file and convert to set of integers.

       File containing comma separated ranges is converted to an expanded set
       of integers. e.g., '1-3,8-9,15' is converted to set([1,2,3,8,9,15])
    """
    cpuset_str = None
    try:
        with open(filename, 'r') as f:
            cpuset_str = f.readline().strip()
    except Exception as e:
        LOG.error('Cannot parse file:%s, error=%s', filename, e)
    cpuset = set(range_to_list(csv_range=cpuset_str))
    return cpuset


def get_isolated_cpuset():
    """Get isolated cpuset from sys devices.

       Reads sys devices isolated cpu file containing comma separated ranges
       and convert to an expanded set of integers.
    """
    filename = '/sys/devices/system/cpu/isolated'
    cpuset = cpuset_from_cpulist_file(filename)
    return cpuset


def get_online_cpuset():
    """Get online cpuset from sys devices.

       Reads sys devices online cpu file containing comma separated ranges
       and convert to an expanded set of integers.
    """
    filename = '/sys/devices/system/cpu/online'
    cpuset = cpuset_from_cpulist_file(filename)
    return cpuset


def get_k8sinfra_cpuset():
    """Get cgroup k8s-infra cpuset from sys fs cgroup.

       Reads sys fs cgroup k8s-infra cpuset.cpus file containing comma
       separated ranges and convert to an expanded set of integers.
    """
    filename = '/sys/fs/cgroup/cpuset/k8s-infra/cpuset.cpus'
    cpuset = cpuset_from_cpulist_file(filename)
    return cpuset


def get_node_cpusets():
    """Get cpusets per numa node from sys devices.

       Returns a list of nodes with the set of integers per numa node.
    """
    nodepath = '/sys/devices/system/node'
    re_node = re.compile(r'^node(\d+)$')
    nodes = {}
    if os.path.isdir(nodepath):
        for d in os.listdir(nodepath):
            match = re_node.search(d)
            if match:
                node = int(match.group(1))
                filename = nodepath + '/node' + str(node) + '/cpulist'
                cpuset = set()
                if os.path.isfile(filename):
                    cpuset = cpuset_from_cpulist_file(filename)
                nodes[node] = cpuset
    return nodes


def gather_info_and_display():
    """Gather cpuset information for all kubernetes containers.

       Display the cpuset per container and the mapping to numa nodes.
       Display the aggregate cpuset usage per system-level groupings,
       per-numa node.
    """
    hostname = socket.gethostname()

    # Read current host cpusets from sysfs
    node_cpusets = get_node_cpusets()
    isolated_cpuset = get_isolated_cpuset()
    online_cpuset = get_online_cpuset()
    k8sinfra_cpuset = get_k8sinfra_cpuset()
    LOG.debug('node_cpusets = %r', node_cpusets)
    LOG.debug('isolated_cpuset = %r', isolated_cpuset)
    LOG.debug('online_cpuset = %r', online_cpuset)
    LOG.debug('k8sinfra_cpuset = %r', k8sinfra_cpuset)

    # Obtain platform node configuration
    re_keyval = re.compile(r'^(\S+)\s*=\s*(\S+)')
    platconf = {}
    try:
        with open(platformconf, 'r') as f:
            for line in f:
                m = re.search(re_keyval, line)
                if m:
                    key = m.group(1)
                    value = m.group(2)
                    platconf[key] = value
    except Exception as e:
        LOG.error('Could not parse: %s, error: %s.', platformconf, e)
        return 1
    nodetype = platconf.get('nodetype')
    subfunction = platconf.get('subfunction')
    system_type = platconf.get('system_type')

    # Obtain platform cpuset for worker node, as configured by sysinv/puppet.
    re_platform = re.compile(r'^PLATFORM_CPU_LIST\s*=\s*\"(\S+)\"')
    if 'worker' in subfunction:
        cpulist_str = None
        try:
            with open(reservedfile, 'r') as f:
                for line in f:
                    m = re.search(re_platform, line)
                    if m:
                        cpulist_str = m.group(1)
        except Exception as e:
            LOG.error('Could not parse: %s, error: %s.', reservedfile, e)
        platform_cpuset = set(range_to_list(csv_range=cpulist_str))
    else:
        platform_cpuset = online_cpuset - isolated_cpuset
    LOG.debug('platform_cpuset = %r', platform_cpuset)

    # Read cpusets from kubelet cpumanager JSON state file dictionary
    state = {}
    try:
        with open(statefile, 'r') as f:
            state = json.load(f)
    except Exception as e:
        LOG.error('Could not load: %s, error: %s.', statefile, e)
        return 1
    LOG.debug('cpu-manager state = %r', state)

    # Obtain cpu-manager policy
    policy = str(state['policyName'])

    # Print tool header line
    LOG.info('host:%s, system_type=%s, nodetype=%s, subfunction=%s, '
             'cpumanager_policy=%s',
             hostname, system_type, nodetype, subfunction, policy)

    # Determine default cpu-manager cpuset
    if 'defaultCpuSet' not in state:
        LOG.error('Missing defaultCpuSet in %s', statefile)
        return 1
    default_cpuranges = str(state['defaultCpuSet'])
    default_cpuset = set(range_to_list(csv_range=default_cpuranges))
    LOG.debug('default_cpuset = %r', default_cpuset)

    # Determine aggregate of cpumanager static allocations,
    # i.e., this contains: platform, guaranteed, isolated .
    static_cpuset = set()
    if 'entries' in state:
        for _, dcpus in state['entries'].items():
            for cpus in [str(i) for i in dcpus.values()]:
                cpulist = set(range_to_list(csv_range=cpus))
                static_cpuset.update(cpulist)

    # Determine guaranteed cpuset
    guaranteed_cpuset = static_cpuset - platform_cpuset - isolated_cpuset
    LOG.debug('guaranteed_cpuset = %r', guaranteed_cpuset)

    # Determine isolated cpuset
    isolated_used_cpuset = static_cpuset.intersection(isolated_cpuset)
    isolated_free_cpuset = isolated_cpuset - isolated_used_cpuset

    # Get list of containers on this host
    cmd = ['crictl', 'ps', '--output=json']
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        LOG.debug('command: %s\n%s', ' '.join(cmd), output)
    except subprocess.CalledProcessError as e:
        LOG.error('Could not list containers, error=%s', e)
        return 1

    pt = prettytable.PrettyTable(
        ['namespace',
         'pod.name',
         'container.name',
         'container.id',
         'state',
         'QoS',
         'shares',
         'group',
         'cpus',
         ], caching=False)
    pt.align = 'l'
    pt.align['shares'] = 'r'

    # Gather data for each container
    J = json.loads(output)

    containers = {}
    for cont in J['containers']:
        containers[cont['id']] = {
            'name': cont['metadata']['name'],
            'pod.name': cont['labels']['io.kubernetes.pod.name'],
            'cont.name': cont['labels']['io.kubernetes.container.name'],
            'namespace': cont['labels']['io.kubernetes.pod.namespace'],
            'state': cont['state'],
        }
    for cid, C in sorted(containers.items(),
                         key=lambda kv: (kv[1]['namespace'],
                                         kv[1]['name'],
                                         kv[1]['cont.name'])):
        cid_short = cid[0:13]
        pname = C['pod.name']
        cname = C['cont.name']
        namespace = C['namespace']
        cstate = C['state']

        # Now that we have the container ids, get more detailed resource info
        cmd = ['crictl', 'inspect', '--output=json', cid]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            LOG.debug('command: %s\n%s', ' '.join(cmd), output)
        except subprocess.CalledProcessError as e:
            LOG.error('Could not get container %s, error=%s', cid, e)
            return 1

        inspect = json.loads(output)
        linux = inspect['info']['runtimeSpec']['linux']
        cgroupsPath = linux['cgroupsPath']
        resources = linux['resources']
        cpu = resources['cpu']
        shares = cpu.get('shares', '-')
        cpus = cpu.get('cpus')
        cpuset = set(range_to_list(csv_range=cpus))
        if not cpuset:
            cpuset = k8sinfra_cpuset

        # Determine pod QoS
        if 'besteffort' in cgroupsPath:
            QoS = 'besteffort'
        elif 'burstable' in cgroupsPath:
            QoS = 'burstable'
        else:
            QoS = 'guaranteed'

        # Determine cpuset group mapping
        if cpus is None:
            group = 'k8s-infra'
        else:
            if cpuset.issubset(platform_cpuset):
                group = 'platform'
            elif cpuset.issubset(isolated_cpuset):
                group = 'isolated'
            elif cpuset.issubset(guaranteed_cpuset):
                group = 'guaranteed'
            elif cpuset.issubset(default_cpuset):
                group = 'default'
            else:
                group = 'unknown'

        # Determine per-numa node mapping of the container cpuset
        per_node = []
        for node, node_cpuset in sorted(node_cpusets.items(),
                                        key=lambda kv: kv[0]):
            # calculate subset of cpus for the given numa node
            n_cpuset = cpuset.intersection(node_cpuset)
            if n_cpuset:
                cpuranges = format_range_set(n_cpuset)
                per_node.append('node {} {}'.format(node, cpuranges))
        per_node_cpus = '; '.join(per_node)

        pt.add_row(
            [namespace,
             pname,
             cname,
             cid_short,
             cstate,
             QoS,
             shares,
             group,
             per_node_cpus or '-',
             ])

    # Display overall cpusets summary per numa node
    pt0 = prettytable.PrettyTable(
        ['Node',
         'Total',
         'Platform',
         'Isolated_used',
         'Isolated_free',
         'Guaranteed',
         'Default',
         ], caching=False)
    pt0.align = 'r'

    # Display total cpu resources per numa node
    pt1 = prettytable.PrettyTable(
        ['Node',
         'Total',
         'Platform',
         'Isolated_used',
         'Isolated_free',
         'Guaranteed',
         'Default',
         ], caching=False)
    pt1.align = 'r'

    for node, node_cpuset in sorted(node_cpusets.items(), key=lambda kv: kv[0]):
        # calculate subset of cpus for the given numa node
        node_platform = platform_cpuset.intersection(node_cpuset)
        node_default = default_cpuset.intersection(node_cpuset)
        node_guaranteed = guaranteed_cpuset.intersection(node_cpuset)
        node_isolated_used = isolated_used_cpuset.intersection(node_cpuset)
        node_isolated_free = isolated_free_cpuset.intersection(node_cpuset)

        # format cpusets as strings
        node_cpuranges = format_range_set(node_cpuset) or '-'
        platform_cpuranges = format_range_set(node_platform) or '-'
        default_cpuranges = format_range_set(node_default) or '-'
        guaranteed_cpuranges = format_range_set(node_guaranteed) or '-'
        isolated_used_cpuranges = format_range_set(node_isolated_used) or '-'
        isolated_free_cpuranges = format_range_set(node_isolated_free) or '-'

        # calculate overall usage and free
        node_used = len(node_cpuset)
        platform_used = len(node_platform)
        default_used = len(node_default)
        guaranteed_used = len(node_guaranteed)
        isolated_used = len(node_isolated_used)
        isolated_free = len(node_isolated_free)

        pt0.add_row(
            [node,
             node_cpuranges,
             platform_cpuranges,
             isolated_used_cpuranges,
             isolated_free_cpuranges,
             guaranteed_cpuranges,
             default_cpuranges,
             ])

        pt1.add_row(
            [node,
             node_used,
             platform_used,
             isolated_used,
             isolated_free,
             guaranteed_used,
             default_used,
             ])

    # Dump the tables out
    print('\nPer-container cpusets:')
    print(pt)

    print('\nLogical cpusets usage per numa node:')
    print(pt0)

    print('\nLogical cpus usage per numa node:')
    print(pt1)

    return 0


def main():
    """Main program."""

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Display kubernetes containers cpuset '
                    'usage per numa-node.')
    parser.add_argument('--debug',
                        action='store_true',
                        help='display debug info')
    args = parser.parse_args()

    # Configure logging
    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    out_hdlr = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '%(asctime)s %(process)s %(levelname)s %(module)s: %(message)s')
    out_hdlr.setFormatter(formatter)
    out_hdlr.setLevel(level)
    LOG.addHandler(out_hdlr)
    LOG.setLevel(level)

    # Limit access of this tool since some sysfs data requires root.
    if os.geteuid() != 0:
        LOG.error('Require sudo/root.')
        sys.exit(1)

    try:
        ret = gather_info_and_display()
        sys.exit(ret)

    except KeyboardInterrupt as e:
        LOG.info('caught: %r, shutting down', e)
        sys.exit(0)

    except IOError:
        sys.exit(0)

    except Exception as e:
        LOG.error('exception: %r', e, exc_info=1)
        sys.exit(-4)
