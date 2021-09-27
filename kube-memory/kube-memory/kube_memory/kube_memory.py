#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
This tool gathers memory usage information for all kubernetes containers and
system services displayed in cgroup memory that are running on the current
host.

This displays the total resident set size per container.
This displays the aggregate memory usage per system service.

Usage: kube-memory [-h] [--debug]
"""

import argparse
import json
import logging
import math
import os
import re
import subprocess
import sys

import prettytable

# Constants
MEMINFO = '/proc/meminfo'
MEMPATH = '/sys/fs/cgroup/memory/'
BYTES_IN_MEBIBYTE = 1048576
KBYTE = 1024
DECIMAL_DIGITS = 2

MEMORY = {}
MEMORY['cgroups'] = {}
MEMORY['namespaces'] = {}

RESERVED_CONF = '/etc/platform/worker_reserved.conf'

BASE_GROUPS = ['docker', 'system.slice', 'user.slice']
K8S_NAMESPACE_SYSTEM = ['kube-system', 'armada', 'cert-manager', 'portieris',
                        'vault', 'notification', 'platform-deployment-manager']
K8S_NAMESPACE_ADDON = ['monitor', 'openstack']

# Used commands
AWK_CMD = ["awk", "$2>0{print$0}"]
GREP_CMD = ["grep", "-rs", "total_rss"]

# logger
LOG = logging.getLogger(__name__)


def py2_round(number, decimal=0):
    # This function will keep the behavior of py2 round method
    param = 10 ** decimal
    if number > 0:
        return float(math.floor((number * param) + 0.5)) / param  # pylint: disable=W1619
    return float(math.ceil((number * param) - 0.5)) / param  # pylint: disable=W1619


def mem_to_mebibytes(n_bytes):
    """Convert a string that represents memory in bytes into mebibytes(MiB)

       Output is displayed with precision of 3 decimal digits.
       e.g., '1829108992' is converted to 1744.374.
    """
    try:
        mebibytes = (float(n_bytes) / BYTES_IN_MEBIBYTE)  # pylint: disable=W1619
        return str(py2_round(mebibytes, DECIMAL_DIGITS))
    except (ValueError, TypeError):
        return "-"


def pid_from_container(container_id):
    """Get pid for a given a container id.

    """

    cmd = ['pgrep', '-f', container_id]
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        LOG.error('Could not get pid, error=%s', error)
        return 1


def get_memory_cgroups():
    """Get system-level service groups from cgroup memory

       Returns a list of each system service name.
    """
    groups = []
    for dirs in os.listdir(MEMPATH):
        if os.path.isdir(MEMPATH + dirs):
            groups.append(dirs)
    return groups


def get_meminfo():
    """Get contents of /proc/meminfo.

    Returns dictionary containing each meminfo field integer.
    i.e., m[field]
    """

    mem_info = {}
    re_keyval = re.compile(r'^\s*(\S+)\s*[=:]\s*(\d+)')
    try:
        with open(MEMINFO, 'r') as mem_file:
            for line in mem_file:
                match = re_keyval.search(line)
                if match:
                    keyfile = match.group(1)
                    val = match.group(2)
                    mem_info[keyfile] = int(val)
    except IOError as err:
        LOG.error('%s: Cannot read meminfo, error=%s',
                  'platform memory usage', err)
        return mem_info

    return mem_info


def get_platform_reserved_memory():
    """Get platform reserved memory MiB by parsing worker_reserved.conf file.

    This value is provided by puppet resource file which is populated
    via sysinv query.

    Returns total platform reserved MiB.
    Returns 0.0 if worker_reserved.conf does not exist.
    """
    re_keyval_arr = re.compile(
        r'^\s*WORKER_BASE_RESERVED\s*[=:]\s*\(\s*(.*)\s*\)')
    re_base_mem = re.compile(r'\"node\d+:(\d+)MB:\d+\"')
    reserved_mebib = 0.0

    # Match key=("value1" "value2" ... "valueN")
    reserved_str = None
    if os.path.exists(RESERVED_CONF):
        try:
            with open(RESERVED_CONF, 'r') as infile:
                for line in infile:
                    match = re_keyval_arr.search(line)
                    if match:
                        reserved_str = match.group(1)
        except Exception as err:
            LOG.error(
                '%s: Cannot parse file, error=%s',
                'platform memory usage', err)
            return 0.0

    # Parse and aggregate reserved memory from pattern like this:
    # WORKER_BASE_MEMORY=("node0:1500MB:1" "node1:1500MB:1")
    if reserved_str:
        nodes = [
            int(x.group(1)) for x in re.finditer(re_base_mem, reserved_str)]
        reserved_mebib = float(sum(x for x in nodes))
    return reserved_mebib


def pipe_command(*cmds, **kwargs):
    """Creates a shell pipeline and run command

    :param *cmds(list): Lists of commands to be executed
    :param **kwargs: cwd(str): Sets directory to execute subprocess.Popen()
    :returns (str): Final command output
    """
    cmd_list = []
    for cmd in cmds:
        cmd_list.append(cmd)

    last_popen = [subprocess.Popen(
        cmd_list[0], stdout=subprocess.PIPE, cwd=kwargs.pop("cwd", None))]

    for i in range(len(cmd_list) - 1):
        last_popen.append(subprocess.Popen(
            cmd_list[i + 1], stdin=last_popen[i].stdout,
            stdout=subprocess.PIPE))
        last_popen[i].stdout.close()
    return last_popen[-1].communicate()[0]


def gather_groups_memory(output_mem):
    """Obtain total rss displayed in memory.stat for each group.

    :param output_mem(str): Total rss output
    :returns (PrettyTable): Table with the final results.
    """
    groups = get_memory_cgroups()
    p_table = prettytable.PrettyTable(
        ['Group',
         'Resident Set Size (MiB)'
         ], caching=False)
    p_table.align = 'l'
    p_table.align['Resident Set Size (MiB)'] = 'r'

    # Get overall memory summary per group
    total_rss = 0.0
    for group in groups:
        for line in output_mem.split("\n"):
            if group + "/memory.stat" in line:
                total_rss += float(line.split()[1])
                rss_mem = mem_to_mebibytes(line.split()[1])
                MEMORY['cgroups'][group] = rss_mem
                p_table.add_row(
                    [group,
                     rss_mem or '-',
                     ])
                break

    # Add overall rss memory
    MEMORY['cgroups']['total_rss'] = mem_to_mebibytes(total_rss)
    p_table.add_row(
        ["Total cgroup-rss",
         MEMORY['cgroups']['total_rss'] or '-',
         ])
    return p_table


def gather_containers_memory(output_mem):
    """Gather memory information for all kubernetes containers.

    :param output_mem(str): Total rss output
    :returns (PrettyTable): Table with the final results.
    """

    # Get list of containers on this host
    cmd = ['crictl', 'ps', '--output=json']
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        LOG.debug('command: %s\n%s', ' '.join(cmd), output)
    except subprocess.CalledProcessError as error:
        LOG.error('Could not list containers, error=%s', error)
        return 1

    p_table = prettytable.PrettyTable(
        ['namespace',
         'pod.name',
         'container.name',
         'container.id',
         'state',
         'QoS',
         'PID',
         'Resident Set Size (MiB)',
         ], caching=False)
    p_table.align = 'l'
    p_table.align['Resident Set Size (MiB)'] = 'c'

    # Gather data for each container
    c_json = json.loads(output)

    containers = {}
    for cont in c_json['containers']:
        containers[cont['id']] = {
            'name': cont['metadata']['name'],
            'pod.name': cont['labels']['io.kubernetes.pod.name'],
            'cont.name': cont['labels']['io.kubernetes.container.name'],
            'namespace': cont['labels']['io.kubernetes.pod.namespace'],
            'pod.SandboxId': cont['podSandboxId'],
            'state': cont['state'],
            'pod.uid': cont['labels']['io.kubernetes.pod.uid'],
        }

    sandboxes = []
    for cid, cjson in sorted(containers.items(),
                             key=lambda kv: (kv[1]['namespace'],
                                             kv[1]['name'],
                                             kv[1]['cont.name'])):
        cid_short = cid[0:13]
        sbid_short = cjson['pod.SandboxId'][0:13]
        pname = cjson['pod.name']
        cname = cjson['cont.name']
        namespace = cjson['namespace']
        cstate = cjson['state']

        # Now that we have the container ids, get memory, PID and QoS info
        rss_mem_cid = None
        rss_mem_sbid = None
        pid_cid = None
        if namespace not in MEMORY['namespaces']:
            MEMORY['namespaces'][namespace] = 0
        qos = "guaranteed"
        for line in output_mem.split("\n"):
            if cid_short in line:
                rss_mem_cid = line.split()[1]
                MEMORY['namespaces'][namespace] += float(
                    mem_to_mebibytes(rss_mem_cid))
                pid_cid = pid_from_container(cid_short)
                qos_list = {"besteffort", "burstable"}
                for c_qos in qos_list:
                    if c_qos in line:
                        qos = c_qos
                        break
            elif sbid_short in line:
                if sbid_short not in sandboxes:
                    rss_mem_sbid = line.split()[1]
                    sandboxes.append(sbid_short)
                else:
                    rss_mem_sbid = ""
                break

        # Display both container and sandbox rss memory
        rss_mem = "container: " + mem_to_mebibytes(rss_mem_cid) + \
            "\nsandbox: " + mem_to_mebibytes(rss_mem_sbid)

        p_table.add_row(
            [namespace,
             pname,
             cname,
             cid_short,
             cstate,
             qos,
             pid_cid,
             rss_mem or '-',
             ])
    return p_table


def sys_service_memory():
    """Break down memory per system service (system.slice)

       Returns a table with the final results.
    """
    sort_cmd = ["sort", "-k", "2nr"]

    p_table = prettytable.PrettyTable(
        ['Service',
         'Resident Set Size (MiB)',
         ], caching=False)
    p_table.align = 'l'
    p_table.align['Resident Set Size (MiB)'] = 'r'

    try:
        output = pipe_command(GREP_CMD, AWK_CMD, sort_cmd,
                              cwd=MEMPATH + "system.slice")
        LOG.debug(
            'command: %s\n%s',
            ' '.join(GREP_CMD + [MEMPATH] + AWK_CMD + sort_cmd), output)
    except subprocess.CalledProcessError as error:
        LOG.error('Could not get total_rss memory, error=%s', error)
        return 1

    for line in output.split("\n"):
        service = line.split("memory.stat:total_rss ")[0]
        rss_mem = line.split("memory.stat:total_rss ")[-1]
        p_table.add_row(
            [service,
             mem_to_mebibytes(rss_mem),
             ])

    # Delete first row wich display total system.slice rss
    p_table.del_row(0)
    return p_table


def gather_info_and_display():
    """Gather memory info for all kubernetes containers and system services.

       This displays the total resident set size per container.
       This displays the aggregate memory usage per system-level groupings.
    """
    # Obtain total rss displayed in memory.stat for each group,
    # container and service.
    try:
        output_mem = pipe_command(GREP_CMD, AWK_CMD, cwd=MEMPATH)
        LOG.debug(
            'command: %s\n%s',
            "grep -rs total_rss '/sys/fs/cgroup/memory/' "
            "| awk '$2>0{print$0}' ",
            output_mem)
    except subprocess.CalledProcessError as error:
        LOG.error('Could not get total_rss memory, error=%s', error)
        return 1

    mem_info = get_meminfo()
    pt_groups = gather_groups_memory(output_mem)
    pt_cont = gather_containers_memory(output_mem)
    pt_serv = sys_service_memory()

    # Dump the tables out
    print('\nPer groups memory usage:')

    # Get string to be printed and create list of elements separated by \n
    list_of_table_lines = pt_groups.get_string().split('\n')

    # Use the first line (+---+-- ...) as horizontal rule to insert later
    horizontal_line = list_of_table_lines[0]

    # Print the table, except last two lines ( "Total" row + final separator).
    print("\n".join(list_of_table_lines[:-2]))
    # Print separator, and finally the "Total" row.
    print(horizontal_line)
    print("\n".join(list_of_table_lines[-2:]))

    pt_namespc = prettytable.PrettyTable(
        ['Namespace',
         'Resident Set Size (MiB)',
         ], caching=False)
    pt_namespc.align = 'l'
    pt_namespc.align['Resident Set Size (MiB)'] = 'r'

    print('\nPer namespace memory usage:')
    for n_s in MEMORY['namespaces']:
        pt_namespc.add_row(
            [n_s,
             MEMORY['namespaces'][n_s],
             ])
    print(pt_namespc)

    print('\nPer container memory usage:')
    print(pt_cont)

    print('\nPer service memory usage:')
    print(pt_serv)

    base_mebib = 0.0
    k8s_system = 0.0
    k8s_addon = 0.0
    platform_memory_percent = 0.0

    # Calculate base memory usage (i.e., normal memory, exclude K8S and VMs)
    # e.g., docker, system.slice, user.slice
    for group in MEMORY['cgroups']:
        if group in BASE_GROUPS:
            base_mebib += float(MEMORY['cgroups'][group])

    # K8S platform system usage (essential) and addons usage (non-essential)
    for n_s in MEMORY['namespaces']:
        if n_s in K8S_NAMESPACE_SYSTEM:
            k8s_system += MEMORY['namespaces'][n_s]
        elif n_s in K8S_NAMESPACE_ADDON:
            k8s_addon += MEMORY['namespaces'][n_s]

    # Calculate platform memory usage
    platform_mebib = base_mebib + k8s_system

    anon_mebib = float(mem_to_mebibytes(
        mem_info['Active(anon)'] + mem_info['Inactive(anon)'])) * KBYTE
    avail_mebib = float(mem_to_mebibytes(
        mem_info['MemAvailable'])) * KBYTE
    total_mebib = float(anon_mebib + avail_mebib)

    anon_percent = py2_round(100 * anon_mebib / total_mebib, DECIMAL_DIGITS)  # pylint: disable=W1619

    reserved_mebib = get_platform_reserved_memory()
    # Calculate platform memory in terms of percent reserved
    if reserved_mebib > 0.0:
        platform_memory_percent = py2_round(
            100 * platform_mebib / reserved_mebib, DECIMAL_DIGITS)  # pylint: disable=W1619

    pt_platf = prettytable.PrettyTable(
        ['Reserved',
         'Platform',
         'Base',
         'K8s Platform system',
         'k8s-addon'
         ], caching=False)
    pt_platf.align = 'l'

    pt_platf.add_row(
        [reserved_mebib,
         '{} ({}%)'.format(platform_mebib, platform_memory_percent),
         base_mebib,
         k8s_system,
         k8s_addon
         ])
    print('\nPlatform memory usage in MiB:')
    print(pt_platf)

    pt_4k = prettytable.PrettyTable(
        ['Anon',
         'Cgroup-rss',
         'Available',
         'Total'
         ], caching=False)
    pt_4k.align = 'l'

    pt_4k.add_row(
        ['{} ({}%)'.format(anon_mebib, anon_percent),
         MEMORY['cgroups']['total_rss'],
         avail_mebib,
         total_mebib
         ])

    print('\n4K memory usage in MiB:')
    print(pt_4k)

    return 0


def main():
    """Main program."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Display memory usage information '
                    'for all kubernetes containers '
                    'and services.')
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

    except KeyboardInterrupt as error:
        LOG.info('caught: %r, shutting down', error)
        sys.exit(0)

    except IOError:
        sys.exit(0)

    except Exception as error:
        LOG.error('exception: %r', error, exc_info=1)
        sys.exit(-4)
