#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import sys
from unittest.mock import MagicMock
sys.modules.setdefault('collectd', MagicMock())
sys.modules.setdefault('fm_core', MagicMock())
sys.modules.setdefault('tsconfig', MagicMock())
sys.modules.setdefault('tsconfig.tsconfig', MagicMock())
sys.modules.setdefault('fm_api', MagicMock())
sys.modules.setdefault('fm_api.constants', MagicMock())
sys.modules.setdefault('fm_api.fm_api', MagicMock())
sys.modules.setdefault('pynetlink', MagicMock())
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

import plugin_common as pc
import cpu
import memory
import unittest
from unittest.mock import mock_open
from unittest.mock import patch
import numpy as np


class TestIsStrictMemoryAccounting(unittest.TestCase):
    def test_strict_true(self):
        """Verify strict_true memory.is_strict_memory_accounting() is."""
        with patch('builtins.open', mock_open(read_data='2\n')):
            self.assertTrue(memory.is_strict_memory_accounting())

    def test_strict_false(self):
        """Verify strict_false memory.is_strict_memory_accounting() is."""
        with patch('builtins.open', mock_open(read_data='0\n')):
            self.assertFalse(memory.is_strict_memory_accounting())

    def test_exception(self):
        """Verify exception memory.is_strict_memory_accounting() is."""
        with patch('builtins.open', side_effect=Exception('fail')):
            self.assertFalse(memory.is_strict_memory_accounting())


class TestGetPlatformReservedMemory(unittest.TestCase):
    def test_no_file(self):
        """Verify reserved memory returns 0 when file missing."""
        with patch('os.path.exists', return_value=False):
            self.assertEqual(memory.get_platform_reserved_memory(), 0.0)

    def test_key_missing(self):
        """Verify reserved memory returns 0 without key."""
        content = 'OTHER_KEY=("foo")\n'
        with patch('os.path.exists', return_value=True), \
                patch('builtins.open', mock_open(read_data=content)):
            self.assertEqual(memory.get_platform_reserved_memory(), 0.0)

    def test_parse_exception(self):
        """Verify reserved memory returns 0 on read error."""
        with patch('os.path.exists', return_value=True), \
                patch('builtins.open', side_effect=Exception('fail')):
            self.assertEqual(memory.get_platform_reserved_memory(), 0.0)


class TestGetCgroupMemory(unittest.TestCase):

    def test_ioerror(self):
        """Verify ioerror on exception."""
        with patch('builtins.open', side_effect=IOError):
            result = memory.get_cgroup_memory('/fake')
            self.assertAlmostEqual(result['rss_MiB'], 0.0)


class TestGetMeminfo(unittest.TestCase):
    def test_normal(self):
        """Verify get_meminfo parses MemTotal value."""
        data = 'MemTotal:       16384 kB\nMemFree:         8192 kB\n'
        with patch('builtins.open', mock_open(read_data=data)):
            meminfo = memory.get_meminfo()
            self.assertEqual(meminfo['MemTotal'], 16384)

    def test_ioerror(self):
        """Verify ioerror returns {} on exception."""
        with patch('builtins.open', side_effect=IOError('fail')):
            self.assertEqual(memory.get_meminfo(), {})


class TestGetMeminfoNodes(unittest.TestCase):
    def test_normal(self):
        """Verify get_meminfo_nodes parses per-node data."""
        node_data = 'Node 0 MemTotal: 8192 kB\nNode 0 MemFree: 4096 kB\n'
        with patch('os.listdir', return_value=['node0']), \
                patch('builtins.open', mock_open(read_data=node_data)):
            meminfo = memory.get_meminfo_nodes()
            self.assertEqual(meminfo['node0']['MemTotal'], 8192)

    def test_ioerror(self):
        """Verify ioerror returns {} on exception."""
        with patch('os.listdir', return_value=['node0']), \
                patch('builtins.open', side_effect=IOError('fail')):
            meminfo = memory.get_meminfo_nodes()
            self.assertEqual(meminfo['node0'], {})


class TestCalcNormalMemory(unittest.TestCase):
    def test_non_strict(self):
        """Verify calc_memory uses anon pages when non-strict."""
        memory.obj.strict_memory_accounting = False
        memory.obj.meminfo = {
            'Active(anon)': 1024, 'Inactive(anon)': 1024,
            'MemAvailable': 2048, 'Slab': 512,
            'Committed_AS': 0, 'CommitLimit': 1
        }
        result = memory.calc_normal_memory()
        self.assertIn('anon_MiB', result)
        self.assertIn('avail_MiB', result)
        self.assertIn('total_MiB', result)
        self.assertIn('anon_percent', result)
        self.assertIn('slab_MiB', result)
        self.assertGreater(result['total_MiB'], 0)

    def test_zero_total(self):
        """Verify calc_memory returns 0 with zero totals."""
        memory.obj.strict_memory_accounting = False
        memory.obj.meminfo = {
            'Active(anon)': 0, 'Inactive(anon)': 0,
            'MemAvailable': 0, 'Slab': 0,
            'Committed_AS': 0, 'CommitLimit': 1
        }
        result = memory.calc_normal_memory()
        self.assertEqual(result['anon_percent'], 0.0)


class TestCalcNormalMemoryNodes(unittest.TestCase):
    def test_normal(self):
        """Verify normal 'anon_MiB' in result[...]."""
        memory.obj.meminfo_nodes = {
            'node0': {
                'Active(anon)': 512, 'Inactive(anon)': 512,
                'MemFree': 1024, 'FilePages': 256,
                'SReclaimable': 256, 'Slab': 128
            }
        }
        result = memory.calc_normal_memory_nodes()
        self.assertIn('node0', result)
        self.assertIn('anon_MiB', result['node0'])

    def test_zero_total(self):
        """Verify calc_node_memory returns 0 with zero totals."""
        memory.obj.meminfo_nodes = {
            'node0': {
                'Active(anon)': 0, 'Inactive(anon)': 0,
                'MemFree': 0, 'FilePages': 0,
                'SReclaimable': 0, 'Slab': 0
            }
        }
        result = memory.calc_normal_memory_nodes()
        self.assertEqual(result['node0']['anon_percent'], 0.0)


class TestGetCgroupsProcsPathsAndPid(unittest.TestCase):
    def test_get_cgroups_procs_paths(self):
        """Verify get_cgroups_procs_paths '/a' in result."""
        with patch('os.path.isdir', return_value=True), \
                patch('os.walk') as mw:
            mw.return_value = iter([('/a', ['b'], [])])
            # first call returns ('/a', ['b'], []), second returns
            # ('/a/b', [], [])
            with patch('memory.next', side_effect=[('/a', ['b'], []), ('/a/b', [], [])]):
                pass
            # Simpler: just test with no subdirs
        with patch('os.path.isdir', side_effect=[True, False]):
            with patch('os.walk') as mw2:
                mw2.return_value = iter([('/a', [], [])])
                result = memory.get_cgroups_procs_paths('/a')
                self.assertIn('/a', result)

    def test_not_a_dir(self):
        """Verify not_a returns []."""
        with patch('os.path.isdir', return_value=False):
            self.assertEqual(memory.get_cgroups_procs_paths('/nope'), [])

    def test_get_cgroup_pid(self):
        """Verify get_cgroup_pid reads two PIDs from file."""
        data = '1234\n5678\n'
        with patch('builtins.open', mock_open(read_data=data)):
            pids = memory.get_cgroup_pid('/fake')
            self.assertEqual(len(pids), 2)

    def test_get_cgroup_pid_ioerror(self):
        """Verify get_cgroup_pid_ioerror returns [] on exception."""
        with patch('builtins.open', side_effect=IOError):
            self.assertEqual(memory.get_cgroup_pid('/fake'), [])


class TestFormatIec(unittest.TestCase):
    def test_kib(self):
        """Verify kib 'KiB' in memory.format_iec()."""
        self.assertIn('KiB', memory.format_iec(500))

    def test_mib(self):
        """Verify mib 'MiB' in memory.format_iec()."""
        self.assertIn('MiB', memory.format_iec(2048))

    def test_gib(self):
        """Verify gib 'GiB' in memory.format_iec()."""
        self.assertIn('GiB', memory.format_iec(1024 * 1024 + 1))

    def test_tib(self):
        """Verify tib 'TiB' in memory.format_iec()."""
        self.assertIn('TiB', memory.format_iec(1024 * 1024 * 1024 + 1))


class TestGetPidNameAndRss(unittest.TestCase):
    def test_get_pid_name(self):
        """Verify get_pid_name returns 'myprocess'."""
        with patch('builtins.open', mock_open(read_data='myprocess\n')):
            self.assertEqual(memory.get_pid_name(123), 'myprocess')

    def test_get_pid_name_ioerror(self):
        """Verify get_pid_name_ioerror returns '' on exception."""
        with patch('builtins.open', side_effect=IOError):
            self.assertEqual(memory.get_pid_name(123), '')

    def test_get_pid_rss(self):
        """Verify get_pid_rss parses VmRSS from status."""
        data = 'VmRSS: 4096 kB\nVmSize: 8192 kB\n'
        with patch('builtins.open', mock_open(read_data=data)):
            self.assertEqual(memory.get_pid_rss(123), 4096.0)

    def test_get_pid_rss_ioerror(self):
        """Verify get_pid_rss returns 0 on IOError."""
        with patch('builtins.open', side_effect=IOError):
            self.assertEqual(memory.get_pid_rss(123), 0.0)

    def test_get_pid_rss_no_vmrss(self):
        """Verify get_pid_rss returns 0 without VmRSS line."""
        data = 'VmSize: 8192 kB\n'
        with patch('builtins.open', mock_open(read_data=data)):
            self.assertEqual(memory.get_pid_rss(123), 0.0)


class TestMemoryConfigFunc(unittest.TestCase):
    def test_config(self):
        """Verify config memory.obj.debug is True."""
        cfg = MagicMock()
        node_one = MagicMock()
        node_one.key = 'debug'
        node_one.values = [True]
        node_two = MagicMock()
        node_two.key = 'verbose'
        node_two.values = [False]
        cfg.children = [node_one, node_two]
        result = memory.config_func(cfg)
        self.assertEqual(result, pc.PLUGIN_PASS)
        self.assertTrue(memory.obj.debug)


class TestMemoryInitFunc(unittest.TestCase):

    def test_init_config_not_complete(self):
        """Verify init_config_not_complete returns 0 when not."""
        memory.obj._config_complete = False
        memory.obj.init_complete = False
        with patch.object(memory.obj, 'config_complete', return_value=False):
            result = memory.init_func()
            self.assertEqual(result, 0)

    @patch('memory.get_platform_reserved_memory', return_value=0.0)
    @patch('memory.is_strict_memory_accounting', return_value=False)
    @patch('socket.gethostname', return_value='testhost')
    def test_init_reserve_all(self, mock_host, mock_strict, mock_reserved):
        """Verify init_reserve_all memory.obj.reserve_all is True."""
        memory.obj._config_complete = True
        memory.obj.init_complete = False
        memory.init_func()
        self.assertTrue(memory.obj.reserve_all)


class TestMemoryReadFunc(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        memory.obj.init_complete = True
        memory.obj._node_ready = True
        memory.obj.hostname = 'testhost'
        memory.obj.debug = False
        memory.obj.verbose = False
        memory.obj.reserve_all = False
        memory.obj.reserved_MiB = 1000.0
        memory.obj._cache = {}
        memory.obj.k8s_pods = set()

    def test_read_not_init(self):
        """Verify read_not_init returns 0 when not initialized."""
        memory.obj.init_complete = False
        with patch('memory.init_func', return_value=0):
            result = memory.read_func()
            self.assertEqual(result, 0)
        memory.obj.init_complete = True

    def test_read_not_node_ready(self):
        """Verify read_not_node_ready returns 0."""
        memory.obj._node_ready = False
        with patch.object(memory.obj, 'node_ready', return_value=False):
            result = memory.read_func()
            self.assertEqual(result, 0)
        memory.obj._node_ready = True


class TestReadSchedstat(unittest.TestCase):
    def test_normal(self):
        """Verify read_schedstat parses per-cpu run times."""
        data = ('version 16\n'
                'timestamp 123456\n'
                'cpu0 0 0 0 0 0 0 5000000 1000000 100\n'
                'cpu1 0 0 0 0 0 0 6000000 2000000 200\n')
        with patch('builtins.open', mock_open(read_data=data)):
            ct = cpu.read_schedstat()
            self.assertEqual(ct[0], 5000000)
            self.assertEqual(ct[1], 6000000)

    def test_exception(self):
        """Verify exception returns {} on exception."""
        with patch('builtins.open', side_effect=Exception('fail')):
            ct = cpu.read_schedstat()
            self.assertEqual(ct, {})


class TestGetLogicalCpus(unittest.TestCase):
    def test_normal(self):
        """Verify normal returns []."""
        data = 'Processor : 0\nProcessor : 1\nProcessor : 2\n'
        with patch('builtins.open', mock_open(read_data=data)):
            cpus = cpu.get_logical_cpus()
            self.assertEqual(sorted(cpus), [0, 1, 2])

    def test_exception(self):
        """Verify exception returns [] on exception."""
        with patch('builtins.open', side_effect=Exception('fail')):
            self.assertEqual(cpu.get_logical_cpus(), [])


class TestGetPlatformCpulist(unittest.TestCase):

    def test_no_file(self):
        """Verify no_file returns []."""
        with patch('os.path.exists', return_value=False):
            self.assertEqual(cpu.get_platform_cpulist(), [])

    def test_key_missing(self):
        """Verify key_missing returns [] when missing."""
        data = 'OTHER_KEY="0-3"\n'
        with patch('os.path.exists', return_value=True), \
                patch('builtins.open', mock_open(read_data=data)):
            self.assertEqual(cpu.get_platform_cpulist(), [])

    def test_parse_exception(self):
        """Verify parse_exception returns [] on exception."""
        with patch('os.path.exists', return_value=True), \
                patch('builtins.open', side_effect=Exception('fail')):
            self.assertEqual(cpu.get_platform_cpulist(), [])


class TestGetCgroupCpuacct(unittest.TestCase):

    def test_ioerror_no_cpulist(self):
        """Verify ioerror_no returns 0 on exception."""
        with patch('builtins.open', side_effect=IOError):
            self.assertEqual(cpu.get_cgroup_cpuacct('/fake'), 0)

    def test_ioerror_with_cpulist(self):
        """Verify ioerror_with returns 0 on exception."""
        with patch('builtins.open', side_effect=IOError):
            self.assertEqual(cpu.get_cgroup_cpuacct('/fake', cpulist=[0]), 0)


class TestGetCpuFrequencies(unittest.TestCase):
    def test_normal(self):
        """Verify get_cpu_frequencies reads scaling freq."""
        cpu.obj.cpu_freq = {}
        cpu.obj.cpu_freq_non_platform_cores = True
        with patch('builtins.open', mock_open(read_data=b'2400000')):
            cpu.get_cpu_frequencies([0, 1])
            self.assertEqual(cpu.obj.cpu_freq[0], 2400000)

    def test_exception_non_platform(self):
        """Verify exception_non cpu.obj.cpu_freq_non_platform_cores."""
        cpu.obj.cpu_freq = {}
        cpu.obj.cpu_freq_non_platform_cores = True
        with patch('builtins.open', side_effect=Exception('fail')):
            cpu.get_cpu_frequencies([0])
            self.assertFalse(cpu.obj.cpu_freq_non_platform_cores)

    def test_exception_platform_only(self):
        """Verify exception_platform cpu.obj.cpu_frequency is False."""
        cpu.obj.cpu_freq = {}
        cpu.obj.cpu_freq_non_platform_cores = False
        cpu.obj.cpu_frequency = True
        with patch('builtins.open', side_effect=Exception('fail')):
            cpu.get_cpu_frequencies([0])
            self.assertFalse(cpu.obj.cpu_frequency)


class TestUpdateCpuFrequencyData(unittest.TestCase):
    @patch('cpu.get_cpu_frequencies')
    def test_init(self, mock_freq):
        """Verify init is called with expected args."""
        cpu.obj.cpu_freq_non_platform_cores = True
        cpu.obj.logical_cpus = [0, 1]
        cpu.obj.cpu_list = [0]
        cpu.update_cpu_frequency_data(init=True)
        mock_freq.assert_called_once_with([0, 1])

    @patch('cpu.get_cpu_frequencies')
    def test_init_platform_only(self, mock_freq):
        """Verify init_platform_only is called with expected args."""
        cpu.obj.cpu_freq_non_platform_cores = False
        cpu.obj.cpu_list = [0]
        cpu.update_cpu_frequency_data(init=True)
        mock_freq.assert_called_once_with([0])


class TestCalculateOccupancy(unittest.TestCase):
    def _make_ca(self, overall_total=0, first=None):
        """Build cpuacct dicts with all required keys."""
        if first is None:
            first = {}
        data_dict = {
            pc.GROUP_OVERALL: {pc.GROUP_TOTAL: overall_total, pc.GROUP_OVERHEAD: overall_total},
            pc.GROUP_FIRST: first,
            pc.GROUP_PODS: {},
            pc.CGROUP_SYSTEM: {}, pc.CGROUP_USER: {},
            pc.CGROUP_UTILS: {}, pc.CGROUP_K8SPLATFORM: {}
        }
        return data_dict

    def test_basic(self):
        """Verify calculate_occupancy computes cpu percent."""
        time_zero = {'timestamp': 0.0, 0: 0, 1: 0}
        time_one = {'timestamp': 1.0, 0: 5000000, 1: 5000000}
        t0_ca = self._make_ca(0, {'system.slice': 0})
        t1_ca = self._make_ca(10000000, {'system.slice': 5000000})
        occ = {cpu.PLATFORM_CPU_PERCENT: 0.0}
        for group in pc.OVERALL_GROUPS:
            occ[group] = 0.0
        cpu.calculate_occupancy(
            'hires', False, False, {},
            time_zero, time_one,
            t0_ca, t1_ca,
            occ, 1000.0, 2, [0, 1], False)
        self.assertGreater(occ[cpu.PLATFORM_CPU_PERCENT], 0.0)


class TestAggregateHistogram(unittest.TestCase):
    def test_no_histogram(self):
        """Verify no_histogram 'system' in hist_occ."""
        bins = np.histogram_bin_edges(np.array([0, 100], dtype=np.float64), bins=10, range=(0, 100))
        hist_occ = {}
        occ = {cpu.PLATFORM_CPU_PERCENT: 5.0, 'system.slice': 2.0}
        cpu.aggregate_histogram(False, occ, bins, hist_occ, False)
        self.assertIn('system', hist_occ)


class TestCpuConfigFunc(unittest.TestCase):
    def test_config(self):
        """Verify config cpu.obj.hires is True."""
        cfg = MagicMock()
        node_one = MagicMock()
        node_one.key = 'debug'
        node_one.values = [True]
        node_two = MagicMock()
        node_two.key = 'verbose'
        node_two.values = [False]
        node_three = MagicMock()
        node_three.key = 'hires'
        node_three.values = [True]
        node_four = MagicMock()
        node_four.key = 'cpu_frequency_non_platform_cores'
        node_four.values = [False]
        cfg.children = [node_one, node_two, node_three, node_four]
        result = cpu.config_func(cfg)
        self.assertEqual(result, pc.PLUGIN_PASS)
        self.assertTrue(cpu.obj.debug)
        self.assertTrue(cpu.obj.hires)


class TestCpuInitFunc(unittest.TestCase):
    def test_config_not_complete(self):
        """Verify init_func returns PASS when not configured."""
        with patch.object(cpu.obj, 'config_complete', return_value=False):
            result = cpu.init_func()
            self.assertEqual(result, pc.PLUGIN_PASS)

    def test_node_not_ready(self):
        """Verify init_func returns PASS when node not ready."""
        cpu.obj._config_complete = True
        cpu.obj._node_ready = False
        with patch.object(cpu.obj, 'config_complete', return_value=True), \
                patch.object(cpu.obj, 'node_ready', return_value=False):
            result = cpu.init_func()
            self.assertEqual(result, pc.PLUGIN_PASS)

    @patch('cpu.get_platform_cpulist', return_value=[99])
    @patch('cpu.get_logical_cpus', return_value=[0, 1])
    @patch('socket.gethostname', return_value='testhost')
    def test_init_cpu_not_subset(self, mock_host, mock_lcpus, mock_pcpus):
        """Verify init_func fails when cpus not subset."""
        cpu.obj._config_complete = True
        cpu.obj._node_ready = True
        cpu.obj.init_complete = False
        with patch.object(cpu.obj, 'config_complete', return_value=True), \
                patch.object(cpu.obj, 'node_ready', return_value=True):
            result = cpu.init_func()
        self.assertEqual(result, pc.PLUGIN_FAIL)

    @patch('cpu.update_cpu_data')
    @patch('cpu.get_platform_cpulist', return_value=[])
    @patch('cpu.get_logical_cpus', return_value=[0, 1])
    @patch('socket.gethostname', return_value='testhost')
    def test_init_empty_cpulist(self, mock_host, mock_lcpus, mock_pcpus, mock_update):
        """Verify init_empty_cpulist returns [] with empty input."""
        cpu.obj._config_complete = True
        cpu.obj._node_ready = True
        cpu.obj.init_complete = False
        cpu.obj.debug = False
        schedstat_data = 'version 16\n'
        with patch.object(cpu.obj, 'config_complete', return_value=True), \
                patch.object(cpu.obj, 'node_ready', return_value=True), \
                patch('builtins.open', mock_open(read_data=schedstat_data)), \
                patch('os.path.isfile', return_value=False):
            result = cpu.init_func()
        self.assertEqual(result, pc.PLUGIN_PASS)
        self.assertEqual(cpu.obj.cpu_list, [0, 1])

    @patch('cpu.get_platform_cpulist', return_value=[0])
    @patch('cpu.get_logical_cpus', return_value=[0, 1])
    @patch('socket.gethostname', return_value='testhost')
    def test_init_bad_schedstat_version(self, mock_host, mock_lcpus, mock_pcpus):
        """Verify init_func fails on bad schedstat version."""
        cpu.obj._config_complete = True
        cpu.obj._node_ready = True
        cpu.obj.init_complete = False
        schedstat_data = 'version 10\n'
        with patch.object(cpu.obj, 'config_complete', return_value=True), \
                patch.object(cpu.obj, 'node_ready', return_value=True), \
                patch('builtins.open', mock_open(read_data=schedstat_data)):
            result = cpu.init_func()
        self.assertEqual(result, pc.PLUGIN_FAIL)
        cpu.obj.schedstat_supported = True

    @patch('cpu.get_platform_cpulist', return_value=[0])
    @patch('cpu.get_logical_cpus', return_value=[0, 1])
    @patch('socket.gethostname', return_value='testhost')
    def test_init_schedstat_read_error(self, mock_host, mock_lcpus, mock_pcpus):
        """Verify init_func fails on schedstat read error."""
        cpu.obj._config_complete = True
        cpu.obj._node_ready = True
        cpu.obj.init_complete = False
        with patch.object(cpu.obj, 'config_complete', return_value=True), \
                patch.object(cpu.obj, 'node_ready', return_value=True), \
                patch('builtins.open', side_effect=Exception('fail')):
            result = cpu.init_func()
        self.assertEqual(result, pc.PLUGIN_FAIL)


class TestCpuReadFunc(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        cpu.obj.init_complete = True
        cpu.obj.schedstat_supported = True
        cpu.obj.cpu_list = [0, 1]
        cpu.obj.hostname = 'testhost'
        cpu.obj.debug = False
        cpu.obj.dispatch = False
        cpu.obj.cpu_frequency = False
        cpu.obj.elapsed_ms = 2000.0
        cpu.obj.number_platform_cpus = 2
        cpu.obj._occ = {cpu.PLATFORM_CPU_PERCENT: 5.0}
        cpu.obj.d_occ = {cpu.PLATFORM_CPU_PERCENT: 5.0}
        for group in pc.OVERALL_GROUPS:
            cpu.obj._occ[group] = 0.0
            cpu.obj.d_occ[group] = 0.0

    @patch('cpu.update_cpu_frequency_data')
    @patch('cpu.update_cpu_data')
    def test_read_basic(self, mock_update, mock_freq):
        """Verify read_basic is called once."""
        result = cpu.read_func()
        self.assertEqual(result, pc.PLUGIN_PASS)
        mock_update.assert_called_once()

    def test_read_not_init(self):
        """Verify read_func returns PASS when not initialized."""
        cpu.obj.init_complete = False
        with patch('cpu.init_func', return_value=pc.PLUGIN_PASS):
            result = cpu.read_func()
            self.assertEqual(result, pc.PLUGIN_PASS)
        cpu.obj.init_complete = True

    def test_read_schedstat_not_supported(self):
        """Verify read_func fails when schedstat unsupported."""
        cpu.obj.schedstat_supported = False
        result = cpu.read_func()
        self.assertEqual(result, pc.PLUGIN_FAIL)
        cpu.obj.schedstat_supported = True

    def test_read_no_cpus(self):
        """Verify read_func returns PASS with empty cpu list."""
        cpu.obj.cpu_list = []
        result = cpu.read_func()
        self.assertEqual(result, pc.PLUGIN_PASS)
        cpu.obj.cpu_list = [0, 1]

    @patch('cpu.update_cpu_data')
    def test_read_early_return(self, mock_update):
        """Verify read_func returns PASS when elapsed too low."""
        cpu.obj.elapsed_ms = 100.0
        result = cpu.read_func()
        self.assertEqual(result, pc.PLUGIN_PASS)
        cpu.obj.elapsed_ms = 2000.0

    @patch('cpu.update_cpu_frequency_data')
    @patch('cpu.update_cpu_data')
    def test_read_dispatch(self, mock_update, mock_freq):
        """Verify read_func dispatches with frequency enabled."""
        cpu.obj.dispatch = True
        cpu.obj.cpu_frequency = True
        result = cpu.read_func()
        self.assertEqual(result, pc.PLUGIN_PASS)

    @patch('cpu.update_cpu_data')
    def test_read_debug_overhead(self, mock_update):
        """Verify read_func runs with debug overhead logging."""
        cpu.obj.debug = True
        result = cpu.read_func()
        self.assertEqual(result, pc.PLUGIN_PASS)
        cpu.obj.debug = False


if __name__ == '__main__':
    unittest.main()
