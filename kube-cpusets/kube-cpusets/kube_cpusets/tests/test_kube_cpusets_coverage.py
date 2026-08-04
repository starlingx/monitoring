#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive unit tests for kube_cpusets module."""

import contextlib
import json
import subprocess
import unittest
from unittest.mock import mock_open
from unittest.mock import patch

from kube_cpusets import kube_cpusets


def _make_open_side_effect(file_map):
    """Create an open side_effect from a filename-to-content map."""
    def open_side_effect(filename, *args, **kwargs):
        for key, content in file_map.items():
            if key in filename:
                return mock_open(read_data=content)()
        raise FileNotFoundError(filename)
    return open_side_effect


def _patch_fs(file_map, nodes):
    """Return ExitStack context patching open/isdir/listdir/isfile."""
    stack = contextlib.ExitStack()
    stack.enter_context(
        patch('builtins.open',
              side_effect=_make_open_side_effect(file_map)))
    stack.enter_context(
        patch('os.path.isdir', return_value=True))
    stack.enter_context(
        patch('os.listdir', return_value=nodes))
    stack.enter_context(
        patch('os.path.isfile', return_value=True))
    return stack


def _build_mocks():
    """Build common mock data for gather_info_and_display tests."""
    state = {
        'policyName': 'static',
        'defaultCpuSet': '0-3',
        'entries': {
            'pod1': {'container1': '4-5'},
            'pod2': {'container2': '6-7'},
        }
    }
    platconf = (
        'nodetype=worker\n'
        'subfunction=worker\n'
        'system_type=Standard\n'
    )
    reserved = 'PLATFORM_CPU_LIST="0-1"\n'
    crictl_ps = json.dumps({
        'containers': [{
            'id': 'abc1234567890xyz',
            'metadata': {'name': 'test-container'},
            'labels': {
                'io.kubernetes.pod.name': 'test-pod',
                'io.kubernetes.container.name':
                    'test-container',
                'io.kubernetes.pod.namespace':
                    'kube-system',
            },
            'state': 'CONTAINER_RUNNING',
        }]
    })
    crictl_inspect = json.dumps({
        'info': {
            'runtimeSpec': {
                'linux': {
                    'cgroupsPath':
                        '/kubepods/burstable/pod1/ctr1',
                    'resources': {
                        'cpu': {
                            'shares': 512,
                            'cpus': '0-3',
                        }
                    }
                }
            }
        }
    })
    return (state, platconf, reserved,
            crictl_ps, crictl_inspect)


class TestFormatRangeSet(unittest.TestCase):
    """Tests for format_range_set function."""

    def test_single_item(self):
        """Verify single_item returns '5'."""
        self.assertEqual(
            kube_cpusets.format_range_set({5}), '5')

    def test_contiguous_range(self):
        """Verify contiguous_range returns '1-3'."""
        self.assertEqual(
            kube_cpusets.format_range_set({1, 2, 3}), '1-3')

    def test_multiple_ranges(self):
        """Verify multiple_ranges returns '1-3,8-9,15'."""
        result = kube_cpusets.format_range_set(
            {1, 2, 3, 8, 9, 15})
        self.assertEqual(result, '1-3,8-9,15')

    def test_empty_set(self):
        """Verify empty_set returns '' with empty input."""
        self.assertEqual(
            kube_cpusets.format_range_set(set()), '')

    def test_non_contiguous_singles(self):
        """Verify non_contiguous returns '1,5,10'."""
        result = kube_cpusets.format_range_set({1, 5, 10})
        self.assertEqual(result, '1,5,10')

    def test_large_range(self):
        """Verify large_range returns '0-15'."""
        result = kube_cpusets.format_range_set(
            set(range(0, 16)))
        self.assertEqual(result, '0-15')


class TestRangeToList(unittest.TestCase):
    """Tests for range_to_list function."""

    def test_single_value(self):
        """Verify single_value returns []."""
        self.assertEqual(
            kube_cpusets.range_to_list('5'), [5])

    def test_range(self):
        """Verify range returns []."""
        self.assertEqual(
            kube_cpusets.range_to_list('1-3'), [1, 2, 3])

    def test_mixed(self):
        """Verify mixed returns []."""
        self.assertEqual(
            kube_cpusets.range_to_list('1-3,8-9,15'),
            [1, 2, 3, 8, 9, 15]
        )

    def test_none(self):
        """Verify none returns [] with None input."""
        self.assertEqual(
            kube_cpusets.range_to_list(None), [])

    def test_empty_string(self):
        """Verify empty_string returns [] with empty input."""
        self.assertEqual(
            kube_cpusets.range_to_list(''), [])


class TestCpusetFromCpulistFile(unittest.TestCase):
    """Tests for cpuset_from_cpulist_file function."""

    def test_valid_file(self):
        """Verify cpuset_from_cpulist_file parses ranges."""
        mopen = mock_open(read_data='0-3,8-9\n')
        with patch('builtins.open', mopen):
            result = kube_cpusets.cpuset_from_cpulist_file(
                '/test/file')
        self.assertEqual(result, {0, 1, 2, 3, 8, 9})

    def test_file_not_found(self):
        """Verify cpuset_from_cpulist_file returns empty on missing file."""
        with patch('builtins.open',
                   side_effect=FileNotFoundError):
            result = kube_cpusets.cpuset_from_cpulist_file(
                '/nonexistent')
        self.assertEqual(result, set())

    def test_empty_file(self):
        """Verify cpuset_from_cpulist_file returns empty for blank."""
        mopen = mock_open(read_data='\n')
        with patch('builtins.open', mopen):
            result = kube_cpusets.cpuset_from_cpulist_file(
                '/test/file')
        self.assertEqual(result, set())


class TestGetIsolatedCpuset(unittest.TestCase):
    """Tests for get_isolated_cpuset function."""

    def test_returns_cpuset(self):
        """Verify get_isolated_cpuset parses cpu range."""
        mopen = mock_open(read_data='4-7\n')
        with patch('builtins.open', mopen):
            result = kube_cpusets.get_isolated_cpuset()
        self.assertEqual(result, {4, 5, 6, 7})


class TestGetOnlineCpuset(unittest.TestCase):
    """Tests for get_online_cpuset function."""

    def test_returns_cpuset(self):
        """Verify get_online_cpuset parses cpu range."""
        mopen = mock_open(read_data='0-15\n')
        with patch('builtins.open', mopen):
            result = kube_cpusets.get_online_cpuset()
        self.assertEqual(result, set(range(16)))


class TestGetK8sInfraCpuset(unittest.TestCase):
    """Tests for get_k8sinfra_cpuset function."""

    def test_returns_cpuset(self):
        """Verify get_k8sinfra_cpuset parses cpu range."""
        mopen = mock_open(read_data='0-3\n')
        with patch('builtins.open', mopen):
            result = kube_cpusets.get_k8sinfra_cpuset()
        self.assertEqual(result, {0, 1, 2, 3})


class TestGetNodeCpusets(unittest.TestCase):
    """Tests for get_node_cpusets function."""

    @patch('os.path.isfile', return_value=True)
    @patch('os.listdir',
           return_value=['node0', 'node1', 'notanode'])
    @patch('os.path.isdir', return_value=True)
    def test_multiple_nodes(self, _isdir, _listdir, _isfile):
        """Verify get_node_cpusets returns per-node cpusets."""
        file_map = {'node0': '0-3\n', 'node1': '4-7\n'}
        with patch('builtins.open',
                   side_effect=_make_open_side_effect(
                       file_map)):
            result = kube_cpusets.get_node_cpusets()
        self.assertEqual(result[0], {0, 1, 2, 3})
        self.assertEqual(result[1], {4, 5, 6, 7})

    @patch('os.path.isdir', return_value=False)
    def test_no_node_dir(self, _isdir):
        """Test when node directory doesn't exist."""
        result = kube_cpusets.get_node_cpusets()
        self.assertEqual(result, {})

    @patch('os.path.isfile', return_value=False)
    @patch('os.listdir', return_value=['node0'])
    @patch('os.path.isdir', return_value=True)
    def test_node_no_cpulist(
            self, _isdir, _listdir, _isfile):
        """Verify node without cpulist returns empty set."""
        result = kube_cpusets.get_node_cpusets()
        self.assertEqual(result[0], set())


class TestGatherInfoAndDisplay(unittest.TestCase):
    """Tests for gather_info_and_display function."""

    @patch('subprocess.check_output')
    @patch('socket.gethostname', return_value='testhost')
    def test_gather_info_success(
            self, _hostname, mock_subproc):
        """Verify gather_info_success returns 0 on success."""
        (state, platconf, reserved,
         crictl_ps, crictl_inspect) = _build_mocks()
        mock_subproc.side_effect = [
            "tmpfs\n",                   # stat cgroup (v1)
            crictl_ps.encode(),
            crictl_inspect.encode(),
        ]
        file_map = {
            'isolated': '4-7\n',
            'online': '0-15\n',
            'k8sinfra': '0-3\n',
            'platform.conf': platconf,
            'worker_reserved': reserved,
            'cpu_manager_state': json.dumps(state),
            'node0': '0-7\n',
            'node1': '8-15\n',
        }
        with _patch_fs(file_map, ['node0', 'node1']):
            ret = kube_cpusets.gather_info_and_display()
        self.assertEqual(ret, 0)

    @patch('socket.gethostname', return_value='testhost')
    def test_gather_info_platconf_error(self, _hostname):
        """Test with platform.conf read error."""
        def open_side_effect(filename, *args, **kwargs):
            if 'isolated' in filename:
                return mock_open(read_data='4-7\n')()
            if 'online' in filename:
                return mock_open(read_data='0-15\n')()
            if 'k8sinfra' in filename:
                return mock_open(read_data='0-3\n')()
            if 'platform.conf' in filename:
                raise PermissionError("denied")
            if 'node0' in filename:
                return mock_open(read_data='0-7\n')()
            raise FileNotFoundError(filename)

        stack = contextlib.ExitStack()
        stack.enter_context(
            patch('builtins.open',
                  side_effect=open_side_effect))
        stack.enter_context(
            patch('os.path.isdir', return_value=True))
        stack.enter_context(
            patch('os.listdir', return_value=['node0']))
        stack.enter_context(
            patch('os.path.isfile', return_value=True))
        with stack:
            ret = kube_cpusets.gather_info_and_display()
        self.assertEqual(ret, 1)

    @patch('socket.gethostname', return_value='testhost')
    def test_gather_info_statefile_error(self, _hostname):
        """Test with state file read error."""
        platconf = (
            'nodetype=worker\n'
            'subfunction=worker\n'
            'system_type=Standard\n'
        )
        reserved = 'PLATFORM_CPU_LIST="0-1"\n'

        def open_side_effect(filename, *args, **kwargs):
            if 'isolated' in filename:
                return mock_open(read_data='4-7\n')()
            if 'online' in filename:
                return mock_open(read_data='0-15\n')()
            if 'k8sinfra' in filename:
                return mock_open(read_data='0-3\n')()
            if 'platform.conf' in filename:
                return mock_open(read_data=platconf)()
            if 'worker_reserved' in filename:
                return mock_open(read_data=reserved)()
            if 'cpu_manager_state' in filename:
                raise PermissionError("denied")
            if 'node0' in filename:
                return mock_open(read_data='0-7\n')()
            raise FileNotFoundError(filename)

        stack = contextlib.ExitStack()
        stack.enter_context(
            patch('builtins.open',
                  side_effect=open_side_effect))
        stack.enter_context(
            patch('os.path.isdir', return_value=True))
        stack.enter_context(
            patch('os.listdir', return_value=['node0']))
        stack.enter_context(
            patch('os.path.isfile', return_value=True))
        with stack:
            ret = kube_cpusets.gather_info_and_display()
        self.assertEqual(ret, 1)

    @patch('socket.gethostname', return_value='testhost')
    def test_gather_info_missing_default_cpuset(
            self, _hostname):
        """Test with missing defaultCpuSet in state."""
        state = {'policyName': 'static'}
        platconf = (
            'nodetype=worker\n'
            'subfunction=worker\n'
            'system_type=Standard\n'
        )
        reserved = 'PLATFORM_CPU_LIST="0-1"\n'
        file_map = {
            'isolated': '4-7\n',
            'online': '0-15\n',
            'k8sinfra': '0-3\n',
            'platform.conf': platconf,
            'worker_reserved': reserved,
            'cpu_manager_state': json.dumps(state),
            'node0': '0-7\n',
        }
        with _patch_fs(file_map, ['node0']):
            ret = kube_cpusets.gather_info_and_display()
        self.assertEqual(ret, 1)

    @patch('subprocess.check_output')
    @patch('socket.gethostname', return_value='testhost')
    def test_gather_info_crictl_ps_error(
            self, _hostname, mock_subproc):
        """Test with crictl ps failure."""
        state = {
            'policyName': 'static',
            'defaultCpuSet': '0-3',
            'entries': {}
        }
        platconf = (
            'nodetype=controller\n'
            'subfunction=controller\n'
            'system_type=Standard\n'
        )
        mock_subproc.side_effect = (
            subprocess.CalledProcessError(1, 'crictl'))
        file_map = {
            'isolated': '\n',
            'online': '0-15\n',
            'k8sinfra': '0-3\n',
            'platform.conf': platconf,
            'cpu_manager_state': json.dumps(state),
            'node0': '0-7\n',
        }
        with _patch_fs(file_map, ['node0']):
            ret = kube_cpusets.gather_info_and_display()
        self.assertEqual(ret, 1)

    @patch('subprocess.check_output')
    @patch('socket.gethostname', return_value='testhost')
    def test_gather_info_container_no_cpus(
            self, _hostname, mock_subproc):
        """Verify gather_info_container_no returns 0."""
        state = {
            'policyName': 'none',
            'defaultCpuSet': '0-15',
            'entries': {}
        }
        platconf = (
            'nodetype=controller\n'
            'subfunction=controller\n'
            'system_type=Standard\n'
        )
        crictl_ps = json.dumps({
            'containers': [{
                'id': 'abc1234567890xyz',
                'metadata': {'name': 'c1'},
                'labels': {
                    'io.kubernetes.pod.name': 'p1',
                    'io.kubernetes.container.name': 'c1',
                    'io.kubernetes.pod.namespace':
                        'default',
                },
                'state': 'CONTAINER_RUNNING',
            }]
        })
        crictl_inspect = json.dumps({
            'info': {
                'runtimeSpec': {
                    'linux': {
                        'cgroupsPath':
                            '/kubepods/besteffort/'
                            'pod1/ctr1',
                        'resources': {
                            'cpu': {
                                'shares': 2,
                            }
                        }
                    }
                }
            }
        })
        mock_subproc.side_effect = [
            "tmpfs\n",                   # stat cgroup (v1)
            crictl_ps.encode(),
            crictl_inspect.encode(),
        ]
        file_map = {
            'isolated': '\n',
            'online': '0-15\n',
            'k8sinfra': '0-3\n',
            'platform.conf': platconf,
            'cpu_manager_state': json.dumps(state),
            'node0': '0-7\n',
            'node1': '8-15\n',
        }
        with _patch_fs(file_map, ['node0', 'node1']):
            ret = kube_cpusets.gather_info_and_display()
        self.assertEqual(ret, 0)

    @patch('subprocess.check_output')
    @patch('socket.gethostname', return_value='testhost')
    def test_gather_info_crictl_inspect_error(
            self, _hostname, mock_subproc):
        """Test with crictl inspect failure."""
        state = {
            'policyName': 'static',
            'defaultCpuSet': '0-3',
            'entries': {}
        }
        platconf = (
            'nodetype=controller\n'
            'subfunction=controller\n'
            'system_type=Standard\n'
        )
        crictl_ps = json.dumps({
            'containers': [{
                'id': 'abc1234567890xyz',
                'metadata': {'name': 'c1'},
                'labels': {
                    'io.kubernetes.pod.name': 'p1',
                    'io.kubernetes.container.name': 'c1',
                    'io.kubernetes.pod.namespace':
                        'default',
                },
                'state': 'CONTAINER_RUNNING',
            }]
        })
        mock_subproc.side_effect = [
            "tmpfs\n",                   # stat cgroup (v1)
            crictl_ps.encode(),
            subprocess.CalledProcessError(
                1, 'crictl inspect'),
        ]
        file_map = {
            'isolated': '\n',
            'online': '0-15\n',
            'k8sinfra': '0-3\n',
            'platform.conf': platconf,
            'cpu_manager_state': json.dumps(state),
            'node0': '0-7\n',
        }
        with _patch_fs(file_map, ['node0']):
            ret = kube_cpusets.gather_info_and_display()
        self.assertEqual(ret, 1)


class TestMain(unittest.TestCase):
    """Tests for main function."""

    @patch('sys.exit')
    @patch('os.geteuid', return_value=1)
    def test_main_non_root(self, _euid, mock_exit):
        """Verify main_non returns 1."""
        with patch('sys.argv', ['kube-cpusets']):
            kube_cpusets.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 1)

    @patch('sys.exit')
    @patch('kube_cpusets.kube_cpusets.gather_info_and_display',
           return_value=0)
    @patch('os.geteuid', return_value=0)
    def test_main_success(self, _euid, _gather, mock_exit):
        """Verify main_success returns 0 on success."""
        with patch('sys.argv', ['kube-cpusets']):
            kube_cpusets.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)

    @patch('sys.exit')
    @patch('kube_cpusets.kube_cpusets.gather_info_and_display',
           side_effect=KeyboardInterrupt)
    @patch('os.geteuid', return_value=0)
    def test_main_keyboard_interrupt(
            self, _euid, _gather, mock_exit):
        """Verify main_keyboard returns 0."""
        with patch('sys.argv', ['kube-cpusets']):
            kube_cpusets.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)

    @patch('sys.exit')
    @patch('kube_cpusets.kube_cpusets.gather_info_and_display',
           side_effect=IOError)
    @patch('os.geteuid', return_value=0)
    def test_main_ioerror(
            self, _euid, _gather, mock_exit):
        """Verify main_ioerror returns 0 on exception."""
        with patch('sys.argv', ['kube-cpusets']):
            kube_cpusets.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)

    @patch('sys.exit')
    @patch('kube_cpusets.kube_cpusets.gather_info_and_display',
           side_effect=RuntimeError("test"))
    @patch('os.geteuid', return_value=0)
    def test_main_generic_exception(
            self, _euid, _gather, mock_exit):
        """Verify main exits with -4 on RuntimeError."""
        with patch('sys.argv', ['kube-cpusets']):
            kube_cpusets.main()
        self.assertEqual(
            mock_exit.call_args[0][0], -4)

    @patch('sys.exit')
    @patch('kube_cpusets.kube_cpusets.gather_info_and_display',
           return_value=0)
    @patch('os.geteuid', return_value=0)
    def test_main_debug_mode(
            self, _euid, _gather, mock_exit):
        """Test main with --debug flag."""
        with patch('sys.argv', ['kube-cpusets', '--debug']):
            kube_cpusets.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)


if __name__ == '__main__':
    unittest.main()
