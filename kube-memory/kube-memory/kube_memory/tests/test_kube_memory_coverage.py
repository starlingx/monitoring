#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive unit tests for kube_memory module."""

import json
import subprocess
import unittest
from unittest.mock import MagicMock
from unittest.mock import mock_open
from unittest.mock import patch

import prettytable

from kube_memory import kube_memory


class TestPy2Round(unittest.TestCase):
    """Tests for py2_round function."""

    def test_positive_round_up(self):
        """Verify py2_round rounds 2.5 up to 3.0."""
        self.assertEqual(kube_memory.py2_round(2.5, 0), 3.0)

    def test_positive_round_down(self):
        """Verify py2_round rounds 2.4 down to 2.0."""
        self.assertEqual(kube_memory.py2_round(2.4, 0), 2.0)

    def test_negative_round(self):
        """Verify py2_round rounds -2.5 to -3.0."""
        self.assertEqual(kube_memory.py2_round(-2.5, 0), -3.0)

    def test_decimal_precision(self):
        """Verify py2_round with 2 decimal places."""
        result = kube_memory.py2_round(3.14159, 2)
        self.assertEqual(result, 3.14)

    def test_zero(self):
        """Verify py2_round of zero returns 0.0."""
        self.assertEqual(kube_memory.py2_round(0, 2), 0.0)


class TestMemToMebibytes(unittest.TestCase):
    """Tests for mem_to_mebibytes function."""

    def test_valid_bytes(self):
        """Verify valid_bytes returns '1.0' with valid input."""
        result = kube_memory.mem_to_mebibytes(1048576)
        self.assertEqual(result, '1.0')

    def test_zero_bytes(self):
        """Verify zero_bytes returns '0.0'."""
        result = kube_memory.mem_to_mebibytes(0)
        self.assertEqual(result, '0.0')

    def test_invalid_value(self):
        """Verify invalid_value returns '-' with invalid input."""
        result = kube_memory.mem_to_mebibytes('invalid')
        self.assertEqual(result, '-')

    def test_none_value(self):
        """Verify none_value returns '-' with None input."""
        result = kube_memory.mem_to_mebibytes(None)
        self.assertEqual(result, '-')

    def test_large_value(self):
        """Verify large_value returns '1024.0'."""
        result = kube_memory.mem_to_mebibytes(1073741824)
        self.assertEqual(result, '1024.0')


class TestPidFromContainer(unittest.TestCase):
    """Tests for pid_from_container function."""

    @patch('subprocess.check_output',
           return_value=b'12345\n')
    def test_valid_container(self, _subproc):
        """Verify pid_from_container returns pid bytes."""
        result = kube_memory.pid_from_container('abc123')
        self.assertEqual(result, b'12345\n')

    @patch('subprocess.check_output',
           side_effect=__import__(
               'subprocess').CalledProcessError(1, 'pgrep'))
    def test_invalid_container(self, _subproc):
        """Verify invalid_container returns 1 on exception."""
        result = kube_memory.pid_from_container('invalid')
        self.assertEqual(result, 1)


class TestGetMemoryCgroups(unittest.TestCase):
    """Tests for get_memory_cgroups function."""

    @patch('os.path.isdir', return_value=True)
    @patch('os.listdir',
           return_value=['docker', 'system.slice', 'file.txt'])
    def test_returns_dirs_only(self, _listdir, _isdir):
        """Verify returns_dirs 'system.slice' in result."""
        result = kube_memory.get_memory_cgroups()
        self.assertIn('docker', result)
        self.assertIn('system.slice', result)


class TestGetMeminfo(unittest.TestCase):
    """Tests for get_meminfo function."""

    def test_valid_meminfo(self):
        """Verify get_meminfo parses MemTotal and MemFree."""
        content = (
            'MemTotal: 16384 kB\n'
            'MemFree: 8192 kB\n'
            'MemAvailable: 12288 kB\n'
        )
        mopen = mock_open(read_data=content)
        with patch('builtins.open', mopen):
            result = kube_memory.get_meminfo()
        self.assertEqual(result['MemTotal'], 16384)
        self.assertEqual(result['MemFree'], 8192)

    def test_ioerror(self):
        """Test IOError returns empty dict."""
        with patch('builtins.open',
                   side_effect=IOError("test")):
            result = kube_memory.get_meminfo()
        self.assertEqual(result, {})


class TestGetPlatformReservedMemory(unittest.TestCase):
    """Tests for get_platform_reserved_memory function."""

    @patch('os.path.exists', return_value=True)
    def test_valid_reserved(self, _exists):
        """Verify reserved memory sums node values."""
        content = (
            'WORKER_BASE_RESERVED='
            '("node0:1500MB:1" "node1:1500MB:1")\n'
        )
        mopen = mock_open(read_data=content)
        with patch('builtins.open', mopen):
            result = kube_memory.get_platform_reserved_memory()
        self.assertEqual(result, 3000.0)

    @patch('os.path.exists', return_value=False)
    def test_no_file(self, _exists):
        """Test returns 0 when file doesn't exist."""
        result = kube_memory.get_platform_reserved_memory()
        self.assertEqual(result, 0.0)

    @patch('os.path.exists', return_value=True)
    def test_file_read_error(self, _exists):
        """Verify reserved memory returns 0 on PermissionError."""
        with patch('builtins.open',
                   side_effect=PermissionError("denied")):
            result = kube_memory.get_platform_reserved_memory()
        self.assertEqual(result, 0.0)

    @patch('os.path.exists', return_value=True)
    def test_no_matching_line(self, _exists):
        """Verify reserved memory returns 0 without key."""
        content = 'SOME_OTHER_KEY=value\n'
        mopen = mock_open(read_data=content)
        with patch('builtins.open', mopen):
            result = kube_memory.get_platform_reserved_memory()
        self.assertEqual(result, 0.0)


class TestPipeCommand(unittest.TestCase):
    """Tests for pipe_command function."""

    @patch('subprocess.Popen')
    def test_single_command(self, mock_popen):
        """Verify single_command returns 'output'."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b'output', b'')
        mock_proc.stdout = MagicMock()
        mock_popen.return_value = mock_proc
        result = kube_memory.pipe_command(['echo', 'test'])
        self.assertEqual(result, 'output')

    @patch('subprocess.Popen')
    def test_two_commands(self, mock_popen):
        """Verify two_commands returns 'filtered'."""
        mock_proc1 = MagicMock()
        mock_proc1.stdout = MagicMock()
        mock_proc2 = MagicMock()
        mock_proc2.communicate.return_value = (
            b'filtered', b'')
        mock_popen.side_effect = [mock_proc1, mock_proc2]
        result = kube_memory.pipe_command(
            ['echo', 'test'], ['grep', 'test'])
        self.assertEqual(result, 'filtered')


class TestGatherGroupsMemory(unittest.TestCase):
    """Tests for gather_groups_memory function."""

    @patch.object(kube_memory, 'get_memory_cgroups',
                  return_value=['docker', 'system.slice'])
    def test_valid_output(self, _groups):
        """Verify valid_output 'docker' in kube_memory.MEMORY[...]."""
        output = (
            "docker/memory.stat:total_rss 1048576\n"
            "system.slice/memory.stat:total_rss 2097152\n"
        )
        kube_memory.MEMORY['cgroups'] = {}
        result = kube_memory.gather_groups_memory(output)
        self.assertIsNotNone(result)
        self.assertIn('docker', kube_memory.MEMORY['cgroups'])


class TestGatherContainersMemory(unittest.TestCase):
    """Tests for gather_containers_memory function."""

    @patch('subprocess.check_output')
    def test_crictl_error(self, mock_subproc):
        """Verify crictl_error returns 1 on failure."""
        mock_subproc.side_effect = (
            subprocess.CalledProcessError(1, 'crictl'))
        result = kube_memory.gather_containers_memory(
            "test output")
        self.assertEqual(result, 1)

    @patch('kube_memory.kube_memory.pid_from_container',
           return_value=b'123\n')
    @patch('subprocess.check_output')
    def test_valid_containers(self, mock_subproc, _pid):
        """Test parsing valid container data."""
        crictl_output = json.dumps({
            'containers': [{
                'id': 'abc1234567890xyz',
                'metadata': {'name': 'c1'},
                'labels': {
                    'io.kubernetes.pod.name': 'p1',
                    'io.kubernetes.container.name': 'c1',
                    'io.kubernetes.pod.namespace':
                        'kube-system',
                    'io.kubernetes.pod.uid': 'uid1',
                },
                'podSandboxId': 'sb1234567890abcdef',
                'state': 'CONTAINER_RUNNING',
            }]
        })
        mock_subproc.return_value = crictl_output.encode()
        kube_memory.MEMORY['namespaces'] = {}
        output_mem = (
            "abc1234567890/memory.stat:total_rss 1048576\n"
            "sb1234567890/memory.stat:total_rss 524288\n"
        )
        result = kube_memory.gather_containers_memory(
            output_mem)
        self.assertIsNotNone(result)


class TestSysServiceMemory(unittest.TestCase):
    """Tests for sys_service_memory function."""

    @patch.object(
        kube_memory, 'pipe_command',
        return_value=(
            "system.slice/memory.stat:total_rss "
            "1048576\nsshd.service/memory.stat:total_rss "
            "524288\n"))
    def test_valid_output(self, _pipe):
        """Verify valid_output returns non-None value with valid."""
        result = kube_memory.sys_service_memory()
        self.assertIsNotNone(result)

    @patch.object(
        kube_memory, 'pipe_command',
        side_effect=__import__(
            'subprocess').CalledProcessError(1, 'grep'))
    def test_command_error(self, _pipe):
        """Verify command_error returns 1 on exception."""
        result = kube_memory.sys_service_memory()
        self.assertEqual(result, 1)


class TestGatherInfoAndDisplay(unittest.TestCase):
    """Tests for gather_info_and_display function."""

    @patch.object(
        kube_memory, 'pipe_command',
        side_effect=__import__(
            'subprocess').CalledProcessError(1, 'grep'))
    def test_initial_pipe_error(self, _pipe):
        """Verify initial_pipe returns 1 on exception."""
        result = kube_memory.gather_info_and_display()
        self.assertEqual(result, 1)

    @patch.object(kube_memory,
                  'get_platform_reserved_memory',
                  return_value=3000.0)
    @patch.object(kube_memory, 'sys_service_memory')
    @patch.object(kube_memory, 'gather_containers_memory')
    @patch.object(kube_memory, 'gather_groups_memory')
    @patch.object(kube_memory, 'get_meminfo')
    @patch.object(kube_memory, 'pipe_command',
                  return_value=(
                      "docker/memory.stat:total_rss "
                      "1048576\n"))
    def test_success_path(  # pylint: disable=too-many-arguments
            self, _pipe, mock_meminfo, mock_groups,
            mock_containers, mock_services, _reserved):
        """Verify success_path returns 0 on success."""
        mock_meminfo.return_value = {
            'Active(anon)': 4096,
            'Inactive(anon)': 2048,
            'MemAvailable': 8192,
        }
        table = prettytable.PrettyTable(['Group', 'RSS'])
        table.add_row(['docker', '1.0'])
        table.add_row(['Total cgroup-rss', '1.0'])
        mock_groups.return_value = table

        table2 = prettytable.PrettyTable(
            ['ns', 'pod', 'ctr', 'id',
             'st', 'qos', 'pid', 'rss'])
        mock_containers.return_value = table2

        table3 = prettytable.PrettyTable(['Service', 'RSS'])
        mock_services.return_value = table3

        kube_memory.MEMORY['cgroups'] = {
            'docker': '1.0',
            'system.slice': '0.5',
            'user.slice': '0.2',
            'total_rss': '1.7',
        }
        kube_memory.MEMORY['namespaces'] = {
            'kube-system': 2.0,
            'monitor': 1.0,
        }
        result = kube_memory.gather_info_and_display()
        self.assertEqual(result, 0)


class TestMainFunction(unittest.TestCase):
    """Tests for main function."""

    @patch('sys.exit', side_effect=SystemExit(1))
    @patch('os.geteuid', return_value=1)
    def test_main_non_root(self, _euid, mock_exit):
        """Verify main_non raises SystemExit."""
        with patch('sys.argv', ['kube-memory']):
            with self.assertRaises(SystemExit):
                kube_memory.main()
        mock_exit.assert_called_with(1)

    @patch('sys.exit')
    @patch.object(kube_memory,
                  'gather_info_and_display', return_value=0)
    @patch('os.geteuid', return_value=0)
    def test_main_success(self, _euid, _gather, mock_exit):
        """Verify main_success returns 0 on success."""
        with patch('sys.argv', ['kube-memory']):
            kube_memory.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)

    @patch('sys.exit')
    @patch.object(kube_memory,
                  'gather_info_and_display',
                  side_effect=KeyboardInterrupt)
    @patch('os.geteuid', return_value=0)
    def test_main_keyboard_interrupt(
            self, _euid, _gather, mock_exit):
        """Verify main_keyboard returns 0."""
        with patch('sys.argv', ['kube-memory']):
            kube_memory.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)

    @patch('sys.exit')
    @patch.object(kube_memory,
                  'gather_info_and_display',
                  side_effect=IOError)
    @patch('os.geteuid', return_value=0)
    def test_main_ioerror(self, _euid, _gather, mock_exit):
        """Verify main_ioerror returns 0 on exception."""
        with patch('sys.argv', ['kube-memory']):
            kube_memory.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)

    @patch('sys.exit')
    @patch.object(kube_memory,
                  'gather_info_and_display',
                  side_effect=RuntimeError("test"))
    @patch('os.geteuid', return_value=0)
    def test_main_generic_exception(
            self, _euid, _gather, mock_exit):
        """Verify main exits with -4 on RuntimeError."""
        with patch('sys.argv', ['kube-memory']):
            kube_memory.main()
        self.assertEqual(
            mock_exit.call_args[0][0], -4)

    @patch('sys.exit')
    @patch.object(kube_memory,
                  'gather_info_and_display', return_value=0)
    @patch('os.geteuid', return_value=0)
    def test_main_debug_mode(self, _euid, _gather, mock_exit):
        """Test main with --debug flag."""
        with patch('sys.argv', ['kube-memory', '--debug']):
            kube_memory.main()
        self.assertEqual(
            mock_exit.call_args[0][0], 0)


if __name__ == '__main__':
    unittest.main()
