#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for plugin_common.py module."""

import os
import sys
import unittest
from unittest.mock import MagicMock
from unittest.mock import mock_open
from unittest.mock import patch

# Mock all external deps before import
sys.modules.setdefault('collectd', MagicMock())
sys.modules['httplib2'] = MagicMock()  # Must be mock - tests control Http.return_value
sys.modules.setdefault('tsconfig', MagicMock())
sys.modules.setdefault('tsconfig.tsconfig', MagicMock())
sys.modules.setdefault('fm_api', MagicMock())
sys.modules.setdefault('fm_api.constants', MagicMock())
sys.modules.setdefault('fm_api.fm_api', MagicMock())

# Set __version__ for kubernetes

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the real plugin_common, saving/restoring any mock
_saved = sys.modules.pop('plugin_common', None)
import importlib
_spec = importlib.util.spec_from_file_location(
    "plugin_common_real",
    os.path.join(os.path.dirname(__file__), '..', 'src', 'plugin_common.py'))
pc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pc)
if _saved is not None:
    sys.modules['plugin_common'] = _saved
import json
import shutil
import subprocess
import tempfile


class TestPluginObject(unittest.TestCase):
    """Tests for PluginObject class."""

    def test_init(self):
        """Verify POD_object stores uid and namespace."""
        obj = pc.PluginObject('test_plugin', 'http://localhost')
        self.assertEqual(obj.plugin, 'test_plugin')
        self.assertEqual(obj.url, 'http://localhost')
        self.assertFalse(obj.init_complete)

    def test_init_completed(self):
        """Verify init_completed sets hostname and base_eid."""
        obj = pc.PluginObject('test', '')
        with patch('socket.gethostname', return_value='host1'):
            obj.init_completed()
        self.assertTrue(obj.init_complete)
        self.assertEqual(obj.hostname, 'host1')
        self.assertEqual(obj.base_eid, 'host=host1')

    def test_gethostname_success(self):
        """Verify gethostname returns hostname string."""
        obj = pc.PluginObject('test', '')
        with patch('socket.gethostname', return_value='myhost'):
            self.assertEqual(obj.gethostname(), 'myhost')

    def test_gethostname_failure(self):
        """Verify gethostname returns None on exception."""
        obj = pc.PluginObject('test', '')
        with patch('socket.gethostname', side_effect=Exception):
            self.assertIsNone(obj.gethostname())

    def test_gethostname_empty(self):
        """Verify gethostname returns None for empty string."""
        obj = pc.PluginObject('test', '')
        with patch('socket.gethostname', return_value=''):
            self.assertIsNone(obj.gethostname())

    def test_config_complete_true(self):
        """Verify config_complete returns True when cached."""
        obj = pc.PluginObject('test', '')
        obj._config_complete = True
        self.assertTrue(obj.config_complete())

    def test_config_complete_false_no_flag(self):
        """Verify config_complete False when flag file missing."""
        obj = pc.PluginObject('test', '')
        mock_tsc = MagicMock()
        mock_tsc.nodetype = 'worker'
        mock_tsc.subfunctions = 'worker'
        mock_tsc.VOLATILE_WORKER_CONFIG_COMPLETE = '/tmp/nonexistent'
        with patch.object(pc, 'tsc', mock_tsc), \
             patch('os.path.exists', return_value=False):
            self.assertFalse(obj.config_complete())

    def test_config_complete_flag_exists(self):
        """Verify config_complete True when controller flag exists."""
        obj = pc.PluginObject('test', '')
        obj._config_complete = False
        mock_tsc = MagicMock()
        mock_tsc.nodetype = 'controller'
        mock_tsc.subfunctions = 'controller'
        mock_tsc.VOLATILE_CONTROLLER_CONFIG_COMPLETE = '/tmp/flag'
        with patch.object(pc, 'tsc', mock_tsc), \
             patch('os.path.exists', return_value=True):
            self.assertTrue(obj.config_complete())

    def test_config_complete_storage(self):
        """Verify config_complete True for storage node."""
        obj = pc.PluginObject('test', '')
        obj._config_complete = False
        mock_tsc = MagicMock()
        mock_tsc.nodetype = 'storage'
        mock_tsc.subfunctions = 'storage'
        mock_tsc.VOLATILE_STORAGE_CONFIG_COMPLETE = '/tmp/flag'
        with patch.object(pc, 'tsc', mock_tsc), \
             patch('os.path.exists', return_value=True):
            self.assertTrue(obj.config_complete())

    def test_config_complete_throttle_log(self):
        """Verify log_throttle_count resets after threshold."""
        obj = pc.PluginObject('test', '')
        obj._config_complete = False
        obj.log_throttle_count = 51
        mock_tsc = MagicMock()
        mock_tsc.nodetype = 'worker'
        mock_tsc.subfunctions = 'worker'
        mock_tsc.VOLATILE_WORKER_CONFIG_COMPLETE = '/tmp/nonexistent'
        with patch.object(pc, 'tsc', mock_tsc), \
             patch('os.path.exists', return_value=False):
            obj.config_complete()
        self.assertEqual(obj.log_throttle_count, 0)

    def test_node_ready_controller(self):
        """Verify node_ready False before threshold on controller."""
        obj = pc.PluginObject('test', '')
        mock_tsc = MagicMock()
        mock_tsc.nodetype = 'controller'
        obj.node_ready_count = 0
        obj.node_ready_threshold = 3
        with patch.object(pc, 'tsc', mock_tsc):
            self.assertFalse(obj.node_ready())
        self.assertEqual(obj.node_ready_count, 1)

    def test_node_ready_controller_threshold(self):
        """Verify node_ready True at threshold on controller."""
        obj = pc.PluginObject('test', '')
        mock_tsc = MagicMock()
        mock_tsc.nodetype = 'controller'
        obj.node_ready_count = 3
        obj.node_ready_threshold = 3
        with patch.object(pc, 'tsc', mock_tsc):
            self.assertTrue(obj.node_ready())

    def test_node_ready_worker(self):
        """Verify node_ready always True for worker node."""
        obj = pc.PluginObject('test', '')
        mock_tsc = MagicMock()
        mock_tsc.nodetype = 'worker'
        with patch.object(pc, 'tsc', mock_tsc):
            self.assertTrue(obj.node_ready())

    def test_is_virtual_true(self):
        """Verify is_virtual True when facter returns true."""
        obj = pc.PluginObject('test', '')
        obj.hostname = 'host1'
        obj.plugin = 'test'
        with patch.object(pc, 'processutils') as mock_pu:
            mock_pu.execute.return_value = ('true\n', '')
            self.assertTrue(obj.is_virtual())

    def test_is_virtual_false(self):
        """Verify is_virtual False when facter returns false."""
        obj = pc.PluginObject('test', '')
        obj.hostname = 'host1'
        obj.plugin = 'test'
        with patch.object(pc, 'processutils') as mock_pu:
            mock_pu.execute.return_value = ('false\n', '')
            self.assertFalse(obj.is_virtual())

    def test_is_virtual_error(self):
        """Verify is_virtual False on stderr output."""
        obj = pc.PluginObject('test', '')
        obj.plugin = 'test'
        with patch.object(pc, 'processutils') as mock_pu:
            mock_pu.execute.return_value = ('', 'error')
            self.assertFalse(obj.is_virtual())

    def test_check_for_fit_no_file(self):
        """Verify check_for_fit True when FIT file absent."""
        obj = pc.PluginObject('test', '')
        with patch('os.path.exists', return_value=False):
            self.assertTrue(obj.check_for_fit('test', 0))

    def test_check_for_fit_valid(self):
        """Verify check_for_fit False and sets usage from file."""
        obj = pc.PluginObject('test', '')
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data='0 89\n')):
            result = obj.check_for_fit('test', 0)
        self.assertFalse(result)
        self.assertEqual(obj.usage, 89.0)

    def test_check_for_fit_single_value(self):
        """Verify check_for_fit parses single float value."""
        obj = pc.PluginObject('test', '')
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data='42.5\n')):
            result = obj.check_for_fit('test', 0)
        self.assertFalse(result)
        self.assertEqual(obj.usage, 42.5)

    def test_check_for_fit_bad_data(self):
        """Verify check_for_fit True on unparseable data."""
        obj = pc.PluginObject('test', '')
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data='bad data\n')):
            result = obj.check_for_fit('test', 0)
        self.assertTrue(result)

    def test_clear_alarm_success(self):
        """Verify clear_alarm returns True on success."""
        obj = pc.PluginObject('test', '')
        fault_mgr = MagicMock()
        fault_mgr.clear_fault.return_value = True
        self.assertTrue(obj.clear_alarm(fault_mgr, '100.103', 'host=h1'))

    def test_clear_alarm_already_cleared(self):
        """Verify clear_alarm True when already cleared."""
        obj = pc.PluginObject('test', '')
        fault_mgr = MagicMock()
        fault_mgr.clear_fault.return_value = False
        self.assertTrue(obj.clear_alarm(fault_mgr, '100.103', 'host=h1'))

    def test_clear_alarm_exception(self):
        """Verify clear_alarm returns False on exception."""
        obj = pc.PluginObject('test', '')
        fault_mgr = MagicMock()
        fault_mgr.clear_fault.side_effect = Exception("fail")
        self.assertFalse(obj.clear_alarm(fault_mgr, '100.103', 'host=h1'))

    def test_make_http_request_success(self):
        """Verify make_http_request parses JSON response."""
        obj = pc.PluginObject('test', 'http://localhost')
        mock_http = MagicMock()
        mock_http.request.return_value = (
            {'status': '200'}, b'{"key": "value"}')
        httplib2 = sys.modules['httplib2']
        httplib2.Http.return_value = mock_http
        self.assertTrue(obj.make_http_request())
        self.assertEqual(obj.jresp, {"key": "value"})

    def test_make_http_request_exception(self):
        """Verify make_http_request False on connection error."""
        obj = pc.PluginObject('test', 'http://localhost')
        httplib2 = sys.modules['httplib2']
        httplib2.Http.return_value.request.side_effect = (
            Exception("conn refused"))
        self.assertFalse(obj.make_http_request())
        httplib2.Http.return_value.request.side_effect = None

    def test_make_http_request_parse_error(self):
        """Verify make_http_request False on invalid JSON."""
        obj = pc.PluginObject('test', 'http://localhost')
        mock_http = MagicMock()
        mock_http.request.return_value = (
            {'status': '200'}, b'not json')
        httplib2 = sys.modules['httplib2']
        httplib2.Http.return_value = mock_http
        self.assertFalse(obj.make_http_request())


class TestK8sClient(unittest.TestCase):
    """Tests for K8sClient class."""

    def test_init(self):
        """Verify K8sClient _kube_client_core is None."""
        with patch('socket.gethostname', return_value='host1'):
            kube_client = pc.K8sClient()
        self.assertIsNone(kube_client._kube_client_core)

    def test_get_namespace_labels(self):
        """Verify _get_namespace_labels extracts labels."""
        with patch('socket.gethostname', return_value='host1'):
            kube_client = pc.K8sClient()
        labels = kube_client._get_namespace_labels([
            {"metadata": {"name": "ns1", "labels": {"k": "v"}}},
            {"metadata": {"name": "ns2"}},
        ])
        self.assertEqual(labels["ns1"], {"k": "v"})
        self.assertEqual(labels["ns2"], {})

    def test_kube_get_local_pods_timeout(self):
        """Verify kube_get_local_pods returns [] on timeout."""
        with patch('socket.gethostname', return_value='host1'):
            kube_client = pc.K8sClient()
        six_mod = sys.modules['six']
        six_mod.PY2 = False
        with patch('subprocess.check_output',
                   side_effect=subprocess.TimeoutExpired('cmd', 2)):
            result = kube_client.kube_get_local_pods()
        self.assertEqual(result, [])

    def test_kube_get_local_pods_json_error(self):
        """Verify kube_get_local_pods returns [] on bad JSON."""
        with patch('socket.gethostname', return_value='host1'):
            kube_client = pc.K8sClient()
        six_mod = sys.modules['six']
        six_mod.PY2 = False
        with patch('subprocess.check_output',
                   return_value=b'not json'):
            result = kube_client.kube_get_local_pods()
        self.assertEqual(result, [])

    def test_kube_get_local_pods_called_process_error(self):
        """Verify kube_get_local_pods returns [] on CalledProcessError."""
        with patch('socket.gethostname', return_value='host1'):
            kube_client = pc.K8sClient()
        six_mod = sys.modules['six']
        six_mod.PY2 = False
        with patch('subprocess.check_output',
                   side_effect=subprocess.CalledProcessError(1, 'cmd')):
            result = kube_client.kube_get_local_pods()
        self.assertEqual(result, [])

    def test_get_namespace_labels_api(self):
        """Verify get_namespace_labels parses kubectl output."""
        with patch('socket.gethostname', return_value='host1'):
            kube_client = pc.K8sClient()
        data = {"items": [
            {"metadata": {"name": "ns1", "labels": {"a": "b"}}}
        ]}
        with patch('subprocess.check_output',
                   return_value=json.dumps(data).encode()):
            result = kube_client.get_namespace_labels()
        self.assertEqual(result, {"ns1": {"a": "b"}})

    def test_get_namespace_labels_timeout(self):
        """Verify get_namespace_labels returns {} on timeout."""
        with patch('socket.gethostname', return_value='host1'):
            kube_client = pc.K8sClient()
        with patch('subprocess.check_output',
                   side_effect=subprocess.TimeoutExpired('cmd', 2)):
            result = kube_client.get_namespace_labels()
        self.assertEqual(result, {})


class TestPODObject(unittest.TestCase):
    """Tests for POD_object class."""

    def test_init(self):
        """Verify POD_object stores uid and namespace."""
        pod = pc.POD_object('uid1', 'name1', 'kube-system', 'Guaranteed')
        self.assertEqual(pod.uid, 'uid1')
        self.assertEqual(pod.namespace, 'kube-system')

    def test_is_platform_resource_system(self):
        """Verify kube-system namespace is platform resource."""
        pod = pc.POD_object('u', 'n', 'kube-system', 'G')
        self.assertTrue(pod.is_platform_resource())

    def test_is_platform_resource_label(self):
        """Verify platform_label=True is platform resource."""
        pod = pc.POD_object('u', 'n', 'other', 'G', platform_label=True)
        self.assertTrue(pod.is_platform_resource())

    def test_is_not_platform_resource(self):
        """Verify default namespace is not platform resource."""
        pod = pc.POD_object('u', 'n', 'default', 'G')
        self.assertFalse(pod.is_platform_resource())

    def test_str(self):
        """Verify POD_object __str__ includes uid field."""
        pod = pc.POD_object('u', 'n', 'ns', 'G')
        self.assertIn('uid', str(pod))


class TestUtilityFunctions(unittest.TestCase):
    """Tests for module-level utility functions."""

    def test_is_uuid_like_valid(self):
        """Verify is_uuid_like True for valid UUID string."""
        self.assertTrue(
            pc.is_uuid_like('12345678-1234-1234-1234-123456789abc'))

    def test_is_uuid_like_invalid(self):
        """Verify is_uuid_like False for non-UUID string."""
        self.assertFalse(pc.is_uuid_like('not-a-uuid'))

    def test_is_uuid_like_none(self):
        """Verify is_uuid_like False for None input."""
        self.assertFalse(pc.is_uuid_like(None))

    def test_get_severity_str(self):
        """Verify get_severity_str maps all severity levels."""
        mock_fc = MagicMock()
        mock_fc.FM_ALARM_SEVERITY_CLEAR = 'clear'
        mock_fc.FM_ALARM_SEVERITY_CRITICAL = 'critical'
        mock_fc.FM_ALARM_SEVERITY_MAJOR = 'major'
        mock_fc.FM_ALARM_SEVERITY_MINOR = 'minor'
        with patch.object(pc, 'fm_constants', mock_fc):
            self.assertEqual(pc.get_severity_str('clear'), 'clear')
            self.assertEqual(pc.get_severity_str('critical'), 'critical')
            self.assertEqual(pc.get_severity_str('major'), 'major')
            self.assertEqual(pc.get_severity_str('minor'), 'minor')
            self.assertEqual(pc.get_severity_str('other'), 'unknown')

    def test_convert2boolean(self):
        """Verify convert2boolean handles all input types."""
        self.assertTrue(pc.convert2boolean(True))
        self.assertFalse(pc.convert2boolean(False))
        self.assertTrue(pc.convert2boolean(1))
        self.assertFalse(pc.convert2boolean(0))
        self.assertTrue(pc.convert2boolean('yes'))
        self.assertTrue(pc.convert2boolean('true'))
        self.assertFalse(pc.convert2boolean('no'))
        self.assertFalse(pc.convert2boolean(None))

    def test_range_to_list(self):
        """Verify range_to_list parses ranges and handles None."""
        self.assertEqual(pc.range_to_list('1-3,8-9,15'),
                         [1, 2, 3, 8, 9, 15])
        self.assertEqual(pc.range_to_list(None), [])
        self.assertEqual(pc.range_to_list(''), [])

    def test_format_range_set(self):
        """Verify format_range_set formats contiguous ranges."""
        self.assertEqual(pc.format_range_set({1, 2, 3, 8, 9}), '1-3,8-9')
        self.assertEqual(pc.format_range_set({5}), '5')
        self.assertEqual(pc.format_range_set(set()), '')

    def test_walklevel(self):
        """Verify walklevel at level=0 yields one entry."""
        temp_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(temp_dir, 'a', 'b'), exist_ok=True)
        results = list(pc.walklevel(temp_dir, level=0))
        self.assertEqual(len(results), 1)
        shutil.rmtree(temp_dir)

    def test_get_debian_codename(self):
        """Verify get_debian_codename parses os-release."""
        data = "ID=debian\nVERSION_CODENAME=bullseye\n"
        with patch('builtins.open', mock_open(read_data=data)):
            result = pc.get_debian_codename()
        self.assertEqual(result, 'bullseye')

    def test_get_debian_codename_not_found(self):
        """Verify get_debian_codename None when file missing."""
        with patch('builtins.open', side_effect=FileNotFoundError):
            result = pc.get_debian_codename()
        self.assertIsNone(result)

    def test_get_debian_codename_no_match(self):
        """Verify get_debian_codename None without codename."""
        data = "ID=debian\n"
        with patch('builtins.open', mock_open(read_data=data)):
            result = pc.get_debian_codename()
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
