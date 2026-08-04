#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import sys
import socket as real_socket
import unittest
from unittest.mock import MagicMock
from unittest.mock import mock_open
from unittest.mock import patch

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
import fm_notifier
import six as six_mock

collectd = sys.modules['collectd']
tsc_mock = sys.modules['tsconfig.tsconfig']
fm_constants = MagicMock()
fm_constants.FM_ALARM_SEVERITY_CLEAR = 0
fm_constants.FM_ALARM_SEVERITY_MINOR = 1
fm_constants.FM_ALARM_SEVERITY_MAJOR = 2
fm_constants.FM_ALARM_SEVERITY_CRITICAL = 3
fm_constants.FM_ALARM_STATE_SET = 'set'
fm_constants.FM_ALARM_STATE_CLEAR = 'clear'
fm_constants.FM_ENTITY_TYPE_HOST = 'host'
fm_constants.FM_ALARM_TYPE_7 = 7
fm_constants.FM_ALARM_TYPE_4 = 4
fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN = 0
fm_constants.ALARM_PROBABLE_CAUSE_50 = 50
fm_constants.ALARM_PROBABLE_CAUSE_29 = 29
fm_constants.FM_ALARM_ID_NETWORK_INTERFACE = '300.002'
fm_constants.FM_ALARM_ID_NETWORK_PROVIDERNET = '300.001'

for mod in [fm_notifier, pc]:

    if hasattr(mod, 'fm_constants'):
        mod.fm_constants = fm_constants


class TestDegradeObject(unittest.TestCase):
    def test_init(self):
        """Verify init returns []."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        self.assertEqual(degrade_obj.port, 2101)
        self.assertIsNone(degrade_obj.addr)
        self.assertEqual(degrade_obj.degrade_list, [])

    @patch('socket.getaddrinfo', return_value=[(None, None, None, None, ('10.0.0.1', 0))])
    def test_get_active_controller_ip(self, mock_addr):
        """Verify get_active_controller_ip returns '10.0.0.1'."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj._get_active_controller_ip()
        self.assertEqual(degrade_obj.addr, '10.0.0.1')

    @patch('socket.getaddrinfo', side_effect=Exception('fail'))
    def test_get_active_controller_ip_fail(self, mock_addr):
        """Verify get_active_controller_ip returns None on exception."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj._get_active_controller_ip()
        self.assertIsNone(degrade_obj.addr)

    @patch('socket.socket')
    def test_mtce_degrade_notifier_assert(self, mock_sock):
        """Verify mtce_degrade returns 'assert'."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.addr = '10.0.0.1'
        degrade_obj.degrade_list = ['cpu:host=controller-0']
        degrade_obj.last_state = 'undef'
        nObj = MagicMock()
        nObj.host = 'controller-0'
        degrade_obj.mtce_degrade_notifier(nObj)
        self.assertEqual(degrade_obj.last_state, 'assert')

    @patch('socket.socket')
    def test_mtce_degrade_notifier_clear(self, mock_sock):
        """Verify mtce_degrade returns 'clear'."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.addr = '10.0.0.1'
        degrade_obj.degrade_list = []
        degrade_obj.last_state = 'undef'
        nObj = MagicMock()
        nObj.host = 'controller-0'
        degrade_obj.mtce_degrade_notifier(nObj)
        self.assertEqual(degrade_obj.last_state, 'clear')

    @patch('socket.socket')
    def test_mtce_degrade_notifier_throttle(self, mock_sock):
        """Verify mtce_degrade returns 1."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.addr = '10.0.0.1'
        degrade_obj.degrade_list = []
        degrade_obj.last_state = 'clear'
        degrade_obj.msg_throttle = 0
        nObj = MagicMock()
        nObj.host = 'controller-0'
        degrade_obj.mtce_degrade_notifier(nObj)
        self.assertEqual(degrade_obj.msg_throttle, 1)

    @patch('socket.socket')
    def test_mtce_degrade_notifier_socket_error_ipv6(self, mock_sock_cls):
        """Verify mtce_degrade_notifier uses IPv6 socket."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.addr = '10.0.0.1'
        degrade_obj.degrade_list = ['cpu:host=c']
        degrade_obj.last_state = 'undef'
        nObj = MagicMock()
        nObj.host = 'controller-0'
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendto.side_effect = real_socket.error(real_socket.EAI_ADDRFAMILY, 'addr family')
        degrade_obj.mtce_degrade_notifier(nObj)
        self.assertEqual(degrade_obj.protocol, real_socket.AF_INET6)

    @patch('socket.socket')
    def test_mtce_degrade_notifier_socket_error_other(self, mock_sock_cls):
        """Verify mtce_degrade returns None on failure."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.addr = '10.0.0.1'
        degrade_obj.degrade_list = ['cpu:host=c']
        degrade_obj.last_state = 'undef'
        nObj = MagicMock()
        nObj.host = 'controller-0'
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendto.side_effect = real_socket.error(99, 'other')
        degrade_obj.mtce_degrade_notifier(nObj)
        self.assertIsNone(degrade_obj.addr)

    @patch('os.path.ismount', return_value=False)
    def test_remove_degrade_for_missing_filesystems(self, mock_mount):
        """Verify remove_degrade_for_missing returns [] when missing."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.degrade_list = ['df:host=c.filesystem=/scratch']
        degrade_obj.remove_degrade_for_missing_filesystems()
        self.assertEqual(degrade_obj.degrade_list, [])

    @patch('os.path.ismount', return_value=True)
    def test_remove_degrade_for_missing_filesystems_mounted(self, mock_mount):
        """Verify remove_degrade_for_missing returns 1 when missing."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.degrade_list = ['df:host=c.filesystem=/scratch']
        degrade_obj.remove_degrade_for_missing_filesystems()
        self.assertEqual(len(degrade_obj.degrade_list), 1)

    def test_remove_degrade_non_df(self):
        """Verify remove_degrade_non_df returns 1."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.degrade_list = ['cpu:host=c']
        degrade_obj.remove_degrade_for_missing_filesystems()
        self.assertEqual(len(degrade_obj.degrade_list), 1)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_failure_add(self, mock_mount):
        """Verify manage_degrade_list_failure returns 1 on failure."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__CPU
        nObj.plugin_instance = ''
        nObj.severity = fm_notifier.NOTIF_FAILURE
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 1)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_okay_remove(self, mock_mount):
        """Verify manage_degrade_list_okay returns 0."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            resource = 'cpu:host=controller-0'
            degrade_obj.degrade_list = [resource]
            nObj = MagicMock()
            nObj.plugin = fm_notifier.PLUGIN__CPU
            nObj.plugin_instance = ''
            nObj.severity = fm_notifier.NOTIF_OKAY
            nObj.host = 'controller-0'
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_warning_add(self, mock_mount):
        """Verify manage_degrade_list_warning returns 1."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__INTERFACE
        nObj.plugin_instance = ''
        nObj.severity = fm_notifier.NOTIF_WARNING
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 1)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_df_instance(self, mock_mount):
        """Verify manage_degrade_list_df returns 1."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__DF
        nObj.plugin_instance = 'root'
        nObj.severity = fm_notifier.NOTIF_FAILURE
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 1)

    def test_manage_degrade_list_df_bad_instance(self):
        """Verify manage_degrade_list_df returns 0."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__DF
        nObj.plugin_instance = 'nonexistent'
        nObj.severity = fm_notifier.NOTIF_FAILURE
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_warning_not_in_list(self, mock_mount):
        """Verify manage_degrade_list_warning returns 0."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__CPU
        nObj.plugin_instance = ''
        nObj.severity = fm_notifier.NOTIF_WARNING
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_failure_no_failure_list(self, mock_mount):
        """Verify manage_degrade_list_failure returns 0 on failure."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.degrade_list__failure = []
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            resource = 'cpu:host=controller-0'
            degrade_obj.degrade_list = [resource]
            nObj = MagicMock()
            nObj.plugin = fm_notifier.PLUGIN__CPU
            nObj.plugin_instance = ''
            nObj.severity = fm_notifier.NOTIF_FAILURE
            nObj.host = 'controller-0'
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_warning_no_warning_list(self, mock_mount):
        """Verify manage_degrade_list_warning returns 0."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.degrade_list__warning = []
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            resource = 'interface:host=controller-0'
            degrade_obj.degrade_list = [resource]
            nObj = MagicMock()
            nObj.plugin = fm_notifier.PLUGIN__INTERFACE
            nObj.plugin_instance = ''
            nObj.severity = fm_notifier.NOTIF_WARNING
            nObj.host = 'controller-0'
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_with_plugin_instance(self, mock_mount):
        """Verify manage_degrade_list_with returns 1."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__CPU
        nObj.plugin_instance = 'platform'
        nObj.severity = fm_notifier.NOTIF_FAILURE
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 1)

    @patch('os.path.ismount', return_value=False)
    def test_manage_degrade_list_df_failure_unmounted(self, mock_mount):
        """Verify manage_degrade_list_df returns 0 on failure."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__DF
        nObj.plugin_instance = 'root'
        nObj.severity = fm_notifier.NOTIF_FAILURE
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)

    @patch('os.path.ismount', return_value=False)
    def test_manage_degrade_list_df_warning_unmounted(self, mock_mount):
        """Verify manage_degrade_list_df returns 0."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        degrade_obj.degrade_list__warning = [fm_notifier.PLUGIN__DF]
        nObj = MagicMock()
        nObj.plugin = fm_notifier.PLUGIN__DF
        nObj.plugin_instance = 'root'
        nObj.severity = fm_notifier.NOTIF_WARNING
        nObj.host = 'controller-0'
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)

    @patch('os.path.ismount', return_value=True)
    def test_manage_degrade_list_warning_remove_not_in_warning_list(self, mock_mount):
        """Test warning remove not in warning list."""
        degrade_obj = fm_notifier.DegradeObject(2101)
        with patch('os.uname', return_value=('', 'controller-0', '', '', '')):
            resource = 'cpu:host=controller-0'
            degrade_obj.degrade_list = [resource]
            nObj = MagicMock()
            nObj.plugin = fm_notifier.PLUGIN__CPU
            nObj.plugin_instance = ''
            nObj.severity = fm_notifier.NOTIF_WARNING
            nObj.host = 'controller-0'
            degrade_obj.manage_degrade_list(nObj)
        self.assertEqual(len(degrade_obj.degrade_list), 0)


class TestFmAlarmObject(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        fm_notifier.fmAlarmObject.host = 'controller-0'
        fm_notifier.fmAlarmObject.lock = fm_notifier.Lock()

    def test_init(self):
        """Verify init returns 'cpu'."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        self.assertEqual(obj.id, '100.101')
        self.assertEqual(obj.plugin, 'cpu')

    def test_manage_alarm_lists_warning_new(self):
        """Verify manage_alarm_lists adds new warning."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.manage_alarm_lists('host=controller-0', 'warning')
        self.assertIn('host=controller-0', obj.warnings)

    def test_manage_alarm_lists_failure_new(self):
        """Verify manage_alarm_lists adds new failure."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.manage_alarm_lists('host=controller-0', 'failure')
        self.assertIn('host=controller-0', obj.failures)

    def test_manage_alarm_lists_same_severity(self):
        """Verify manage_alarm_lists_same returns 'done'."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.warnings = ['host=controller-0']
        result = obj.manage_alarm_lists('host=controller-0', 'warning')
        self.assertEqual(result, 'done')

    def test_manage_alarm_lists_warning_to_failure(self):
        """Verify manage_alarm_lists_warning on failure."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.warnings = ['host=controller-0']
        obj.manage_alarm_lists('host=controller-0', 'failure')
        self.assertIn('host=controller-0', obj.failures)
        self.assertNotIn('host=controller-0', obj.warnings)

    def test_manage_alarm_lists_failure_to_warning(self):
        """Verify manage_alarm_lists_failure on failure."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.failures = ['host=controller-0']
        obj.manage_alarm_lists('host=controller-0', 'warning')
        self.assertIn('host=controller-0', obj.warnings)
        self.assertNotIn('host=controller-0', obj.failures)

    def test_manage_alarm_lists_clear(self):
        """Verify manage_alarm_lists clears existing alarm."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.warnings = ['host=controller-0']
        obj.manage_alarm_lists('host=controller-0', 'okay')
        self.assertNotIn('host=controller-0', obj.warnings)

    def test_manage_alarm_lists_clear_from_failure(self):
        """Verify manage_alarm_lists_clear on failure."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.failures = ['host=controller-0']
        obj.manage_alarm_lists('host=controller-0', 'okay')
        self.assertNotIn('host=controller-0', obj.failures)

    def test_manage_alarm_lists_warning_to_failure_unexpected(self):
        """Verify manage_alarm_lists warning-to-failure."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.failures = ['host=controller-0']
        obj.warnings = ['host=controller-0']
        obj.manage_alarm_lists('host=controller-0', 'warning')
        self.assertIn('host=controller-0', obj.warnings)

    def test_manage_alarm_lists_failure_to_warning_unexpected(self):
        """Verify manage_alarm_lists failure-to-warning."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.warnings = ['host=controller-0']
        obj.failures = ['host=controller-0']
        obj.manage_alarm_lists('host=controller-0', 'failure')
        self.assertIn('host=controller-0', obj.failures)

    def test_get_instance_object(self):
        """Verify get_instance_object finds matching object."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        inst = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.instance_objects['eid1'] = inst
        result = obj._get_instance_object('eid1')
        self.assertEqual(result, inst)

    def test_get_instance_object_none(self):
        """Verify get_instance_object_none returns None with None."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        self.assertIsNone(obj._get_instance_object(None))

    def test_get_instance_object_missing(self):
        """Verify get_instance_object_missing returns None when."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        self.assertIsNone(obj._get_instance_object('missing'))

    def test_add_instance_object(self):
        """Verify add_instance_object 'eid1' in obj.instance_objects."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        inst = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj._add_instance_object(inst, 'eid1')
        self.assertIn('eid1', obj.instance_objects)

    def test_copy_instance_object(self):
        """Verify copy_instance returns 'fix it'."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.resource_name = 'Platform CPU'
        obj.repair = 'fix it'
        target = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj._copy_instance_object(target)
        self.assertEqual(target.resource_name, 'Platform CPU')
        self.assertEqual(target.repair, 'fix it')

    def test_create_instance_object(self):
        """Verify create_instance_object returns 'platform'."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.resource_name = 'Platform CPU'
        inst = obj.create_instance_object('platform')
        self.assertIsNotNone(inst)
        self.assertEqual(inst.instance_name, 'platform')

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', mock_open(read_data='<Plugin "df">\nMountPoint "/"\nMountPoint "/var/log"\n</Plugin>\n'))  # noqa: E501
    def test_create_instance_objects_df(self, mock_exists):
        """Verify create_instance_objects builds df objects."""
        fm_notifier.fmAlarmObject.plugin_path = '/etc/collectd.d/'
        obj = fm_notifier.fmAlarmObject(fm_notifier.ALARM_ID__DF, fm_notifier.PLUGIN__DF)
        obj.resource_name = 'File System'
        obj.create_instance_objects()
        self.assertGreater(len(obj.instance_objects), 0)

    @patch('os.path.exists', return_value=False)
    def test_create_instance_objects_df_no_conf(self, mock_exists):
        """Verify create_instance_objects fails on bad config."""
        fm_notifier.fmAlarmObject.plugin_path = '/etc/collectd.d/'
        obj = fm_notifier.fmAlarmObject(fm_notifier.ALARM_ID__DF, fm_notifier.PLUGIN__DF)
        result = obj.create_instance_objects()
        self.assertEqual(result, fm_notifier.FAIL)

    def test_manage_change_no_update(self):
        """Verify manage_change_no_update returns 'done'."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.entity_id = 'host=controller-0'
        nObj = MagicMock()
        nObj.message = 'has not been updated for 10 seconds'
        nObj.severity = 4
        result = obj.manage_change(nObj)
        self.assertEqual(result, 'done')

    def test_manage_change_current_value(self):
        """Verify manage_change updates current value."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.entity_id = 'host=controller-0'
        obj.resource_name = 'Platform CPU'
        obj.count = 0
        nObj = MagicMock()
        nObj.message = 'Current value of "value" is 51.41.'
        nObj.severity = 4
        result = obj.manage_change(nObj)
        self.assertIsNone(result)
        self.assertAlmostEqual(obj.value, 51.41, places=1)

    def test_manage_change_threshold(self):
        """Verify manage_change detects threshold crossing."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.entity_id = 'host=controller-0'
        obj.resource_name = 'Platform CPU'
        obj.count = 0
        nObj = MagicMock()
        nObj.message = 'Data source "value" is currently 97.46. That is above the failure threshold of 90.00.'
        nObj.severity = 1
        result = obj.manage_change(nObj)
        self.assertIsNone(result)
        self.assertAlmostEqual(obj.threshold, 90.0, places=0)

    def test_manage_change_no_value(self):
        """Verify manage_change_no_value returns 'done'."""
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj.entity_id = 'host=controller-0'
        nObj = MagicMock()
        nObj.message = 'no value here'
        nObj.severity = 4
        result = obj.manage_change(nObj)
        self.assertEqual(result, 'done')

    def test_debounce_no_change(self):
        """Verify debounce_no returns False."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        result = obj.debounce(base, 'eid', 'okay', 10.0)
        self.assertFalse(result)

    def test_debounce_okay_to_warning(self):
        """Verify debounce_okay returns True."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        for _ in range(fm_notifier.DEBOUNCE_FROM_CLEAR_THLD):
            result = obj.debounce(base, 'eid', 'warning', 85.0)
        self.assertTrue(result)

    def test_debounce_okay_to_failure(self):
        """Verify debounce_okay returns True on failure."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        for _ in range(fm_notifier.DEBOUNCE_FROM_CLEAR_THLD):
            result = obj.debounce(base, 'eid', 'failure', 95.0)
        self.assertTrue(result)

    def test_debounce_failure_to_okay(self):
        """Verify debounce_failure returns True on failure."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        base.failures = ['eid']
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        for _ in range(fm_notifier.DEBOUNCE_FROM_ASSERT_THLD):
            result = obj.debounce(base, 'eid', 'okay', 10.0)
        self.assertTrue(result)

    def test_debounce_failure_to_warning(self):
        """Verify debounce_failure returns True on failure."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        base.failures = ['eid']
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        for _ in range(fm_notifier.DEBOUNCE_FROM_ASSERT_THLD):
            result = obj.debounce(base, 'eid', 'warning', 80.0)
        self.assertTrue(result)

    def test_debounce_warning_to_okay(self):
        """Verify debounce_warning returns True."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        base.warnings = ['eid']
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        for _ in range(fm_notifier.DEBOUNCE_FROM_ASSERT_THLD):
            result = obj.debounce(base, 'eid', 'okay', 10.0)
        self.assertTrue(result)

    def test_debounce_warning_to_failure(self):
        """Verify debounce_warning returns True on failure."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        base.warnings = ['eid']
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        for _ in range(fm_notifier.DEBOUNCE_FROM_ASSERT_THLD):
            result = obj.debounce(base, 'eid', 'failure', 95.0)
        self.assertTrue(result)

    def test_debounce_non_percent(self):
        """Verify debounce_non returns False."""
        base = fm_notifier.fmAlarmObject('100.101', 'cpu')
        base.reading_type = 'state'
        obj = fm_notifier.fmAlarmObject('100.101', 'cpu')
        result = obj.debounce(base, 'eid', 'failure', 95.0)
        self.assertFalse(result)


class TestFmNotifierModuleFunctions(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        fm_notifier.fmAlarmObject.host = 'controller-0'
        fm_notifier.fmAlarmObject.lock = fm_notifier.Lock()

    def test_clear_alarm_success(self):
        """Verify clear_alarm_success fm_notifier.clear_alarm() is."""
        fm_notifier.api = MagicMock()
        fm_notifier.api.clear_fault.return_value = True
        self.assertTrue(fm_notifier.clear_alarm('100.101', 'eid'))

    def test_clear_alarm_already_clear(self):
        """Verify clear_alarm_already_clear fm_notifier.clear_alarm()."""
        fm_notifier.api = MagicMock()
        fm_notifier.api.clear_fault.return_value = False
        self.assertTrue(fm_notifier.clear_alarm('100.101', 'eid'))

    def test_clear_alarm_exception(self):
        """Verify clear_alarm_exception fm_notifier.clear_alarm() is."""
        fm_notifier.api = MagicMock()
        fm_notifier.api.clear_fault.side_effect = Exception('fail')
        self.assertFalse(fm_notifier.clear_alarm('100.101', 'eid'))

    def test_get_base_object(self):
        """Verify get_base_object returns 'cpu'."""
        obj = fm_notifier.get_base_object('100.101')
        self.assertIsNotNone(obj)
        self.assertEqual(obj.plugin, 'cpu')

    def test_get_base_object_none(self):
        """Verify get_base_object_none returns None with None input."""
        obj = fm_notifier.get_base_object('999.999')
        self.assertIsNone(obj)

    def test_get_object_base(self):
        """Verify get_object_base returns non-None value."""
        obj = fm_notifier.get_object('100.101', 'host=controller-0')
        self.assertIsNotNone(obj)

    def test_get_object_instance(self):
        """Verify get_object_instance finds by entity_id."""
        base = fm_notifier.PLUGINS[fm_notifier.PLUGIN__CPU]
        inst = fm_notifier.fmAlarmObject('100.101', 'cpu')
        base.instance_objects['eid1'] = inst
        result = fm_notifier.get_object('100.101', 'eid1')
        self.assertEqual(result, inst)
        base.instance_objects.clear()

    def test_build_entity_id_cpu(self):
        """Verify build_entity_id_cpu 'cpu=platform' in eid."""
        eid = fm_notifier._build_entity_id('cpu', 'platform')
        self.assertIn('cpu=platform', eid)

    def test_build_entity_id_mem(self):
        """Verify build_entity_id_mem 'memory=platform' in eid."""
        eid = fm_notifier._build_entity_id('memory', 'platform')
        self.assertIn('memory=platform', eid)

    def test_build_entity_id_mem_node(self):
        """Verify build_entity_id_mem 'numa=node0' in eid."""
        eid = fm_notifier._build_entity_id('memory', 'node0')
        self.assertIn('numa=node0', eid)

    def test_build_entity_id_mem_empty(self):
        """Verify build_entity_id_mem returns 'host=controller-0'."""
        eid = fm_notifier._build_entity_id('memory', '')
        self.assertEqual(eid, 'host=controller-0')

    def test_build_entity_id_cpu_empty(self):
        """Verify build_entity_id_cpu returns 'host=controller-0'."""
        eid = fm_notifier._build_entity_id('cpu', '')
        self.assertEqual(eid, 'host=controller-0')

    def test_build_entity_id_df(self):
        """Verify build_entity_id_df 'filesystem=/' in eid."""
        eid = fm_notifier._build_entity_id('df', 'root')
        self.assertIn('filesystem=/', eid)

    def test_build_entity_id_df_bad(self):
        """Verify build_entity_id_df returns None."""
        eid = fm_notifier._build_entity_id('df', 'nonexistent')
        self.assertIsNone(eid)

    def test_build_entity_id_vswitch_mem(self):
        """Verify build_entity_id_vswitch 'processor=0' in eid."""
        eid = fm_notifier._build_entity_id('vswitch_mem', '0')
        self.assertIn('processor=0', eid)

    def test_build_entity_id_vswitch_mem_empty(self):
        """Verify build_entity_id_vswitch returns None with empty."""
        eid = fm_notifier._build_entity_id('vswitch_mem', '')
        self.assertIsNone(eid)

    def test_build_entity_id_vswitch_iface(self):
        """Verify build_entity_id_vswitch 'interface=uuid1' in eid."""
        eid = fm_notifier._build_entity_id('vswitch_iface', 'uuid1')
        self.assertIn('interface=uuid1', eid)

    def test_build_entity_id_vswitch_iface_empty(self):
        """Verify build_entity_id_vswitch returns None with empty."""
        eid = fm_notifier._build_entity_id('vswitch_iface', '')
        self.assertIsNone(eid)

    def test_build_entity_id_vswitch_port(self):
        """Verify build_entity_id_vswitch 'port=uuid1' in eid."""
        eid = fm_notifier._build_entity_id('vswitch_port', 'uuid1')
        self.assertIn('port=uuid1', eid)

    def test_build_entity_id_vswitch_port_empty(self):
        """Verify build_entity_id_vswitch returns None with empty."""
        eid = fm_notifier._build_entity_id('vswitch_port', '')
        self.assertIsNone(eid)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', mock_open(read_data='<Plugin "df">\nMountPoint "/"\nMountPoint "/var/log"\n</Plugin>\n'))  # noqa: E501
    def test_get_df_mountpoints(self, mock_exists):
        """Verify get_df_mountpoints lists mount points."""
        fm_notifier.fmAlarmObject.plugin_path = '/etc/collectd.d/'
        result = fm_notifier._get_df_mountpoints()
        self.assertIsInstance(result, list)

    @patch('os.path.exists', return_value=False)
    def test_get_df_mountpoints_no_conf(self, mock_exists):
        """Verify get_df_mountpoints fails on error."""
        fm_notifier.fmAlarmObject.plugin_path = '/etc/collectd.d/'
        result = fm_notifier._get_df_mountpoints()
        self.assertEqual(result, fm_notifier.FAIL)

    @patch('os.path.ismount', return_value=False)
    @patch.object(fm_notifier, 'clear_alarm', return_value=True)
    def test_clear_alarm_for_missing_filesystems(self, mock_ca, mock_mount):
        """Verify clear_alarm_for_missing when missing."""
        df_base = fm_notifier.PLUGINS[fm_notifier.PLUGIN__DF]
        inst = fm_notifier.fmAlarmObject(fm_notifier.ALARM_ID__DF, fm_notifier.PLUGIN__DF)
        inst.entity_id = 'host=controller-0.filesystem=/scratch'
        inst.instance_name = '/scratch'
        inst.plugin = fm_notifier.PLUGIN__DF
        df_base.instance_objects[inst.entity_id] = inst
        df_base.warnings = [inst.entity_id]
        df_base.failures = []
        fm_notifier._clear_alarm_for_missing_filesystems()
        self.assertNotIn(inst.entity_id, df_base.warnings)
        df_base.instance_objects.clear()
        df_base.warnings.clear()

    @patch('os.path.ismount', return_value=True)
    def test_clear_alarm_for_missing_filesystems_mounted(self, mock_mount):
        """Verify clear_alarm_for_missing clears stale alarm."""
        df_base = fm_notifier.PLUGINS[fm_notifier.PLUGIN__DF]
        inst = fm_notifier.fmAlarmObject(fm_notifier.ALARM_ID__DF, fm_notifier.PLUGIN__DF)
        inst.entity_id = 'host=controller-0.filesystem=/'
        inst.instance_name = '/'
        inst.plugin = fm_notifier.PLUGIN__DF
        df_base.instance_objects[inst.entity_id] = inst
        df_base.failures = [inst.entity_id]
        df_base.warnings = []
        fm_notifier._clear_alarm_for_missing_filesystems()
        self.assertIn(inst.entity_id, df_base.failures)
        df_base.instance_objects.clear()
        df_base.failures.clear()


class TestFmNotifierInitFunc(unittest.TestCase):
    @patch('builtins.open', mock_open(read_data='Include "/etc/collectd.d"\n'))
    @patch('os.path.exists', return_value=True)
    @patch.object(pc.PluginObject, 'gethostname', return_value='controller-0')
    def test_init_func(self, mock_gh, mock_exists):
        """Verify init_func fm_notifier.pluginObject.init_complete is."""
        tsc_mock.nodetype = 'controller'
        tsc_mock.subfunctions = 'controller'
        fm_notifier.six = six_mock
        fm_notifier.six.PY2 = False
        fm_notifier.fmAlarmObject.plugin_path = '/etc/collectd.d/'
        fm_notifier.pluginObject = pc.PluginObject(fm_notifier.PLUGIN, '')
        fm_notifier.init_func()
        self.assertTrue(fm_notifier.pluginObject.init_complete)


if __name__ == '__main__':
    unittest.main()
