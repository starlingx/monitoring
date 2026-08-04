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
sys.modules.setdefault('gps', MagicMock())
sys.modules.setdefault('pynetlink', MagicMock())
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

import plugin_common as pc
import ptp
import unittest
import tempfile
from unittest.mock import mock_open
from unittest.mock import patch
sys.modules.setdefault('gps', MagicMock())
sys.modules.setdefault('pynetlink', MagicMock())
sys.modules.setdefault('tsconfig', MagicMock())
sys.modules.setdefault('tsconfig.tsconfig', MagicMock())
sys.modules.setdefault('fm_api', MagicMock())
sys.modules.setdefault('fm_api.constants', MagicMock())
sys.modules.setdefault('fm_api.fm_api', MagicMock())
for module_name in ['plugin_common', 'ptp', 'ptp_interface', 'ptp_gnss_monitor', 'cgu_handler']:
    sys.modules.pop(module_name, None)
# Re-register ptp so patch('ptp.xxx') targets the already-imported
# module
sys.modules['ptp'] = ptp


def _reset_module_state():
    """Reset ptp module-level state between tests."""
    ptp.ALARM_OBJ_LIST.clear()
    ptp.ptpinstances.clear()
    ptp.ordered_instances.clear()
    ptp.ptpinterfaces.clear()
    ptp.interfaces.clear()
    ptp.base_ports.clear()
    ptp.base_port_map.clear()
    ptp.ts2phc_source_interfaces.clear()
    ptp.ts2phc_instance_map.clear()
    ptp.timing_instance_list.clear()
    ptp.ptp4l_instance_map.clear()
    ptp.ethtool_rule_ids.clear()
    ptp.phc2sys_source = None
    ptp.phc2sys_sink = None
    ptp.obj.hostname = 'testhost'
    ptp.obj.base_eid = 'host=testhost'
    ptp.obj.mode = 'hardware'
    ptp.obj.init_complete = False
    ptp.obj._node_ready = False
    ptp.obj.virtual = False
    ptp.obj.audits = 0
    ptp.obj.capabilities = {'primary_nic': None, 'ts2phc_source': None}


def _make_ptp4l_conf(content, name='test1'):
    """Create a temp ptp4l config file with proper naming pattern."""
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', prefix=f'ptp4l-{name}', suffix='.conf', delete=False)
    temp_file.write(content)
    temp_file.close()
    return temp_file.name


def _make_phc2sys_conf(content, name='test1'):
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', prefix=f'phc2sys-{name}', suffix='.conf', delete=False)
    temp_file.write(content)
    temp_file.close()
    return temp_file.name


def _make_ts2phc_conf(content, name='test1'):
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', prefix=f'ts2phc-{name}', suffix='.conf', delete=False)
    temp_file.write(content)
    temp_file.close()
    return temp_file.name


def _make_clock_conf(content, name='test1'):
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', prefix=f'clock-{name}', suffix='.conf', delete=False)
    temp_file.write(content)
    temp_file.close()
    return temp_file.name


def _make_gnss_monitor_conf(content, name='test1'):
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', prefix=f'gnss-monitor-{name}', suffix='.conf', delete=False)
    temp_file.write(content)
    temp_file.close()
    return temp_file.name


PTP4L_CONF_BASIC = """\
[global]
time_stamping hardware
domainNumber 24
uds_address /var/run/ptp4l-test1
dataset_comparison G.8275.x

[ens1f0]
masterOnly 1
"""

PTP4L_CONF_UNICAST = """\
[global]
time_stamping hardware
domainNumber 24

[ens1f0]
masterOnly 1

[unicast_master_table]
table_id 1
logQueryInterval 0

[unicast_master_table]
table_id 2
logQueryInterval 1
"""

PHC2SYS_CONF_BASIC = """\
[global]
ha_enabled 0
domainNumber 24

[ens1f0]
ha_priority 1
"""

PHC2SYS_CONF_HA = """\
[global]
ha_enabled 1
domainNumber 24
ha_phc2sys_com_socket /var/run/phc2sys-test

[ens2f0]
ha_priority 100
ha_uds_address /var/run/ptp4l-inst1

[ens3f0]
ha_priority 50
ha_uds_address /var/run/ptp4l-inst2
"""


class TestCreateInterfaceAlarmObjects(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_create_ptp4l_alarm_objects(self):
        """Verify alarm objects created for ptp4l interface."""
        ptp.create_interface_alarm_objects('ens1f0', 'inst1', ptp.PTP_INSTANCE_TYPE_PTP4L)
        self.assertIn('inst1', ptp.ptpinstances)
        ctrl = ptp.ptpinstances['inst1']
        self.assertIsNotNone(ctrl.process_alarm_object)
        self.assertIsNotNone(ctrl.oot_alarm_object)
        self.assertIsNotNone(ctrl.nolock_alarm_object)
        self.assertIsNotNone(ctrl.gnss_signal_loss_alarm_object)
        self.assertIn('ens1f0', ptp.ptpinterfaces)

    def test_create_phc2sys_alarm_objects(self):
        """Verify create_phc2sys_alarm_objects returns non-None."""
        ptp.create_interface_alarm_objects('ens2f0', 'inst2', ptp.PTP_INSTANCE_TYPE_PHC2SYS)
        self.assertIn('inst2', ptp.ptpinstances)
        ctrl = ptp.ptpinstances['inst2']
        self.assertIsNotNone(ctrl.phc2sys_clock_source_loss)
        self.assertIsNotNone(ctrl.phc2sys_clock_source_forced_selection)
        self.assertIsNotNone(ctrl.phc2sys_clock_source_low_priority)

    def test_create_gnss_monitor_alarm_objects(self):
        """Verify create_gnss_monitor_alarm found_hw is False."""
        ptp.create_interface_alarm_objects(
            '/dev/gnss0', 'gnss-monitor-inst1', ptp.PTP_INSTANCE_TYPE_GNSS_MONITOR)
        self.assertIn('gnss-monitor-inst1', ptp.ptpinstances)
        self.assertIn('/dev/gnss0', ptp.ptpinterfaces)
        # gnss-monitor should NOT create HW/SW/Legacy alarm objects
        found_hw = any(alarm_obj.alarm == ptp.ALARM_CAUSE__UNSUPPORTED_HW for alarm_obj in ptp.ALARM_OBJ_LIST)
        self.assertFalse(found_hw)

    def test_create_duplicate_instance_skipped(self):
        """Verify duplicate ptp4l instance is skipped."""
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        count_before = len(ptp.ALARM_OBJ_LIST)
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        self.assertEqual(len(ptp.ALARM_OBJ_LIST), count_before)

    def test_create_second_interface_same_instance(self):
        """Verify second interface added to same instance."""
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        count_before = len(ptp.ALARM_OBJ_LIST)
        ptp.create_interface_alarm_objects('ens2f0', 'inst1')
        # New interface alarm objects should be added
        self.assertGreater(len(ptp.ALARM_OBJ_LIST), count_before)
        self.assertIn('ens2f0', ptp.ptpinterfaces)


class TestUtilityFunctions(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_get_os_release_debian(self):
        """Verify get_os_release_debian returns 'debian'."""
        with patch('builtins.open', mock_open(read_data='ID=debian\n')):
            result = ptp._get_os_release()
            self.assertEqual(result, 'debian')

    def test_get_os_release_centos(self):
        """Verify get_os_release_centos returns '"centos"'."""
        with patch('builtins.open', mock_open(read_data='ID="centos"\n')):
            result = ptp._get_os_release()
            self.assertEqual(result, '"centos"')

    def test_get_os_release_missing(self):
        """Verify get_os_release_missing returns 'unknown' on."""
        with patch('builtins.open', side_effect=Exception("no file")):
            result = ptp._get_os_release()
            self.assertEqual(result, 'unknown')

    @patch('ptp._get_os_release', return_value='debian')
    def test_get_ptpinstance_path_debian(self, mock_os):
        """Verify get_ptpinstance_path_debian returns."""
        self.assertEqual(ptp._get_ptpinstance_path(), '/etc/linuxptp/ptpinstance/')

    @patch('ptp._get_os_release', return_value='"centos"')
    def test_get_ptpinstance_path_centos(self, mock_os):
        """Verify get_ptpinstance_path_centos returns."""
        self.assertEqual(ptp._get_ptpinstance_path(), '/etc/ptpinstance/')

    @patch('ptp._get_os_release', return_value='unknown')
    def test_get_ptpinstance_path_unknown(self, mock_os):
        """Verify get_ptpinstance_path_unknown returns ''."""
        self.assertEqual(ptp._get_ptpinstance_path(), '')

    @patch('ptp._get_os_release', return_value='debian')
    def test_get_ptp_options_path_debian(self, mock_os):
        """Verify get_ptp_options_path returns '/etc/default'."""
        self.assertEqual(ptp._get_ptp_options_path(), '/etc/default')

    @patch('ptp._get_os_release', return_value='"centos"')
    def test_get_ptp_options_path_centos(self, mock_os):
        """Verify get_ptp_options_path returns '/etc/sysconfig'."""
        self.assertEqual(ptp._get_ptp_options_path(), '/etc/sysconfig')

    def test_split_gnss_path_valid(self):
        """Verify split_gnss returns 'c' with valid input."""
        self.assertEqual(ptp.split_gnss_path('/dev/gnss0'), 'gnss0')
        self.assertEqual(ptp.split_gnss_path('a/b/c'), 'c')

    def test_split_gnss_path_none(self):
        """Verify split_gnss returns None with None input."""
        self.assertIsNone(ptp.split_gnss_path(None))

    def test_split_gnss_path_short(self):
        """Verify split_gnss returns None."""
        self.assertIsNone(ptp.split_gnss_path('a/b'))

    def test_prune_reconfigured_suffix(self):
        """Verify prune_reconfigured returns None."""
        self.assertEqual(ptp.prune_reconfigured_suffix('/dev/gnss0.pty'), '/dev/gnss0')
        self.assertEqual(ptp.prune_reconfigured_suffix('/dev/gnss0'), '/dev/gnss0')
        self.assertIsNone(ptp.prune_reconfigured_suffix(None))

    @patch('os.path.exists', return_value=True)
    def test_is_microchip_gnss_module_available(self, mock_exists):
        """Verify is_microchip_gnss True when available."""
        self.assertTrue(ptp.is_microchip_gnss_module_available())

    @patch('os.path.exists', return_value=False)
    def test_is_microchip_gnss_module_not_available(self, mock_exists):
        """Verify is_microchip_gnss False when missing."""
        self.assertFalse(ptp.is_microchip_gnss_module_available())

    def test_lockstatus_priority(self):
        """Verify lockstatus_priority returns 1."""
        self.assertEqual(ptp.lockstatus_priority(ptp.CLOCK_STATE_LOCKED_HO_ACQ), 5)
        self.assertEqual(ptp.lockstatus_priority(ptp.CLOCK_STATE_LOCKED), 4)
        self.assertEqual(ptp.lockstatus_priority(ptp.CLOCK_STATE_HOLDOVER), 3)
        self.assertEqual(ptp.lockstatus_priority(ptp.CLOCK_STATE_UNLOCKED), 2)
        self.assertEqual(ptp.lockstatus_priority(ptp.CLOCK_STATE_INVALID), 1)

    @patch('subprocess.check_output', return_value=b'')
    def test_create_interface(self, mock_sub):
        """Verify create_interface builds Interface object."""
        ptp.create_interface('ens1f0')
        self.assertIn('ens1f0', ptp.interfaces)
        # calling again should not overwrite
        obj1 = ptp.interfaces['ens1f0']
        ptp.create_interface('ens1f0')
        self.assertIs(ptp.interfaces['ens1f0'], obj1)


class TestReadTimestampMode(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_read_timestamp_mode(self):
        """Verify read_timestamp_mode returns 'hardware'."""
        content = "time_stamping hardware\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp_file:
            temp_file.write(content)
            path = temp_file.name
        try:
            ptp.obj.mode = ''
            ptp.read_timestamp_mode(path)
            self.assertEqual(ptp.obj.mode, 'hardware')
        finally:
            os.unlink(path)

    def test_read_timestamp_mode_missing_file(self):
        """Verify read_timestamp_mode_missing returns None when."""
        ptp.obj.mode = 'hardware'
        ptp.read_timestamp_mode('/nonexistent/path.conf')
        self.assertIsNone(ptp.obj.mode)


class TestReadPtpServiceOptions(unittest.TestCase):

    def test_read_success(self):
        """Verify read_ptp_service_options parses content."""
        content = "-s /dev/ptp0 -c CLOCK_REALTIME -O 37"
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.opts') as temp_file:
            temp_file.write(content)
            path = temp_file.name
        try:
            with patch('ptp.PTP_OPTIONS_PATH', os.path.dirname(path)):
                with patch('os.path.join', return_value=path):
                    result = ptp.read_ptp_service_options('inst1', 'phc2sys')
                    self.assertEqual(result, content)
        finally:
            os.unlink(path)

    def test_read_file_not_found(self):
        """Verify read_file_not_found returns None."""
        result = ptp.read_ptp_service_options('inst1', 'phc2sys')
        self.assertIsNone(result)


class TestQueryPmc(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ptp.ptpinstances['inst1'].instance_type = ptp.PTP_INSTANCE_TYPE_PTP4L

    @patch('subprocess.check_output')
    def test_query_pmc_basic(self, mock_sub):
        """Verify query_pmc_basic returns '0x20'."""
        mock_sub.return_value = (
            b"sending: GET GRANDMASTER_SETTINGS_NP\n"
            b"  clockClass     6\n"
            b"  clockAccuracy  0x20\n"
        )
        result = ptp.query_pmc('inst1', 'GRANDMASTER_SETTINGS_NP')
        self.assertEqual(result['clockClass'], '6')
        self.assertEqual(result['clockAccuracy'], '0x20')

    @patch('subprocess.check_output')
    def test_query_pmc_with_uds(self, mock_sub):
        """Verify query_pmc_with_uds returns 'abc123'."""
        mock_sub.return_value = b"sending: GET DEFAULT_DATA_SET\n  clockIdentity abc123\n"
        result = ptp.query_pmc('inst1', 'DEFAULT_DATA_SET',
                               uds_address='/var/run/ptp4l-inst1')
        self.assertEqual(result['clockIdentity'], 'abc123')

    @patch('subprocess.check_output', side_effect=ptp.subprocess.CalledProcessError(1, 'pmc'))
    def test_query_pmc_failure(self, mock_sub):
        """Verify query_pmc_failure returns {} on exception."""
        result = ptp.query_pmc('inst1', 'GRANDMASTER_SETTINGS_NP')
        self.assertEqual(result, {})

    @patch('subprocess.check_output', side_effect=ptp.subprocess.CalledProcessError(1, 'pmc'))
    def test_query_pmc_failure_uds(self, mock_sub):
        """Verify query_pmc_failure_uds returns {} on exception."""
        result = ptp.query_pmc('inst1', 'GRANDMASTER_SETTINGS_NP',
                               uds_address='/var/run/ptp4l-inst1')
        self.assertEqual(result, {})


class TestQueryPmcIndexed(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ptp.ptpinstances['inst1'].instance_type = ptp.PTP_INSTANCE_TYPE_PTP4L

    @patch('subprocess.check_output')
    def test_query_pmc_indexed_basic(self, mock_sub):
        """Verify query_pmc_indexed_basic returns 'SLAVE'."""
        mock_sub.return_value = (
            b"sending: GET PORT_DATA_SET\n"
            b"abc123-1 PORT_DATA_SET\n"
            b"  portState SLAVE\n"
            b"abc123-2 PORT_DATA_SET\n"
            b"  portState MASTER\n"
        )
        result = ptp.query_pmc_indexed('inst1', 'PORT_DATA_SET')
        self.assertIn('abc123-1', result)
        self.assertEqual(result['abc123-1']['portState'], 'SLAVE')

    @patch('subprocess.check_output', side_effect=ptp.subprocess.CalledProcessError(1, 'pmc'))
    def test_query_pmc_indexed_failure(self, mock_sub):
        """Verify query_pmc_indexed_failure returns {} on exception."""
        result = ptp.query_pmc_indexed('inst1', 'PORT_DATA_SET')
        self.assertEqual(result, {})

    @patch('subprocess.check_output', side_effect=ptp.subprocess.CalledProcessError(1, 'pmc'))
    def test_query_pmc_indexed_failure_uds(self, mock_sub):
        """Verify query_pmc_indexed_failure returns {} on exception."""
        result = ptp.query_pmc_indexed('inst1', 'PORT_DATA_SET',
                                       uds_address='/var/run/ptp4l-inst1')
        self.assertEqual(result, {})


class TestIsServiceRunning(unittest.TestCase):

    @patch('subprocess.check_output', return_value=b'active\n')
    def test_running(self, mock_sub):
        """Verify running ptp.is_service_running() is True."""
        self.assertTrue(ptp.is_service_running('ptp4l@inst1.service'))

    @patch('subprocess.check_output', return_value=b'inactive\n')
    def test_not_running(self, mock_sub):
        """Verify not_running ptp.is_service_running() is False."""
        self.assertFalse(ptp.is_service_running('ptp4l@inst1.service'))


class TestSetInstanceOrder(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_ordering(self):
        """Verify ordering returns 'phc2sys_inst'."""
        ptp.create_interface_alarm_objects('ens1f0', 'ptp_inst', ptp.PTP_INSTANCE_TYPE_PTP4L)
        ptp.ptpinstances['ptp_inst'].instance_type = ptp.PTP_INSTANCE_TYPE_PTP4L
        ptp.create_interface_alarm_objects('ens2f0', 'ts2phc_inst', ptp.PTP_INSTANCE_TYPE_TS2PHC)
        ptp.ptpinstances['ts2phc_inst'].instance_type = ptp.PTP_INSTANCE_TYPE_TS2PHC
        ptp.create_interface_alarm_objects('ens3f0', 'phc2sys_inst', ptp.PTP_INSTANCE_TYPE_PHC2SYS)
        ptp.ptpinstances['phc2sys_inst'].instance_type = ptp.PTP_INSTANCE_TYPE_PHC2SYS
        ptp._set_instance_order()
        keys = list(ptp.ordered_instances.keys())
        self.assertEqual(keys[0], 'ts2phc_inst')
        self.assertEqual(keys[1], 'ptp_inst')
        self.assertEqual(keys[2], 'phc2sys_inst')
