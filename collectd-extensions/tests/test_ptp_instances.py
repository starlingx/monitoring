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


class TestConfigDict(unittest.TestCase):

    def test_init_requires_dict(self):
        """Verify init_requires_dict raises TypeError."""
        with self.assertRaises(TypeError):
            ptp.ConfigDict("not a dict")

    def test_init_with_dict(self):
        """Verify init_with_dict returns non-None value."""
        config_dict = ptp.ConfigDict({'global': {'key': 'val'}})
        self.assertIsNotNone(config_dict)

    def test_sections(self):
        """Verify sections returns []."""
        config_dict = ptp.ConfigDict({'global': {}, 'ens1f0': {}})
        self.assertEqual(config_dict.sections(), ['global', 'ens1f0'])

    def test_has_section_true(self):
        """Verify has_section config_dict.has_section() is True."""
        config_dict = ptp.ConfigDict({'global': {}})
        self.assertTrue(config_dict.has_section('global'))

    def test_has_section_false(self):
        """Verify has_section config_dict.has_section() is False."""
        config_dict = ptp.ConfigDict({'global': {}})
        self.assertFalse(config_dict.has_section('missing'))

    def test_has_section_type_error(self):
        """Verify has_section raises TypeError on failure."""
        config_dict = ptp.ConfigDict({'global': {}})
        with self.assertRaises(TypeError):
            config_dict.has_section(123)

    def test_getitem(self):
        """Verify getitem returns {}."""
        config_dict = ptp.ConfigDict({'global': {'k': 'v'}})
        self.assertEqual(config_dict['global'], {'k': 'v'})

    def test_getitem_missing(self):
        """Verify getitem_missing raises KeyError when missing."""
        config_dict = ptp.ConfigDict({'global': {}})
        with self.assertRaises(KeyError):
            config_dict['missing']

    def test_getitem_type_error(self):
        """Verify getitem_type raises TypeError on failure."""
        config_dict = ptp.ConfigDict({'global': {}})
        with self.assertRaises(TypeError):
            config_dict[123]

    def test_get_unicast_master_tables_empty(self):
        """Verify get_unicast_master_tables returns {} with empty."""
        config_dict = ptp.ConfigDict({'global': {}})
        self.assertEqual(config_dict.get_unicast_master_tables(), {})

    def test_get_unicast_master_tables(self):
        """Verify get_unicast_master_tables '2' in tables."""
        config_dict = ptp.ConfigDict({
            'global': {},
            'unicast_master_table_0': {'table_id': '1', 'logQueryInterval': '0'},
            'unicast_master_table_1': {'table_id': '2', 'logQueryInterval': '1'},
        })
        tables = config_dict.get_unicast_master_tables()
        self.assertIn('1', tables)
        self.assertIn('2', tables)

    def test_get_unicast_master_tables_no_table_id(self):
        """Verify get_unicast_master_tables '0' in tables."""
        config_dict = ptp.ConfigDict({
            'unicast_master_table_0': {'logQueryInterval': '0'},
        })
        tables = config_dict.get_unicast_master_tables()
        self.assertIn('0', tables)


class TestTimingInstancePtp4l(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_parse_ptp4l_basic(self):
        """Verify parse_ptp4l_basic returns '24'."""
        path = _make_ptp4l_conf(PTP4L_CONF_BASIC)
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertEqual(timing_inst.instance_type, 'ptp4l')
            self.assertIn('ens1f0', timing_inst.interfaces)
            self.assertTrue(timing_inst.config.has_section('global'))
            self.assertEqual(timing_inst.config['global']['domainNumber'], '24')
        finally:
            os.unlink(path)

    def test_parse_ptp4l_unicast(self):
        """Verify parse_ptp4l extracts unicast interface."""
        path = _make_ptp4l_conf(PTP4L_CONF_UNICAST)
        try:
            timing_inst = ptp.TimingInstance(path)
            tables = timing_inst.config.get_unicast_master_tables()
            self.assertEqual(len(tables), 2)
            self.assertIn('ens1f0', timing_inst.interfaces)
        finally:
            os.unlink(path)

    def test_parse_ptp4l_empty_config(self):
        """Verify parse_ptp4l_empty_config returns 0 with empty."""
        path = _make_ptp4l_conf("[global]\ntime_stamping software\n")
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertEqual(len(timing_inst.interfaces), 0)
        finally:
            os.unlink(path)

    def test_parse_ptp4l_comments_and_blanks(self):
        """Verify parse_ptp4l skips comments and blanks."""
        content = "[global]\n# comment\ntime_stamping hardware\n\n[ens2f0]\nmasterOnly 1\n"
        path = _make_ptp4l_conf(content)
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertIn('ens2f0', timing_inst.interfaces)
        finally:
            os.unlink(path)

    def test_parse_ptp4l_duplicate_keys(self):
        """Verify parse_ptp4l_duplicate_keys returns []."""
        content = "[global]\ntime_stamping hardware\n[ens1f0]\nkey val1\nkey val2\n"
        path = _make_ptp4l_conf(content)
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertEqual(timing_inst.config['ens1f0']['key'], ['val1', 'val2'])
        finally:
            os.unlink(path)


class TestPTPAlarmObject(unittest.TestCase):

    def test_init(self):
        """Verify init returns ''."""
        alarm_obj = ptp.PTP_alarm_object('src1')
        self.assertEqual(alarm_obj.source, 'src1')
        self.assertFalse(alarm_obj.raised)
        self.assertEqual(alarm_obj.alarm, ptp.ALARM_CAUSE__NONE)
        self.assertEqual(alarm_obj.reason, '')
        self.assertEqual(alarm_obj.repair, '')
        self.assertEqual(alarm_obj.eid, '')


class TestPTPCtrlObject(unittest.TestCase):

    def test_init_default(self):
        """Verify init_default returns None."""
        ctrl_obj = ptp.PTP_ctrl_object()
        self.assertEqual(ctrl_obj.instance_type, ptp.PTP_INSTANCE_TYPE_PTP4L)
        self.assertFalse(ctrl_obj.phc2sys_ha_enabled)
        self.assertFalse(ctrl_obj.prtc_present)
        self.assertFalse(ctrl_obj.disciplined_by_ts2phc)
        self.assertEqual(ctrl_obj.ptp4l_clock_class, ptp.CLOCK_CLASS_248)
        self.assertIsNone(ctrl_obj.nolock_alarm_object)

    def test_init_custom_type(self):
        """Verify PTP_ctrl_object stores custom instance type."""
        ctrl_obj = ptp.PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_PHC2SYS)
        self.assertEqual(ctrl_obj.instance_type, ptp.PTP_INSTANCE_TYPE_PHC2SYS)


class TestGetAlarmObject(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_found(self):
        """Verify get_alarm_object finds matching alarm."""
        alarm_obj = ptp.PTP_alarm_object('src1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__PROCESS
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.get_alarm_object(ptp.ALARM_CAUSE__PROCESS, 'src1')
        self.assertIs(result, alarm_obj)

    def test_found_no_source(self):
        """Verify get_alarm_object with no source interface."""
        alarm_obj = ptp.PTP_alarm_object('src1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__OOT
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.get_alarm_object(ptp.ALARM_CAUSE__OOT)
        self.assertIs(result, alarm_obj)

    def test_not_found(self):
        """Verify not_found returns None."""
        result = ptp.get_alarm_object(ptp.ALARM_CAUSE__PROCESS, 'missing')
        self.assertIsNone(result)


class TestClearAlarm(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch.object(ptp.api, 'clear_fault', return_value=True)
    def test_clear_success(self, mock_cf):
        """Verify clear_success is called once on success."""
        self.assertTrue(ptp.clear_alarm('host=testhost.ptp'))
        mock_cf.assert_called_once()

    @patch.object(ptp.api, 'clear_fault', return_value=False)
    def test_clear_already_cleared(self, mock_cf):
        """Verify clear_already_cleared ptp.clear_alarm() is True."""
        self.assertTrue(ptp.clear_alarm('host=testhost.ptp'))

    @patch.object(ptp.api, 'clear_fault', side_effect=Exception("fail"))
    def test_clear_exception(self, mock_cf):
        """Verify clear_exception ptp.clear_alarm() is False on."""
        self.assertFalse(ptp.clear_alarm('host=testhost.ptp'))


class TestRaiseAlarm(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_raise_alarm_no_object_found(self):
        """Verify raise_alarm_no_object returns True."""
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__PROCESS, 'missing', 0)
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_process(self, mock_sf):
        """Verify raise_alarm_process alarm_obj.raised is True."""
        alarm_obj = ptp.PTP_alarm_object('inst1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__PROCESS
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.instance=inst1.ptp'
        alarm_obj.reason = 'testhost '
        alarm_obj.repair = 'testhost '
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__PROCESS, 'inst1', data='ptp4l@inst1.service')
        self.assertTrue(result)
        self.assertTrue(alarm_obj.raised)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_oot(self, mock_sf):
        """Verify raise_alarm_oot returns True."""
        alarm_obj = ptp.PTP_alarm_object('inst1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__OOT
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MINOR
        alarm_obj.eid = 'host=testhost.instance=inst1.ptp=out-of-tolerance'
        alarm_obj.reason = 'testhost '
        alarm_obj.repair = 'Check quality'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_50
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        ctrl = ptp.PTP_ctrl_object()
        ctrl.monitoring_parameters = {
            'offset_threshold_minor_nsec': 1000,
            'offset_threshold_major_nsec': 1000000,
        }
        ptp.ptpinstances['inst1'] = ctrl
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__OOT, 'inst1', data=5000)
        self.assertTrue(result)

    def test_raise_alarm_already_raised(self):
        """Verify raise_alarm_already_raised returns True."""
        alarm_obj = ptp.PTP_alarm_object('inst1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__NO_LOCK
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.raised = True
        alarm_obj.eid = 'host=testhost.instance=inst1.ptp=no-lock'
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__NO_LOCK, 'inst1', 0)
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='bad-uuid')
    def test_raise_alarm_set_fault_fails(self, mock_sf):
        """Verify raise_alarm_set_fault returns False on failure."""
        alarm_obj = ptp.PTP_alarm_object('inst1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__NO_LOCK
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.instance=inst1.ptp=no-lock'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_51
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__NO_LOCK, 'inst1', 0)
        self.assertFalse(result)

    @patch.object(ptp.api, 'set_fault', side_effect=Exception("boom"))
    def test_raise_alarm_exception(self, mock_sf):
        """Verify raise_alarm_exception returns False on exception."""
        alarm_obj = ptp.PTP_alarm_object('inst1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__NO_LOCK
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.instance=inst1.ptp=no-lock'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_51
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__NO_LOCK, 'inst1', 0)
        self.assertFalse(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_gnss_signal_loss(self, mock_sf):
        """Verify raise_alarm_gnss_signal returns True."""
        alarm_obj = ptp.PTP_alarm_object('ens1f0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__GNSS_SIGNAL_LOSS
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.interface=ens1f0.ptp=GNSS-signal-loss'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_29
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__GNSS_SIGNAL_LOSS, 'ens1f0', 'unlocked')
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_1pps(self, mock_sf):
        """Verify raise_alarm_1pps returns True."""
        alarm_obj = ptp.PTP_alarm_object('ens1f0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__1PPS_SIGNAL_LOSS
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.interface=ens1f0.ptp=1PPS-signal-loss'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_29
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(ptp.ALARM_CAUSE__1PPS_SIGNAL_LOSS, 'ens1f0', 'unlocked')
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_phc2sys_low_priority(self, mock_sf):
        """Verify raise_alarm_phc2sys_low returns True."""
        alarm_obj = ptp.PTP_alarm_object('inst1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOW_PRIORITY
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MINOR
        alarm_obj.eid = 'host=testhost.phc2sys=inst1.phc2sys=source-clock-low-priority'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(
            ptp.ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_LOW_PRIORITY, 'inst1', 'ens2f0')
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_phc2sys_no_lock(self, mock_sf):
        """Verify raise_alarm_phc2sys_no returns True."""
        alarm_obj = ptp.PTP_alarm_object('ens1f0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_NO_LOCK
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.phc2sys=inst1.interface=ens1f0.phc2sys=source-clock-no-prc-lock'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_29
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(
            ptp.ALARM_CAUSE__PHC2SYS_CLOCK_SOURCE_NO_LOCK, 'ens1f0', '248')
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_gnss_monitor_signal_loss(self, mock_sf):
        """Verify raise_alarm_gnss_monitor returns True."""
        alarm_obj = ptp.PTP_alarm_object('/dev/gnss0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.gnss-monitor=inst1.device_path=/dev/gnss0.ptp=GNSS-signal-loss'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_29
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(
            ptp.ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS, '/dev/gnss0', 'signal loss')
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_gnss_monitor_satellite_count(self, mock_sf):
        """Verify raise_alarm_gnss_monitor returns True."""
        alarm_obj = ptp.PTP_alarm_object('/dev/gnss0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__GNSS_MONITOR_SATELLITE_COUNT
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.gnss-monitor=inst1.device_path=/dev/gnss0.ptp=GNSS-satellite-count'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_50
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(
            ptp.ALARM_CAUSE__GNSS_MONITOR_SATELLITE_COUNT, '/dev/gnss0', 'count low')
        self.assertTrue(result)

    @patch.object(ptp.api, 'set_fault', return_value='550e8400-e29b-41d4-a716-446655440000')
    def test_raise_alarm_gnss_monitor_signal_quality(self, mock_sf):
        """Verify raise_alarm_gnss_monitor returns True."""
        alarm_obj = ptp.PTP_alarm_object('/dev/gnss0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__GNSS_MONITOR_SIGNAL_QUALITY_DB
        alarm_obj.severity = ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR
        alarm_obj.eid = 'host=testhost.gnss-monitor=inst1.device_path=/dev/gnss0.ptp=GNSS-signal-quality-db'
        alarm_obj.reason = 'testhost'
        alarm_obj.repair = 'Check network'
        alarm_obj.cause = ptp.fm_constants.ALARM_PROBABLE_CAUSE_50
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        result = ptp.raise_alarm(
            ptp.ALARM_CAUSE__GNSS_MONITOR_SIGNAL_QUALITY_DB, '/dev/gnss0', 'quality low')
        self.assertTrue(result)


class TestTimingInstancePhc2sys(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_parse_phc2sys_basic(self):
        """Verify parse_phc2sys extracts source interface."""
        path = _make_phc2sys_conf(PHC2SYS_CONF_BASIC)
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertEqual(timing_inst.instance_type, 'phc2sys')
            self.assertIn('ens1f0', timing_inst.interfaces)
        finally:
            os.unlink(path)

    @patch.object(ptp.TimingInstance, 'query_phc2sys_socket', return_value=None)
    def test_parse_phc2sys_ha(self, mock_sock):
        """Verify parse_phc2sys parses HA config interfaces."""
        path = _make_phc2sys_conf(PHC2SYS_CONF_HA)
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertEqual(timing_inst.instance_type, 'phc2sys')
            self.assertIn('ens2f0', timing_inst.interfaces)
            self.assertIn('ens3f0', timing_inst.interfaces)
        finally:
            os.unlink(path)


class TestTimingInstanceTs2phc(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_parse_ts2phc(self):
        """Verify parse_ts2phc 'ens4f0' in timing_inst.interfaces."""
        content = "[global]\nts2phc.nmea_serialport /dev/gnss0\n\n[ens4f0]\n"
        path = _make_ts2phc_conf(content)
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertEqual(timing_inst.instance_type, 'ts2phc')
            self.assertIn('ens4f0', timing_inst.interfaces)
        finally:
            os.unlink(path)


class TestTimingInstanceClock(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_parse_clock(self):
        """Verify parse_clock 'ens5f0' in timing_inst.interfaces."""
        content = "base_port [ens5f0]\nifname ens5f0\nsma1 input\nsma2 output\n"
        path = _make_clock_conf(content)
        try:
            timing_inst = ptp.TimingInstance(path)
            self.assertEqual(timing_inst.instance_type, 'clock')
            self.assertIn('ens5f0', timing_inst.interfaces)
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
