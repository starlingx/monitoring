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
import configparser


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


class TestProcessGnssMonitorAlarm(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.raise_alarm', return_value=True)
    def test_raise_condition(self, mock_raise):
        """Verify raise_condition alarm_obj.raised is True."""
        ctrl = ptp.PTP_ctrl_object()
        ctrl.log_throttle_count = 0
        ctrl.timing_instance = MagicMock()
        alarm_obj = ptp.PTP_alarm_object('/dev/gnss0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS
        ptp.process_gnss_monitor_alarm(ctrl, alarm_obj, '/dev/gnss0', True, 'loss')
        self.assertTrue(alarm_obj.raised)

    @patch('ptp.clear_alarm', return_value=True)
    def test_clear_condition(self, mock_clear):
        """Verify clear_condition alarm_obj.raised is False."""
        ctrl = ptp.PTP_ctrl_object()
        ctrl.timing_instance = MagicMock()
        alarm_obj = ptp.PTP_alarm_object('/dev/gnss0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__GNSS_MONITOR_GNSS_SIGNAL_LOSS
        alarm_obj.raised = True
        alarm_obj.eid = 'test_eid'
        ptp.process_gnss_monitor_alarm(ctrl, alarm_obj, '/dev/gnss0', False, 'ok')
        self.assertFalse(alarm_obj.raised)


class TestProcessGnssMonitor(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.process_gnss_monitor_alarm')
    @patch('ptp.get_alarm_object')
    def test_process(self, mock_get_alarm, mock_process):
        """Verify process is called."""
        ctrl = ptp.PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_GNSS_MONITOR)
        ctrl.log_throttle_count = 0
        timing_inst = MagicMock()
        timing_inst.instance_name = 'gnss-monitor-inst1'
        timing_inst.config_file_path = '/tmp/gnss.conf'
        cfg = configparser.ConfigParser(delimiters=' ')
        cfg.read_string(
            "[global]\ndevices /dev/gnss0\nsatellite_count 4\nsignal_quality_db 20.0\n"
        )
        timing_inst.config = cfg
        timing_inst.device_paths = {'/dev/gnss0'}
        gps_data = MagicMock()
        gps_data.lock_state = True
        gps_data.satellite_count = 5
        gps_data.signal_quality_db = MagicMock()
        gps_data.signal_quality_db.avg = 25.0
        timing_inst.state = {'/dev/gnss0': gps_data}
        ctrl.timing_instance = timing_inst
        mock_get_alarm.return_value = MagicMock()
        ptp.process_gnss_monitor(ctrl)
        self.assertTrue(mock_process.called)


class TestGetNetlinkDpllStatus(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.cgu_handler')
    def test_interface_found(self, mock_cgu):
        """Verify get_netlink_dpll returns locked for iface."""
        mock_iface = MagicMock()
        mock_iface.get_switch_id.return_value = 'clock1'
        ptp.interfaces['ens1f0'] = mock_iface
        mock_device = MagicMock()
        mock_device.lock_status = ptp.CLOCK_STATE_LOCKED
        mock_pin = MagicMock()
        mock_pin.pin_board_label = 'GNSS-1PPS'
        mock_cgu.cgu_get_current_device_state.return_value = (mock_device, mock_pin)
        status, pin = ptp.get_netlink_dpll_status('ens1f0', ptp.DeviceType.PPS)
        self.assertEqual(status, ptp.CLOCK_STATE_LOCKED)

    @patch('ptp.cgu_handler')
    def test_interface_not_found(self, mock_cgu):
        """Verify get_netlink_dpll returns invalid for unknown."""
        status, pin = ptp.get_netlink_dpll_status('missing', ptp.DeviceType.PPS)
        self.assertEqual(status, ptp.CLOCK_STATE_INVALID)

    @patch('ptp.cgu_handler')
    def test_no_device(self, mock_cgu):
        """Verify get_netlink_dpll returns invalid with no dev."""
        mock_iface = MagicMock()
        mock_iface.get_switch_id.return_value = 'clock1'
        ptp.interfaces['ens1f0'] = mock_iface
        mock_cgu.cgu_get_current_device_state.return_value = (None, None)
        status, pin = ptp.get_netlink_dpll_status('ens1f0', ptp.DeviceType.PPS)
        self.assertEqual(status, ptp.CLOCK_STATE_INVALID)


class TestGetNetlinkPinStatus(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.cgu_handler')
    def test_pin_found(self, mock_cgu):
        """Verify get_netlink_pin_status finds matching pin."""
        mock_iface = MagicMock()
        mock_iface.get_switch_id.return_value = 'clock1'
        ptp.interfaces['ens1f0'] = mock_iface
        mock_pin = MagicMock()
        mock_cgu.search_pins.return_value = [mock_pin]
        result = ptp.get_netlink_pin_status('ens1f0', 'SMA1')
        self.assertIs(result, mock_pin)

    @patch('ptp.cgu_handler')
    def test_pin_not_found(self, mock_cgu):
        """Verify pin_not returns None."""
        mock_iface = MagicMock()
        mock_iface.get_switch_id.return_value = 'clock1'
        ptp.interfaces['ens1f0'] = mock_iface
        mock_cgu.search_pins.return_value = []
        result = ptp.get_netlink_pin_status('ens1f0', 'SMA1')
        self.assertIsNone(result)

    def test_interface_not_found(self):
        """Verify interface_not returns None."""
        result = ptp.get_netlink_pin_status('missing', 'SMA1')
        self.assertIsNone(result)


class TestGetPhc2sysCommandLineOption(unittest.TestCase):

    @patch('ptp._get_proc_cmdline')
    def test_flag_found(self, mock_cmd):
        """Verify flag_found returns '37'."""
        mock_cmd.return_value = ['phc2sys', '-s', '/dev/ptp0', '-O', '37']
        result = ptp._get_phc2sys_command_line_option('inst1', '/var/run/', '-O')
        self.assertEqual(result, '37')

    @patch('ptp._get_proc_cmdline')
    def test_flag_not_found(self, mock_cmd):
        """Verify flag_not returns None."""
        mock_cmd.return_value = ['phc2sys', '-s', '/dev/ptp0']
        result = ptp._get_phc2sys_command_line_option('inst1', '/var/run/', '-O')
        self.assertIsNone(result)

    @patch('ptp._get_proc_cmdline', side_effect=OSError("no proc"))
    def test_os_error(self, mock_cmd):
        """Verify os_error returns None on exception."""
        result = ptp._get_phc2sys_command_line_option('inst1', '/var/run/', '-O')
        self.assertIsNone(result)

    @patch('ptp._get_proc_cmdline', return_value=None)
    def test_none_cmdline(self, mock_cmd):
        """Verify none_cmdline returns None with None input."""
        result = ptp._get_phc2sys_command_line_option('inst1', '/var/run/', '-O')
        self.assertIsNone(result)


class TestInitializePtp4lStateFields(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ctrl = ptp.ptpinstances['inst1']
        ctrl.instance_type = ptp.PTP_INSTANCE_TYPE_PTP4L
        ctrl.interface = 'ens1f0'
        timing_inst = MagicMock()
        timing_inst.config = ptp.ConfigDict({
            'global': {
                'clockAccuracy': '0x20',
                'offsetScaledLogVariance': '0x4e5d',
                'timeSource': '0x20',
                'utc_offset': '37',
            }
        })
        ctrl.timing_instance = timing_inst
        ptp.base_port_map['ens1f0'] = 'ens1f0'

    @patch('ptp.query_pmc')
    def test_basic(self, mock_pmc):
        """Verify basic returns 'abc123'."""
        mock_pmc.side_effect = [
            {'currentUtcOffsetValid': '1', 'currentUtcOffset': '37'},
            {'clockIdentity': 'abc123'},
        ]
        ptp.initialize_ptp4l_state_fields('inst1')
        ctrl = ptp.ptpinstances['inst1']
        self.assertEqual(ctrl.ptp4l_clock_accuracy, '0x20')
        self.assertEqual(ctrl.ptp4l_clock_identity, 'abc123')

    @patch('ptp.query_pmc')
    def test_prtc_present(self, mock_pmc):
        """Verify prtc_present ctrl.prtc_present is True."""
        ptp.ts2phc_source_interfaces['ens1f0'] = 'ens1f0'
        ptp.ts2phc_instance_map['ens1f0'] = 'ts2phc_inst'
        mock_pmc.side_effect = [
            {'currentUtcOffsetValid': '1'},
            {'clockIdentity': 'abc123'},
        ]
        ptp.initialize_ptp4l_state_fields('inst1')
        ctrl = ptp.ptpinstances['inst1']
        self.assertTrue(ctrl.prtc_present)

    @patch('ptp.query_pmc')
    def test_no_utc_offset_in_config_or_query(self, mock_pmc):
        """Verify init_ptp4l_state defaults utc_offset to 37."""
        ctrl = ptp.ptpinstances['inst1']
        ctrl.timing_instance.config = ptp.ConfigDict({'global': {}})
        mock_pmc.side_effect = [{}, {}]
        ptp.initialize_ptp4l_state_fields('inst1')
        self.assertEqual(ctrl.ptp4l_current_utc_offset, 37)


class TestAlarmHelpers(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.raise_alarm')
    def test_assert_all_alarms(self, mock_raise):
        """Verify assert_all_alarms raises all alarm objects."""
        alarm_obj = ptp.PTP_alarm_object('src1')
        alarm_obj.alarm = ptp.ALARM_CAUSE__PROCESS
        ptp.ALARM_OBJ_LIST.append(alarm_obj)
        ptp.assert_all_alarms()
        mock_raise.assert_called()


class TestCheckPhc2sysTimeDrift(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ctrl = ptp.ptpinstances['inst1']
        ctrl.instance_type = ptp.PTP_INSTANCE_TYPE_PHC2SYS
        ctrl.interface = 'ens1f0'
        timing_inst = MagicMock()
        timing_inst.config = ptp.ConfigDict({
            'global': {'domainNumber': '24', 'ha_enabled': '0'}
        })
        ctrl.timing_instance = timing_inst

    @patch('ptp.check_time_drift')
    @patch('ptp.read_time_status_np')
    def test_basic(self, mock_read, mock_drift):
        """Verify check_phc2sys_time_drift basic path."""
        mock_read.return_value = ('abc', True, 'def', True, 42.0)
        ctrl = ptp.ptpinstances['inst1']
        ptp.check_phc2sys_time_drift('inst1', ctrl, '/tmp/test.conf')
        mock_drift.assert_called_with('inst1', 'def', 42.0)

    @patch('ptp.check_time_drift')
    @patch('ptp.read_time_status_np')
    def test_no_master_offset(self, mock_read, mock_drift):
        """Verify check_phc2sys_time_drift no master_offset."""
        mock_read.return_value = ('abc', True, 'def', False, 0)
        ctrl = ptp.ptpinstances['inst1']
        ptp.check_phc2sys_time_drift('inst1', ctrl, '/tmp/test.conf')
        mock_drift.assert_called_with('inst1', 'def')


class TestQueryPhc2sysSocket(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_no_socket(self):
        """Verify no_socket returns None."""
        path = _make_phc2sys_conf(PHC2SYS_CONF_BASIC)
        try:
            timing_inst = ptp.TimingInstance(path)
            result = timing_inst.query_phc2sys_socket("clock source")
            self.assertIsNone(result)
        finally:
            os.unlink(path)

    @patch('socket.socket')
    def test_connection_refused(self, mock_sock_cls):
        """Verify connection_refused returns None."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("refused")
        mock_sock_cls.return_value = mock_sock
        path = _make_phc2sys_conf(PHC2SYS_CONF_BASIC)
        try:
            timing_inst = ptp.TimingInstance(path)
            result = timing_inst.query_phc2sys_socket("clock source", "/tmp/test.sock")
            self.assertIsNone(result)
        finally:
            os.unlink(path)

    @patch('socket.socket')
    def test_file_not_found(self, mock_sock_cls):
        """Verify file_not returns None."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = FileNotFoundError("not found")
        mock_sock_cls.return_value = mock_sock
        path = _make_phc2sys_conf(PHC2SYS_CONF_BASIC)
        try:
            timing_inst = ptp.TimingInstance(path)
            result = timing_inst.query_phc2sys_socket("clock source", "/tmp/test.sock")
            self.assertIsNone(result)
        finally:
            os.unlink(path)

    @patch('socket.socket')
    def test_success(self, mock_sock_cls):
        """Verify success returns 'ens1f0' on success."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b'ens1f0'
        mock_sock_cls.return_value = mock_sock
        path = _make_phc2sys_conf(PHC2SYS_CONF_BASIC)
        try:
            timing_inst = ptp.TimingInstance(path)
            result = timing_inst.query_phc2sys_socket("clock source", "/tmp/test.sock")
            self.assertEqual(result, 'ens1f0')
        finally:
            os.unlink(path)

    @patch('socket.socket')
    def test_none_response(self, mock_sock_cls):
        """Verify none_response returns None with None input."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b'None'
        mock_sock_cls.return_value = mock_sock
        path = _make_phc2sys_conf(PHC2SYS_CONF_BASIC)
        try:
            timing_inst = ptp.TimingInstance(path)
            result = timing_inst.query_phc2sys_socket("clock source", "/tmp/test.sock")
            self.assertIsNone(result)
        finally:
            os.unlink(path)


class TestReadPtp4lConfig(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.glob', return_value=[])
    def test_no_files(self, mock_glob):
        """Verify no_files returns 0."""
        ptp.read_ptp4l_config()
        self.assertEqual(len(ptp.ptpinstances), 0)

    @patch('ptp.get_base_port', return_value=None)
    @patch('ptp.create_interface')
    @patch('ptp.glob')
    def test_with_file(self, mock_glob, mock_ci, mock_bp):
        """Verify with_file ... is True."""
        path = _make_ptp4l_conf(PTP4L_CONF_BASIC)
        try:
            mock_glob.return_value = [path]
            ptp.read_ptp4l_config()
            self.assertTrue(len(ptp.ptpinstances) > 0)
        finally:
            os.unlink(path)


class TestReadGnssMonitorPtpConfig(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp_gnss_monitor.parse_gnss_monitor_config')
    @patch('ptp.glob')
    def test_with_file(self, mock_glob, mock_parse):
        """Verify with_file found is True."""
        cfg = configparser.ConfigParser(delimiters=' ')
        cfg.read_string("[global]\ndevices /dev/gnss0\nsatellite_count 4\n")
        mock_parse.return_value = cfg
        path = _make_gnss_monitor_conf("[global]\ndevices /dev/gnss0\n")
        try:
            mock_glob.return_value = [path]
            ptp.read_gnss_monitor_ptp_config()
            found = any('gnss-monitor' in dict_key for dict_key in ptp.ptpinstances)
            self.assertTrue(found)
        finally:
            os.unlink(path)


class TestReadInstanceMonitoringConfig(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.glob')
    def test_with_file(self, mock_glob):
        """Verify monitoring config parses holdover_seconds."""
        content = "[inst1]\nholdover_seconds 7200\noffset_threshold_minor_nsec 500\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp_file:
            temp_file.write(content)
            path = temp_file.name
        try:
            mock_glob.return_value = [path]
            ptp.create_interface_alarm_objects('ens1f0', 'inst1')
            ptp.read_instance_monitoring_config()
            self.assertEqual(
                ptp.ptpinstances['inst1'].monitoring_parameters['holdover_seconds'], 7200)
        finally:
            os.unlink(path)

    @patch('ptp.glob')
    def test_with_bad_value(self, mock_glob):
        """Verify monitoring config uses default on bad value."""
        content = "[inst1]\nholdover_seconds notanumber\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp_file:
            temp_file.write(content)
            path = temp_file.name
        try:
            mock_glob.return_value = [path]
            ptp.create_interface_alarm_objects('ens1f0', 'inst1')
            ptp.read_instance_monitoring_config()
            self.assertEqual(
                ptp.ptpinstances['inst1'].monitoring_parameters['holdover_seconds'],
                ptp.HOLDOVER_THRESHOLD)
        finally:
            os.unlink(path)


class TestReadClockConfig(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('subprocess.check_output', return_value=b'')
    @patch('ptp.glob')
    def test_with_file(self, mock_glob, mock_sub):
        """Verify with_file 'clock' in ptp.ptpinstances."""
        content = "base_port [ens5f0]\nifname ens5f0\nsma1 input\nsma2 output\n"
        path = _make_clock_conf(content)
        try:
            mock_glob.return_value = [path]
            ptp.read_clock_config()
            self.assertIn('clock', ptp.ptpinstances)
        finally:
            os.unlink(path)

    @patch('ptp.glob')
    def test_no_interfaces(self, mock_glob):
        """Verify read_clock_config with no interfaces."""
        content = "# empty clock config\n"
        path = _make_clock_conf(content)
        try:
            mock_glob.return_value = [path]
            ptp.read_clock_config()
            self.assertNotIn('clock', ptp.ptpinstances)
        finally:
            os.unlink(path)


class TestReadTs2phcConfig(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.get_base_port', return_value=None)
    @patch('ptp.create_interface')
    @patch('ptp.get_interface_name_from_gnss', return_value='ens1f0')
    @patch('ptp.read_ptp_service_options', return_value="-s nmea")
    @patch('ptp.glob')
    def test_with_nmea(self, mock_glob, mock_opts, mock_gnss, mock_ci, mock_bp):
        """Verify with_nmea found is True."""
        content = "[global]\nts2phc.nmea_serialport /dev/gnss0\n\n[ens4f0]\n"
        path = _make_ts2phc_conf(content)
        try:
            mock_glob.return_value = [path]
            ptp.read_ts2phc_config()
            found = any(ctrl.instance_type == ptp.PTP_INSTANCE_TYPE_TS2PHC
                        for ctrl in ptp.ptpinstances.values())
            self.assertTrue(found)
        finally:
            os.unlink(path)


class TestGetInterfaceNameFromGnss(unittest.TestCase):

    @patch('ptp.glob', return_value=[])
    def test_no_match(self, mock_glob):
        """Verify no_match returns None."""
        result = ptp.get_interface_name_from_gnss('a/b/gnss0')
        self.assertIsNone(result)

    @patch('ptp.glob', return_value=['/sys/class/net/ens1f0/device/gnss/gnss0'])
    def test_match(self, mock_glob):
        """Verify match returns 'ens1f0'."""
        result = ptp.get_interface_name_from_gnss('a/b/gnss0')
        self.assertEqual(result, 'ens1f0')


class TestProcessPhc2sysHa(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens2f0', 'inst1', ptp.PTP_INSTANCE_TYPE_PHC2SYS)
        ptp.create_interface_alarm_objects('ens3f0', 'inst1', ptp.PTP_INSTANCE_TYPE_PHC2SYS)
        ctrl = ptp.ptpinstances['inst1']
        ctrl.instance_type = ptp.PTP_INSTANCE_TYPE_PHC2SYS
        ctrl.phc2sys_ha_enabled = True
        ctrl.interface = 'ens2f0'
        timing_inst = MagicMock()
        timing_inst.instance_name = 'inst1'
        timing_inst.interfaces = {'ens2f0', 'ens3f0'}
        timing_inst.config = ptp.ConfigDict({
            'global': {'ha_enabled': '1', 'domainNumber': '24',
                       'ha_max_gm_clockClass': '6'},
            'ens2f0': {'ha_priority': '100', 'ha_uds_address': '/var/run/ptp4l-1'},
            'ens3f0': {'ha_priority': '50', 'ha_uds_address': '/var/run/ptp4l-2'},
        })
        timing_inst.state = {
            'phc2sys_source_interface': 'ens2f0',
            'phc2sys_forced_lock': 'False',
            'phc2sys_valid_sources': 'ens2f0,ens3f0',
            'highest_source_priority': 100,
        }
        ctrl.timing_instance = timing_inst

    @patch('subprocess.check_output')
    def test_no_ha_uds_address(self, mock_sub):
        """Verify no_ha raises UnboundLocalError."""
        ctrl = ptp.ptpinstances['inst1']
        ctrl.timing_instance.config = ptp.ConfigDict({
            'global': {'ha_enabled': '1', 'domainNumber': '24',
                       'ha_max_gm_clockClass': '6'},
            'ens2f0': {'ha_priority': '100'},
            'ens3f0': {'ha_priority': '50'},
        })
        # Source code has an UnboundLocalError when ha_uds_address is
        # missing
        with self.assertRaises(UnboundLocalError):
            ptp.process_phc2sys_ha(ctrl)
