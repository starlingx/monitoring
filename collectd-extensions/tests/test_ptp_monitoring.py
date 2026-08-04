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


class TestInitFunc(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.os.path.exists', return_value=False)
    @patch('ptp.glob', return_value=[])
    @patch.object(ptp.obj, 'config_complete', return_value=False)
    def test_init_config_not_complete(self, mock_cc, mock_glob, mock_exists):
        """Verify init_config_not_complete returns False when not."""
        result = ptp.init_func()
        self.assertFalse(result)

    @patch('ptp.cgu_handler')
    @patch('ptp.tsc')
    @patch('ptp.os.path.exists', return_value=False)
    @patch('ptp.glob', return_value=[])
    @patch.object(ptp.obj, 'config_complete', return_value=True)
    @patch.object(ptp.obj, 'gethostname', return_value='testhost')
    @patch.object(ptp.obj, 'is_virtual', return_value=False)
    def test_init_no_ptpinstance_path(self, mock_virt, mock_host, mock_cc,
                                      mock_glob, mock_exists, mock_tsc, mock_cgu):
        """Verify init_no_ptpinstance_path ptp.obj.init_complete is."""
        mock_tsc.nodetype = 'worker'
        mock_cgu.read_cgu.return_value = None
        mock_cgu.cgu_output_to_dict.return_value = {}
        result = ptp.init_func()
        self.assertEqual(result, 0)
        self.assertTrue(ptp.obj.init_complete)

    @patch('ptp.cgu_handler')
    @patch('ptp.tsc')
    @patch('ptp.read_ptp4l_config')
    @patch('ptp.read_ts2phc_config')
    @patch('ptp.read_clock_config')
    @patch('ptp.read_files_for_timing_instances')
    @patch('ptp.read_gnss_monitor_ptp_config')
    @patch('ptp.read_instance_monitoring_config')
    @patch('ptp.os.path.exists', return_value=True)
    @patch('ptp.glob', return_value=[])
    @patch.object(ptp.obj, 'config_complete', return_value=True)
    @patch.object(ptp.obj, 'gethostname', return_value='testhost')
    @patch.object(ptp.obj, 'is_virtual', return_value=False)
    def test_init_with_ptpinstance_path(self, mock_virt, mock_host, mock_cc,
                                        mock_glob, mock_exists,
                                        mock_rim, mock_rgnss, mock_rfti,
                                        mock_rcc, mock_rts, mock_rp4l,
                                        mock_tsc, mock_cgu):
        """Verify init_with_ptpinstance_path ptp.obj.controller is."""
        mock_tsc.nodetype = 'controller'
        mock_cgu.read_cgu.return_value = None
        mock_cgu.cgu_output_to_dict.return_value = {}
        result = ptp.init_func()
        self.assertEqual(result, 0)
        self.assertTrue(ptp.obj.controller)


class TestReadFunc(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_read_func_virtual(self):
        """Verify read_func_virtual returns 0."""
        ptp.obj.virtual = True
        result = ptp.read_func()
        self.assertEqual(result, 0)

    @patch('ptp.init_func')
    def test_read_func_not_initialized(self, mock_init):
        """Verify read_func_not_initialized is called once when not."""
        ptp.obj.init_complete = False
        ptp.obj.virtual = False
        result = ptp.read_func()
        self.assertEqual(result, 0)
        mock_init.assert_called_once()

    @patch('ptp.cgu_handler')
    @patch('subprocess.check_output')
    @patch.object(ptp.obj, 'node_ready', return_value=False)
    def test_read_func_node_not_ready(self, mock_nr, mock_sub, mock_cgu):
        """Verify read_func_node_not returns 0 when not ready."""
        ptp.obj.init_complete = True
        ptp.obj.virtual = False
        ptp.obj._node_ready = False
        result = ptp.read_func()
        self.assertEqual(result, 0)

    @patch('ptp.cgu_handler')
    @patch('ptp.api')
    @patch('subprocess.check_output')
    @patch.object(ptp.obj, 'node_ready', return_value=True)
    def test_read_func_node_ready_no_alarms(self, mock_nr, mock_sub, mock_api, mock_cgu):
        """Verify read_func_node_ready returns 0."""
        ptp.obj.init_complete = True
        ptp.obj.virtual = False
        ptp.obj._node_ready = False
        mock_api.get_faults_by_id.return_value = None
        mock_cgu.read_cgu.return_value = None
        mock_cgu.cgu_output_to_dict.return_value = {}
        result = ptp.read_func()
        self.assertEqual(result, 0)

    @patch('ptp.cgu_handler')
    @patch('ptp.api')
    @patch('subprocess.check_output')
    @patch.object(ptp.obj, 'node_ready', return_value=True)
    def test_read_func_node_ready_with_alarms(self, mock_nr, mock_sub, mock_api, mock_cgu):
        """Verify read_func_node_ready returns 0."""
        ptp.obj.init_complete = True
        ptp.obj.virtual = False
        ptp.obj._node_ready = False
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=testhost.ptp=inst1'
        mock_api.get_faults_by_id.return_value = [alarm]
        mock_api.clear_fault.return_value = True
        mock_cgu.read_cgu.return_value = None
        mock_cgu.cgu_output_to_dict.return_value = {}
        result = ptp.read_func()
        self.assertEqual(result, 0)

    @patch('ptp.cgu_handler')
    @patch('ptp.api')
    @patch('subprocess.check_output')
    @patch.object(ptp.obj, 'node_ready', return_value=True)
    def test_read_func_alarm_clear_fails(self, mock_nr, mock_sub, mock_api, mock_cgu):
        """Verify read_func_alarm_clear returns 0 on failure."""
        ptp.obj.init_complete = True
        ptp.obj.virtual = False
        ptp.obj._node_ready = False
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=testhost.ptp=inst1'
        mock_api.get_faults_by_id.return_value = [alarm]
        mock_api.clear_fault.return_value = False
        mock_cgu.read_cgu.return_value = None
        mock_cgu.cgu_output_to_dict.return_value = {}
        result = ptp.read_func()
        self.assertEqual(result, 0)

    @patch('ptp.cgu_handler')
    @patch('ptp.api')
    @patch('subprocess.check_output')
    @patch.object(ptp.obj, 'node_ready', return_value=True)
    def test_read_func_alarm_no_eid(self, mock_nr, mock_sub, mock_api, mock_cgu):
        """Verify read_func_alarm_no returns 0."""
        ptp.obj.init_complete = True
        ptp.obj.virtual = False
        ptp.obj._node_ready = False
        alarm = MagicMock()
        alarm.entity_instance_id = None
        mock_api.get_faults_by_id.return_value = [alarm]
        mock_cgu.read_cgu.return_value = None
        mock_cgu.cgu_output_to_dict.return_value = {}
        result = ptp.read_func()
        self.assertEqual(result, 0)

    @patch('ptp.cgu_handler')
    @patch('ptp.api')
    @patch('subprocess.check_output')
    @patch.object(ptp.obj, 'node_ready', return_value=True)
    def test_read_func_alarm_different_host(self, mock_nr, mock_sub, mock_api, mock_cgu):
        """Verify read_func_alarm_different returns 0."""
        ptp.obj.init_complete = True
        ptp.obj.virtual = False
        ptp.obj._node_ready = False
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=otherhost.ptp=inst1'
        mock_api.get_faults_by_id.return_value = [alarm]
        mock_cgu.read_cgu.return_value = None
        mock_cgu.cgu_output_to_dict.return_value = {}
        result = ptp.read_func()
        self.assertEqual(result, 0)

    @patch('ptp.cgu_handler')
    @patch('ptp.api')
    @patch('subprocess.check_output')
    @patch.object(ptp.obj, 'node_ready', return_value=True)
    def test_read_func_get_faults_exception(self, mock_nr, mock_sub, mock_api, mock_cgu):
        """Verify read_func_get_faults returns 0 on exception."""
        ptp.obj.init_complete = True
        ptp.obj.virtual = False
        ptp.obj._node_ready = False
        mock_api.get_faults_by_id.side_effect = Exception("fm error")
        result = ptp.read_func()
        self.assertEqual(result, 0)


class TestCheckGnssAlarm(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ptp.ptpinstances['inst1'].monitoring_parameters = {
            'holdover_seconds': 14400,
            'locked_to_holdover_threshold_seconds': 300,
        }

    @patch('ptp.clear_alarm', return_value=True)
    def test_locked_clears_alarm(self, mock_clear):
        """Verify locked_clears alarm_obj.raised is False."""
        alarm_obj = ptp.ptpinstances['inst1'].gnss_signal_loss_alarm_object
        alarm_obj.raised = True
        ptp.check_gnss_alarm('inst1', alarm_obj, 'ens1f0', ptp.CLOCK_STATE_LOCKED)
        self.assertFalse(alarm_obj.raised)

    @patch('ptp.clear_alarm', return_value=True)
    def test_locked_ho_acq_clears(self, mock_clear):
        """Verify locked_ho alarm_obj.raised is False."""
        alarm_obj = ptp.ptpinstances['inst1'].gnss_signal_loss_alarm_object
        alarm_obj.raised = True
        ptp.check_gnss_alarm('inst1', alarm_obj, 'ens1f0', ptp.CLOCK_STATE_LOCKED_HO_ACQ)
        self.assertFalse(alarm_obj.raised)


class TestCheckPinAlarm(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')

    @patch('ptp.clear_alarm', return_value=True)
    def test_connected_clears(self, mock_clear):
        """Verify connected_clears alarm_obj.raised is False."""
        alarm_obj = ptp.PTP_alarm_object('ens1f0')
        alarm_obj.alarm = ptp.ALARM_CAUSE__1PPS_SIGNAL_LOSS
        alarm_obj.raised = True
        alarm_obj.eid = 'test_eid'
        ptp.check_pin_alarm('inst1', alarm_obj, 'ens1f0', ptp.PinState.CONNECTED)
        self.assertFalse(alarm_obj.raised)


class TestGetBasePort(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    def test_cached(self):
        """Verify cached returns 'ens1f0'."""
        ptp.base_port_map['ens1f0'] = 'ens1f0'
        self.assertEqual(ptp.get_base_port('ens1f0'), 'ens1f0')

    def test_compute_not_in_interfaces(self):
        """Verify compute_not returns None."""
        result = ptp.compute_base_port('ens99f0')
        self.assertIsNone(result)

    def test_compute_with_pci_slot(self):
        """Verify compute_with returns 'ens1f0'."""
        mock_iface = MagicMock()
        mock_iface.get_pci_slot.return_value = '0000:51:00.1'
        mock_iface.get_family.return_value = 'Columbiaville'
        ptp.interfaces['ens1f1'] = mock_iface

        mock_base = MagicMock()
        mock_base.get_pci_slot.return_value = '0000:51:00.0'
        mock_base.get_family.return_value = 'Columbiaville'
        ptp.interfaces['ens1f0'] = mock_base
        ptp.base_ports.append('ens1f0')

        result = ptp.compute_base_port('ens1f1')
        self.assertEqual(result, 'ens1f0')

    def test_compute_granite_rapid_d(self):
        """Verify compute_granite returns 'ens0f0'."""
        mock_iface = MagicMock()
        mock_iface.get_pci_slot.return_value = None
        mock_iface.get_family.return_value = 'Granite Rapid-D'
        ptp.interfaces['ens1f0'] = mock_iface

        mock_base = MagicMock()
        mock_base.get_family.return_value = 'Granite Rapid-D'
        ptp.interfaces['ens0f0'] = mock_base
        ptp.base_ports.append('ens0f0')

        result = ptp.compute_base_port('ens1f0')
        self.assertEqual(result, 'ens0f0')

    @patch('ptp.resolve_parent_interface', return_value='ens0f0')
    def test_compute_virtual_interface(self, mock_resolve):
        """Verify compute_virtual returns 'ens0f0'."""
        mock_iface = MagicMock()
        mock_iface.get_pci_slot.return_value = None
        mock_iface.get_family.return_value = 'unknown'
        ptp.interfaces['vlan100'] = mock_iface

        mock_parent = MagicMock()
        mock_parent.get_pci_slot.return_value = '0000:51:00.0'
        mock_parent.get_family.return_value = 'Columbiaville'
        ptp.interfaces['ens0f0'] = mock_parent

        mock_base = MagicMock()
        mock_base.get_pci_slot.return_value = '0000:51:00.0'
        mock_base.get_family.return_value = 'Columbiaville'
        ptp.interfaces['ens0f0'] = mock_base
        ptp.base_ports.append('ens0f0')

        result = ptp.compute_base_port('vlan100')
        self.assertEqual(result, 'ens0f0')

    @patch('ptp.resolve_parent_interface', return_value=None)
    def test_compute_virtual_no_parent(self, mock_resolve):
        """Verify compute_virtual returns None."""
        mock_iface = MagicMock()
        mock_iface.get_pci_slot.return_value = None
        mock_iface.get_family.return_value = 'unknown'
        ptp.interfaces['vlan100'] = mock_iface
        result = ptp.compute_base_port('vlan100')
        self.assertIsNone(result)

    @patch('ptp.resolve_parent_interface', return_value='ens0f0')
    def test_compute_virtual_granite_rapid_d_parent(self, mock_resolve):
        """Verify compute_virtual returns 'ens0f0_base'."""
        mock_iface = MagicMock()
        mock_iface.get_pci_slot.return_value = None
        mock_iface.get_family.return_value = 'unknown'
        ptp.interfaces['vlan100'] = mock_iface

        mock_parent = MagicMock()
        mock_parent.get_pci_slot.return_value = None
        mock_parent.get_family.return_value = 'Granite Rapid-D'
        ptp.interfaces['ens0f0'] = mock_parent

        mock_base = MagicMock()
        mock_base.get_family.return_value = 'Granite Rapid-D'
        ptp.interfaces['ens0f0_base'] = mock_base
        ptp.base_ports.append('ens0f0_base')

        result = ptp.compute_base_port('vlan100')
        self.assertEqual(result, 'ens0f0_base')


class TestGetDpllState(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.get_netlink_dpll_status')
    def test_eec_worse(self, mock_dpll):
        """Verify get_dpll_state returns worse EEC state."""
        mock_dpll.side_effect = [
            (ptp.CLOCK_STATE_UNLOCKED, None),
            (ptp.CLOCK_STATE_LOCKED, MagicMock()),
        ]
        state, pin = ptp.get_dpll_state('ens1f0')
        self.assertEqual(state, ptp.CLOCK_STATE_UNLOCKED)

    @patch('ptp.get_netlink_dpll_status')
    def test_pps_worse(self, mock_dpll):
        """Verify get_dpll_state returns worse PPS state."""
        mock_dpll.side_effect = [
            (ptp.CLOCK_STATE_LOCKED, MagicMock()),
            (ptp.CLOCK_STATE_HOLDOVER, MagicMock()),
        ]
        state, pin = ptp.get_dpll_state('ens1f0')
        self.assertEqual(state, ptp.CLOCK_STATE_HOLDOVER)


class TestCheckClockClass(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ctrl = ptp.ptpinstances['inst1']
        ctrl.instance_type = ptp.PTP_INSTANCE_TYPE_PTP4L
        ctrl.interface = 'ens1f0'
        ctrl.monitoring_parameters = {
            'holdover_seconds': 14400,
            'offset_threshold_minor_nsec': 1000,
            'offset_threshold_major_nsec': 1000000,
            'locked_to_holdover_threshold_seconds': 300,
        }
        timing_inst = MagicMock()
        timing_inst.config = ptp.ConfigDict({'global': {'dataset_comparison': 'G.8275.x'}})
        timing_inst.interfaces = {'ens1f0'}
        ctrl.timing_instance = timing_inst
        mock_iface = MagicMock()
        mock_iface.get_pci_slot.return_value = '0000:51:00.0'
        mock_iface.get_family.return_value = 'Columbiaville'
        ptp.interfaces['ens1f0'] = mock_iface
        ptp.base_port_map['ens1f0'] = 'ens1f0'
        ptp.base_ports.append('ens1f0')
        ptp.ts2phc_source_interfaces['ens1f0'] = 'ens1f0'
        ptp.ts2phc_instance_map['ens1f0'] = 'ts2phc_inst'

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.get_dpll_state', return_value=(ptp.CLOCK_STATE_LOCKED, MagicMock()))
    @patch('ptp.query_pmc', return_value={'clockClass': '248'})
    def test_locked_sets_class_6(self, mock_pmc, mock_dpll, mock_svc,
                                 mock_write, mock_wa):
        """Verify locked DPLL sets clock class 6."""
        ptp.check_clock_class('inst1')
        mock_write.assert_called()
        args = mock_write.call_args[0]
        self.assertEqual(args[1]['clockClass'], ptp.CLOCK_CLASS_6)

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.get_dpll_state', return_value=(ptp.CLOCK_STATE_UNLOCKED, None))
    @patch('ptp.query_pmc', return_value={'clockClass': '6'})
    def test_unlocked_sets_class_248(self, mock_pmc, mock_dpll, mock_svc,
                                     mock_write, mock_wa):
        """Verify unlocked DPLL sets clock class 248."""
        ptp.check_clock_class('inst1')
        mock_write.assert_called()
        args = mock_write.call_args[0]
        self.assertEqual(args[1]['clockClass'], ptp.CLOCK_CLASS_248)

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.get_dpll_state')
    @patch('ptp.query_pmc', return_value={'clockClass': '6'})
    @patch('ptp.timeutils')
    def test_holdover_within_spec(self, mock_time, mock_pmc, mock_dpll,
                                  mock_svc, mock_write, mock_wa):
        """Verify holdover within spec sets clock class 7."""
        mock_dpll.return_value = (ptp.CLOCK_STATE_HOLDOVER, MagicMock())
        # Setup ts2phc instance with holdover timestamp
        ptp.create_interface_alarm_objects('ens1f0', 'ts2phc_inst',
                                           ptp.PTP_INSTANCE_TYPE_TS2PHC)
        ptp.ptpinstances['ts2phc_inst'].instance_type = ptp.PTP_INSTANCE_TYPE_TS2PHC
        ptp.ptpinstances['ts2phc_inst'].holdover_timestamp['ens1f0'] = MagicMock()
        ptp.ptpinstances['ts2phc_inst'].monitoring_parameters = {
            'holdover_seconds': 14400,
        }
        mock_time.utcnow.return_value = MagicMock()
        mock_time.delta_seconds.return_value = 100
        ptp.check_clock_class('inst1')
        mock_write.assert_called()
        args = mock_write.call_args[0]
        self.assertEqual(args[1]['clockClass'], ptp.CLOCK_CLASS_7)


class TestReadTimeStatusNp(unittest.TestCase):

    @patch('subprocess.check_output')
    def test_basic(self, mock_sub):
        """Verify read_time_status_np parses master_offset."""
        mock_sub.return_value = (
            b"sending: GET TIME_STATUS_NP\n"
            b"abc123-0 seq 0 RESPONSE MANAGEMENT TIME_STATUS_NP\n"
            b"  master_offset  42\n"
            b"  gmPresent      true\n"
            b"  gmIdentity     def456\n"
        )
        my_id, gm_present, gm_id, got_offset, offset = \
            ptp.read_time_status_np('/tmp/test.conf')
        self.assertEqual(my_id, 'abc123')
        self.assertEqual(gm_id, 'def456')
        self.assertTrue(got_offset)
        self.assertEqual(offset, 42.0)

    @patch('subprocess.check_output')
    def test_socket_mode(self, mock_sub):
        """Verify socket_mode got_offset is False."""
        mock_sub.return_value = b"sending: GET TIME_STATUS_NP\n"
        my_id, gm_present, gm_id, got_offset, offset = \
            ptp.read_time_status_np('/var/run/sock', is_socket=True,
                                    domain_number='24')
        self.assertFalse(got_offset)


class TestIsLocalGm(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ptp.ptpinstances['inst1'].instance_type = ptp.PTP_INSTANCE_TYPE_PTP4L
        ptp.ptpinstances['inst1'].ptp4l_grandmaster_identity = 'abc'
        ptp.ptpinstances['inst1'].ptp4l_clock_identity = 'abc'

    @patch('ptp.query_pmc')
    def test_is_local(self, mock_pmc):
        """Verify is_local ptp.is_local_gm() is True."""
        mock_pmc.side_effect = [
            {'grandmasterIdentity': 'abc'},
            {'clockIdentity': 'abc'},
        ]
        self.assertTrue(ptp.is_local_gm('inst1'))

    @patch('ptp.query_pmc')
    def test_not_local(self, mock_pmc):
        """Verify not_local ptp.is_local_gm() is False."""
        mock_pmc.side_effect = [
            {'grandmasterIdentity': 'def'},
            {'clockIdentity': 'abc'},
        ]
        self.assertFalse(ptp.is_local_gm('inst1'))


class TestSetUtcOffset(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()
        ptp.create_interface_alarm_objects('ens1f0', 'inst1')
        ctrl = ptp.ptpinstances['inst1']
        ctrl.instance_type = ptp.PTP_INSTANCE_TYPE_PTP4L
        ctrl.interface = 'ens1f0'
        ctrl.ptp4l_current_utc_offset = 37
        timing_inst = MagicMock()
        timing_inst.config = ptp.ConfigDict({
            'global': {'domainNumber': '24', 'uds_address': '/var/run/ptp4l',
                       'ha_enabled': '0'}
        })
        ctrl.timing_instance = timing_inst

    @patch('subprocess.check_output')
    def test_utc_offset_valid(self, mock_sub):
        """Verify set_utc_offset parses valid offset."""
        mock_sub.return_value = (
            b"currentUtcOffset 37\n"
            b"currentUtcOffsetValid 1\n"
        )
        ptp.set_utc_offset('inst1')
        ctrl = ptp.ptpinstances['inst1']
        self.assertEqual(ctrl.ptp4l_current_utc_offset, 37)

    @patch('subprocess.check_output')
    def test_utc_offset_not_valid(self, mock_sub):
        """Verify set_utc_offset keeps old value on invalid."""
        mock_sub.return_value = (
            b"currentUtcOffset 38\n"
            b"currentUtcOffsetValid 0\n"
        )
        ptp.set_utc_offset('inst1')
        ctrl = ptp.ptpinstances['inst1']
        self.assertEqual(ctrl.ptp4l_current_utc_offset, 37)


class TestCheckPhc2sysOffset(unittest.TestCase):

    @patch('ptp.glob', return_value=[])
    def test_no_conf_files(self, mock_glob):
        """Verify no_conf returns None."""
        result = ptp.check_phc2sys_offset()
        self.assertIsNone(result)

    @patch('ptp._get_phc2sys_command_line_option')
    @patch('ptp.glob')
    def test_with_offset(self, mock_glob, mock_opt):
        """Verify check_phc2sys_offset computes nanoseconds."""
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/phc2sys-inst1.conf']
        mock_opt.side_effect = [None, '37']  # -c returns None, -O returns 37
        result = ptp.check_phc2sys_offset()
        self.assertEqual(result, 37000000000)

    @patch('ptp._get_phc2sys_command_line_option')
    @patch('ptp.glob')
    def test_clock_realtime(self, mock_glob, mock_opt):
        """Verify clock_realtime returns 0."""
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/phc2sys-inst1.conf']
        mock_opt.side_effect = ['CLOCK_REALTIME', '0']
        result = ptp.check_phc2sys_offset()
        self.assertEqual(result, 0)


class TestBlockUnblockPtpTraffic(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        _reset_module_state()

    @patch('ptp.resolve_parent_interface', return_value=None)
    @patch('subprocess.check_output', return_value=b'Added rule with ID 42\n')
    def test_block(self, mock_sub, mock_resolve):
        """Verify block returns '42'."""
        ptp.block_ptp_traffic('inst1', 'ens1f0')
        self.assertEqual(ptp.ethtool_rule_ids['ens1f0'], '42')

    @patch('ptp.resolve_parent_interface', return_value=None)
    @patch('subprocess.check_output',
           side_effect=ptp.subprocess.CalledProcessError(1, 'ethtool'))
    def test_block_failure(self, mock_sub, mock_resolve):
        """Verify block_failure on exception."""
        ptp.block_ptp_traffic('inst1', 'ens1f0')
        self.assertNotIn('ens1f0', ptp.ethtool_rule_ids)

    @patch('ptp.resolve_parent_interface', return_value=None)
    @patch('subprocess.check_call')
    def test_unblock(self, mock_sub, mock_resolve):
        """Verify unblock_ptp_traffic removes ethtool rule."""
        ptp.ethtool_rule_ids['ens1f0'] = '42'
        ptp.unblock_ptp_traffic('inst1', 'ens1f0')
        self.assertNotIn('ens1f0', ptp.ethtool_rule_ids)
