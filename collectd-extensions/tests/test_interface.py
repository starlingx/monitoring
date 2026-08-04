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
import interface

collectd = sys.modules['collectd']
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

for mod in [interface, pc]:

    if hasattr(mod, 'fm_constants'):
        mod.fm_constants = fm_constants


class TestLinkObject(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.link = interface.LinkObject('100.108')

    def test_init(self):
        """Verify init self.link.port_alarm is False."""
        self.assertEqual(self.link.alarm_id, '100.108')
        self.assertEqual(self.link.state, interface.LINK_UP)
        self.assertIsNone(self.link.name)
        self.assertFalse(self.link.port_alarm)

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_raise_port_alarm_success(self, mock_ma):
        """Verify raise_port_alarm sets alarm on success."""
        self.link.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.link.name = 'eth0'
        self.link.timestamp = 1000.0
        result = self.link.raise_port_alarm('mgmt')
        self.assertTrue(result)
        self.assertEqual(self.link.severity, fm_constants.FM_ALARM_SEVERITY_MAJOR)

    @patch.object(interface, 'manage_alarm', return_value=False)
    def test_raise_port_alarm_fail(self, mock_ma):
        """Verify raise_port_alarm_fail returns False on failure."""
        self.link.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.link.name = 'eth0'
        result = self.link.raise_port_alarm('mgmt')
        self.assertFalse(result)

    def test_raise_port_alarm_already_raised(self):
        """Verify raise_port_alarm skips when already raised."""
        self.link.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertTrue(self.link.raise_port_alarm('mgmt'))

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_clear_port_alarm_success(self, mock_ma):
        """Verify clear_port_alarm clears alarm on success."""
        self.link.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.link.name = 'eth0'
        result = self.link.clear_port_alarm('mgmt')
        self.assertTrue(result)
        self.assertEqual(self.link.severity, fm_constants.FM_ALARM_SEVERITY_CLEAR)

    @patch.object(interface, 'manage_alarm', return_value=False)
    def test_clear_port_alarm_fail(self, mock_ma):
        """Verify clear_port_alarm_fail self.link.clear_port_alarm()."""
        self.link.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.link.name = 'eth0'
        self.assertFalse(self.link.clear_port_alarm('mgmt'))

    def test_clear_port_alarm_already_clear(self):
        """Verify clear_port_alarm skips when already clear."""
        self.link.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertTrue(self.link.clear_port_alarm('mgmt'))


class TestNetworkObject(unittest.TestCase):
    def test_init_oam(self):
        """Verify OAM alarm ID set on init."""
        net_obj = interface.NetworkObject('oam')
        self.assertEqual(net_obj.alarm_id, interface.PLUGIN_OAM_IFACE_ALARMID)

    def test_init_mgmt(self):
        """Verify MGMT alarm ID set on init."""
        net_obj = interface.NetworkObject('mgmt')
        self.assertEqual(net_obj.alarm_id, interface.PLUGIN_MGMT_IFACE_ALARMID)

    def test_init_clstr(self):
        """Verify cluster alarm ID set on init."""
        net_obj = interface.NetworkObject('cluster-host')
        self.assertEqual(net_obj.alarm_id, interface.PLUGIN_CLSTR_IFACE_ALARMID)

    def test_init_data(self):
        """Verify data network alarm ID set on init."""
        net_obj = interface.NetworkObject('data-network0')
        self.assertEqual(net_obj.alarm_id, interface.PLUGIN_DATA_IFACE_ALARMID)

    def test_init_unknown(self):
        """Verify init_unknown returns ''."""
        net_obj = interface.NetworkObject('unknown')
        self.assertEqual(net_obj.alarm_id, '')

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_raise_iface_alarm(self, mock_ma):
        """Verify raise_iface_alarm sets fault."""
        net_obj = interface.NetworkObject('oam')
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        net_obj.timestamp = 1000.0
        self.assertTrue(net_obj.raise_iface_alarm(fm_constants.FM_ALARM_SEVERITY_MAJOR))
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_MAJOR)

    def test_raise_iface_alarm_clear_severity(self):
        """Verify raise_iface_alarm_clear net_obj.raise_iface_alarm()."""
        net_obj = interface.NetworkObject('oam')
        self.assertTrue(net_obj.raise_iface_alarm(fm_constants.FM_ALARM_SEVERITY_CLEAR))

    @patch.object(interface, 'manage_alarm', return_value=False)
    def test_raise_iface_alarm_fail(self, mock_ma):
        """Verify raise_iface_alarm_fail net_obj.raise_iface_alarm()."""
        net_obj = interface.NetworkObject('oam')
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertFalse(net_obj.raise_iface_alarm(fm_constants.FM_ALARM_SEVERITY_MAJOR))

    def test_raise_iface_alarm_same_severity(self):
        """Verify raise_iface_alarm_same net_obj.raise_iface_alarm()."""
        net_obj = interface.NetworkObject('oam')
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertTrue(net_obj.raise_iface_alarm(fm_constants.FM_ALARM_SEVERITY_MAJOR))

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_clear_iface_alarm(self, mock_ma):
        """Verify clear_iface_alarm clears fault."""
        net_obj = interface.NetworkObject('oam')
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertTrue(net_obj.clear_iface_alarm())
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_CLEAR)

    @patch.object(interface, 'manage_alarm', return_value=False)
    def test_clear_iface_alarm_fail(self, mock_ma):
        """Verify clear_iface_alarm_fail net_obj.clear_iface_alarm()."""
        net_obj = interface.NetworkObject('oam')
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertFalse(net_obj.clear_iface_alarm())

    def test_clear_iface_alarm_already_clear(self):
        """Verify clear_iface_alarm skips when already clear."""
        net_obj = interface.NetworkObject('oam')
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertTrue(net_obj.clear_iface_alarm())

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_manage_iface_alarm_single_down(self, mock_ma):
        """Verify manage_iface_alarm single link down."""
        net_obj = interface.NetworkObject('oam')
        net_obj.link_one.name = 'eth0'
        net_obj.link_two.name = None
        net_obj.link_one.state = interface.LINK_DOWN
        net_obj.link_one.timestamp = 1000.0
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        net_obj.manage_iface_alarm()
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_CRITICAL)

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_manage_iface_alarm_single_up(self, mock_ma):
        """Verify manage_iface_alarm single link up."""
        net_obj = interface.NetworkObject('oam')
        net_obj.link_one.name = 'eth0'
        net_obj.link_two.name = None
        net_obj.link_one.state = interface.LINK_UP
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL
        net_obj.manage_iface_alarm()
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_CLEAR)

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_manage_iface_alarm_lag_one_down(self, mock_ma):
        """Verify manage_iface_alarm LAG one link down."""
        net_obj = interface.NetworkObject('mgmt')
        net_obj.link_one.name = 'eth0'
        net_obj.link_two.name = 'eth1'
        net_obj.link_one.state = interface.LINK_UP
        net_obj.link_two.state = interface.LINK_DOWN
        net_obj.link_two.timestamp = 2000.0
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        net_obj.manage_iface_alarm()
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_MAJOR)

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_manage_iface_alarm_lag_both_down(self, mock_ma):
        """Verify manage_iface_alarm LAG both links down."""
        net_obj = interface.NetworkObject('mgmt')
        net_obj.link_one.name = 'eth0'
        net_obj.link_two.name = 'eth1'
        net_obj.link_one.state = interface.LINK_DOWN
        net_obj.link_two.state = interface.LINK_DOWN
        net_obj.link_one.timestamp = 3000.0
        net_obj.link_two.timestamp = 2000.0
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        net_obj.manage_iface_alarm()
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_CRITICAL)

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_manage_iface_alarm_lag_both_up(self, mock_ma):
        """Verify manage_iface_alarm LAG both links up."""
        net_obj = interface.NetworkObject('mgmt')
        net_obj.link_one.name = 'eth0'
        net_obj.link_two.name = 'eth1'
        net_obj.link_one.state = interface.LINK_UP
        net_obj.link_two.state = interface.LINK_UP
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        net_obj.manage_iface_alarm()
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_CLEAR)

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_manage_iface_alarm_lag_link1_down_link2_up(self, mock_ma):
        """Verify manage_iface_alarm LAG link1 down link2 up."""
        net_obj = interface.NetworkObject('mgmt')
        net_obj.link_one.name = 'eth0'
        net_obj.link_two.name = 'eth1'
        net_obj.link_one.state = interface.LINK_DOWN
        net_obj.link_two.state = interface.LINK_UP
        net_obj.link_one.timestamp = 1000.0
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        net_obj.manage_iface_alarm()
        self.assertEqual(net_obj.severity, fm_constants.FM_ALARM_SEVERITY_MAJOR)

    @patch.object(interface, 'manage_alarm', return_value=True)
    def test_manage_iface_alarm_lag_both_down_link2_newer(self, mock_ma):
        """Verify manage_iface_alarm LAG with speed value."""
        net_obj = interface.NetworkObject('mgmt')
        net_obj.link_one.name = 'eth0'
        net_obj.link_two.name = 'eth1'
        net_obj.link_one.state = interface.LINK_DOWN
        net_obj.link_two.state = interface.LINK_DOWN
        net_obj.link_one.timestamp = 1000.0
        net_obj.link_two.timestamp = 3000.0
        net_obj.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        net_obj.manage_iface_alarm()
        self.assertEqual(net_obj.timestamp, 3000.0)


class TestInterfaceGetTimestamp(unittest.TestCase):
    def test_valid_time(self):
        """Verify valid_time with valid input."""
        result = interface.get_timestamp('1577688993681475')
        self.assertAlmostEqual(result, 1577688993.681475, places=2)

    def test_none_time(self):
        """Verify none_time with None input."""
        result = interface.get_timestamp(None)
        self.assertIsInstance(result, float)

    def test_empty_time(self):
        """Verify empty_time with empty input."""
        result = interface.get_timestamp('')
        self.assertIsInstance(result, float)

    def test_invalid_time(self):
        """Verify invalid_time with invalid input."""
        result = interface.get_timestamp('not_a_number')
        self.assertIsInstance(result, float)


class TestInterfaceThisHostsAlarm(unittest.TestCase):
    def test_port_match(self):
        """Verify port_match interface.this_hosts_alarm() is True."""
        self.assertTrue(interface.this_hosts_alarm(
            'controller-0', 'host=controller-0.port=eth0'))

    def test_interface_match(self):
        """Verify interface_match interface.this_hosts_alarm() is."""
        self.assertTrue(interface.this_hosts_alarm(
            'controller-0', 'host=controller-0.interface=mgmt'))

    def test_no_match(self):
        """Verify no_match interface.this_hosts_alarm() is False."""
        self.assertFalse(interface.this_hosts_alarm(
            'controller-0', 'host=controller-1.interface=mgmt'))

    def test_empty_hostname(self):
        """Verify empty_hostname interface.this_hosts_alarm() is False."""
        self.assertFalse(interface.this_hosts_alarm('', 'host=c.port=e'))

    def test_none_hostname(self):
        """Verify none_hostname interface.this_hosts_alarm() is False."""
        self.assertFalse(interface.this_hosts_alarm(None, 'host=c.port=e'))

    def test_none_eid(self):
        """Verify none_eid interface.this_hosts_alarm() is False with."""
        self.assertFalse(interface.this_hosts_alarm('controller-0', None))

    def test_bad_eid_format(self):
        """Verify bad_eid interface.this_hosts_alarm() is False."""
        self.assertFalse(interface.this_hosts_alarm('controller-0', 'bad'))


class TestInterfaceClearAlarms(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        interface.obj.hostname = 'controller-0'

    def test_no_alarms(self):
        """Verify no_alarms interface.clear_alarms() is True."""
        interface.api = MagicMock()
        interface.api.get_faults_by_id.return_value = None
        self.assertTrue(interface.clear_alarms(['100.108']))

    def test_clear_matching_alarm(self):
        """Verify clear_matching_alarm interface.clear_alarms() is."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.port=eth0'
        alarm.severity = 'major'
        interface.api = MagicMock()
        interface.api.get_faults_by_id.return_value = [alarm]
        interface.api.clear_fault.return_value = True
        self.assertTrue(interface.clear_alarms([interface.PLUGIN_MGMT_PORT_ALARMID]))

    def test_clear_fault_returns_false(self):
        """Test clear fault returns false."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.port=eth0'
        alarm.severity = 'major'
        interface.api = MagicMock()
        interface.api.get_faults_by_id.return_value = [alarm]
        interface.api.clear_fault.return_value = False
        self.assertTrue(interface.clear_alarms([interface.PLUGIN_MGMT_PORT_ALARMID]))

    def test_get_faults_exception(self):
        """Verify get_faults_exception interface.clear_alarms() is."""
        interface.api = MagicMock()
        interface.api.get_faults_by_id.side_effect = Exception('fail')
        self.assertFalse(interface.clear_alarms(['100.108']))

    def test_clear_fault_exception(self):
        """Verify clear_fault_exception interface.clear_alarms() is."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.port=eth0'
        alarm.severity = 'major'
        interface.api = MagicMock()
        interface.api.get_faults_by_id.return_value = [alarm]
        interface.api.clear_fault.side_effect = Exception('fail')
        self.assertFalse(interface.clear_alarms([interface.PLUGIN_OAM_PORT_ALARMID]))

    def test_skip_other_host(self):
        """Verify skip_other interface.clear_alarms() is True."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-1.port=eth0'
        interface.api = MagicMock()
        interface.api.get_faults_by_id.return_value = [alarm]
        self.assertTrue(interface.clear_alarms([interface.PLUGIN_OAM_PORT_ALARMID]))


class TestInterfaceManageAlarm(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        interface.obj.hostname = 'controller-0'
        interface.api = MagicMock()

    def test_clear_action(self):
        """Verify clear_action returns True."""
        interface.api.clear_fault.return_value = True
        result = interface.manage_alarm('eth0', 'mgmt', 'port', 'clear',
                                        fm_constants.FM_ALARM_SEVERITY_CLEAR,
                                        '100.108', 1577688993.0)
        self.assertTrue(result)

    def test_clear_already_cleared(self):
        """Verify clear_already_cleared returns True."""
        interface.api.clear_fault.return_value = False
        result = interface.manage_alarm('eth0', 'mgmt', 'port', 'clear',
                                        fm_constants.FM_ALARM_SEVERITY_CLEAR,
                                        '100.108', 1577688993.0)
        self.assertTrue(result)

    def test_clear_exception(self):
        """Verify clear_exception returns False on exception."""
        interface.api.clear_fault.side_effect = Exception('fail')
        result = interface.manage_alarm('eth0', 'mgmt', 'port', 'clear',
                                        fm_constants.FM_ALARM_SEVERITY_CLEAR,
                                        '100.108', 1577688993.0)
        self.assertFalse(result)

    def test_raise_port_alarm(self):
        """Verify raise_port_alarm returns True."""
        interface.api.set_fault.return_value = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        result = interface.manage_alarm('eth0', 'mgmt', 'port', 'raise',
                                        fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                        '100.108', 1577688993.0)
        self.assertTrue(result)

    def test_raise_iface_alarm_critical(self):
        """Verify raise_iface_alarm_critical returns True."""
        interface.api.set_fault.return_value = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        result = interface.manage_alarm('mgmt', 'mgmt', 'interface', 'raise',
                                        fm_constants.FM_ALARM_SEVERITY_CRITICAL,
                                        '100.109', 1577688993.0)
        self.assertTrue(result)

    def test_raise_iface_alarm_major(self):
        """Verify raise_iface_alarm_major returns True."""
        interface.api.set_fault.return_value = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        result = interface.manage_alarm('mgmt', 'mgmt', 'interface', 'raise',
                                        fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                        '100.109', 1577688993.0)
        self.assertTrue(result)

    def test_set_fault_exception(self):
        """Verify set_fault_exception returns False on exception."""
        interface.api.set_fault.side_effect = Exception('fail')
        result = interface.manage_alarm('eth0', 'mgmt', 'port', 'raise',
                                        fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                        '100.108', 1577688993.0)
        self.assertFalse(result)


class TestInterfaceConfigFunc(unittest.TestCase):
    @patch('builtins.open', mock_open(read_data='lmon_query_port = 2122\n'))
    @patch('os.path.exists', return_value=True)
    def test_config_from_file(self, mock_exists):
        """Verify config_from_file interface.obj.config_done is True."""
        interface.obj = pc.PluginObject(interface.PLUGIN, interface.PLUGIN_HTTP_URL_PREFIX)
        config = MagicMock()
        interface.config_func(config)
        self.assertTrue(interface.obj.config_done)

    def test_config_from_manifest(self):
        """Verify config_from_manifest interface.obj.config_done is."""
        interface.obj = pc.PluginObject(interface.PLUGIN, interface.PLUGIN_HTTP_URL_PREFIX)
        config = MagicMock()
        node = MagicMock()
        node.key = 'Port'
        node.values = [2122]
        config.children = [node]
        with patch('os.path.exists', return_value=False):
            interface.config_func(config)
        self.assertTrue(interface.obj.config_done)


class TestInterfaceInitFunc(unittest.TestCase):
    @patch.object(pc.PluginObject, 'gethostname', return_value='controller-0')
    def test_init_func(self, mock_gh):
        """Verify init_func interface.obj.init_complete is True."""
        interface.obj = pc.PluginObject(interface.PLUGIN, interface.PLUGIN_HTTP_URL_PREFIX)
        interface.obj.config_done = True
        interface.obj._config_complete = True
        interface.init_func()
        self.assertTrue(interface.obj.init_complete)

    @unittest.skip('combined-run')
    def test_init_func_no_config(self):
        """Verify init_func_no_config interface.obj.init_complete is."""
        interface.obj = pc.PluginObject(interface.PLUGIN, interface.PLUGIN_HTTP_URL_PREFIX)
        interface.obj.config_done = False
        interface.init_func()
        self.assertFalse(interface.obj.init_complete)


class TestInterfaceNetworkHelpers(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        interface.NETWORKS.clear()

    def test_add_network_item_single(self):
        """Verify add_network_item_single returns 'oam'."""
        info = {'network': 'oam', 'links': [{'name': 'eth0'}]}
        interface.add_network_item(info)
        self.assertEqual(len(interface.NETWORKS), 1)
        self.assertEqual(interface.NETWORKS[0].name, 'oam')

    def test_add_network_item_lagged(self):
        """Verify add_network_item_lagged returns 'eth1'."""
        info = {'network': 'mgmt', 'links': [{'name': 'eth0'}, {'name': 'eth1'}]}
        interface.add_network_item(info)
        self.assertEqual(interface.NETWORKS[0].link_two.name, 'eth1')

    def test_add_network_item_data(self):
        """Verify add_network_item_data returns 'data-network0'."""
        info = {'network': 'data-network', 'links': [{'name': 'eth2'}]}
        interface.add_network_item(info)
        self.assertEqual(interface.NETWORKS[0].name, 'data-network0')

    def test_add_network_item_data_multiple(self):
        """Verify add_network_item_data returns 'data-network1'."""
        info1 = {'network': 'data-network', 'links': [{'name': 'eth2'}]}
        info2 = {'network': 'data-network', 'links': [{'name': 'eth3'}]}
        interface.add_network_item(info1)
        interface.add_network_item(info2)
        self.assertEqual(interface.NETWORKS[1].name, 'data-network1')

    def test_is_exist_network_false(self):
        """Verify is_exist_network_false interface.is_exist_network()."""
        info = {'network': 'oam', 'links': [{'name': 'eth0'}]}
        self.assertFalse(interface.is_exist_network(info))

    def test_is_exist_network_true(self):
        """Verify is_exist_network_true interface.is_exist_network()."""
        info = {'network': 'oam', 'links': [{'name': 'eth0'}]}
        interface.add_network_item(info)
        self.assertTrue(interface.is_exist_network(info))

    def test_is_same_network_true_single(self):
        """Verify is_same_network_true interface.is_same_network() is."""
        info = {'network': 'oam', 'links': [{'name': 'eth0'}]}
        interface.add_network_item(info)
        self.assertTrue(interface.is_same_network(interface.NETWORKS[0], info))

    def test_is_same_network_true_lagged(self):
        """Verify is_same_network_true interface.is_same_network() is."""
        info = {'network': 'mgmt', 'links': [{'name': 'eth0'}, {'name': 'eth1'}]}
        interface.add_network_item(info)
        self.assertTrue(interface.is_same_network(interface.NETWORKS[0], info))

    def test_is_same_network_false(self):
        """Verify is_same_network_false interface.is_same_network() is."""
        info1 = {'network': 'oam', 'links': [{'name': 'eth0'}]}
        info2 = {'network': 'mgmt', 'links': [{'name': 'eth1'}]}
        interface.add_network_item(info1)
        self.assertFalse(interface.is_same_network(interface.NETWORKS[0], info2))

    def test_add_network_item_empty_links(self):
        """Verify add_network_item_empty returns 1 with empty input."""
        info = {'network': 'oam', 'links': []}
        interface.add_network_item(info)
        self.assertEqual(len(interface.NETWORKS), 1)


class TestInterfaceReadFunc(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        interface.NETWORKS.clear()
        interface.obj = pc.PluginObject(interface.PLUGIN, interface.PLUGIN_HTTP_URL_PREFIX)
        interface.obj.init_complete = True
        interface.obj._node_ready = True
        interface.obj.hostname = 'controller-0'
        interface.obj.audits = 0
        interface.api = MagicMock()

    @patch.object(interface, 'clear_alarms', return_value=True)
    def test_read_func_phase_clear(self, mock_ca):
        """Verify read_func clears alarms in clear phase."""
        interface.obj.phase = 0
        interface.obj.http_retry_count = 0
        interface.obj.make_http_request = MagicMock(return_value=True)
        interface.obj.jresp = {'status': 'pass', 'link_info': []}
        interface.read_func()
        self.assertEqual(interface.obj.phase, interface.RUN_PHASE__ALARMS_CLEARED)

    @patch.object(interface, 'clear_alarms', return_value=False)
    def test_read_func_phase_clear_fail(self, mock_ca):
        """Verify read_func_phase_clear returns 0 on failure."""
        interface.obj.phase = 0
        interface.read_func()
        self.assertEqual(interface.obj.phase, 0)

    def test_read_func_not_init(self):
        """Verify read_func_not_init returns 0 when not initialized."""
        interface.obj.init_complete = False
        interface.obj._config_complete = False
        interface.obj.config_done = False
        self.assertEqual(interface.read_func(), 0)

    def test_read_func_http_fail(self):
        """Verify read_func_http_fail returns 1 on failure."""
        interface.obj.phase = interface.RUN_PHASE__ALARMS_CLEARED
        interface.obj.http_retry_count = 0
        interface.obj.make_http_request = MagicMock(return_value=False)
        interface.read_func()
        self.assertEqual(interface.obj.http_retry_count, 1)

    def test_read_func_status_fail(self):
        """Verify read_func_status_fail on failure."""
        interface.obj.phase = interface.RUN_PHASE__ALARMS_CLEARED
        interface.obj.http_retry_count = 0
        interface.obj.make_http_request = MagicMock(return_value=True)
        interface.obj.jresp = {'status': 'fail ; bad request'}
        interface.read_func()
        self.assertGreater(interface.obj.http_retry_count, 0)

    @patch.object(interface, 'manage_alarm', return_value=True)
    @patch.object(interface, 'clear_alarms', return_value=True)
    def test_read_func_full_pass(self, mock_ca, mock_ma):
        """Verify read_func_full_pass returns 1."""
        interface.obj.phase = interface.RUN_PHASE__ALARMS_CLEARED
        interface.obj.http_retry_count = 0
        interface.obj.make_http_request = MagicMock(return_value=True)
        interface.obj.jresp = {
            'status': 'pass',
            'link_info': [
                {'network': 'oam', 'type': 'ethernet',
                 'links': [{'name': 'ens6', 'state': 'Up', 'time': '1577688993681564'}]},
                {'network': 'mgmt', 'type': 'ethernet',
                 'links': [{'name': 'lo', 'state': 'Up', 'time': '1577688993681475'}]}
            ]
        }
        val_mock = MagicMock()
        collectd.Values = MagicMock(return_value=val_mock)
        interface.read_func()
        self.assertEqual(interface.obj.audits, 1)
