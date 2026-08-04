#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import sys
import datetime
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
import ovs_interface
import six as six_mock

tsc_mock = sys.modules['tsconfig.tsconfig']

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

for mod in [ovs_interface, pc]:

    if hasattr(mod, 'fm_constants'):
        mod.fm_constants = fm_constants


class TestOvsInterfaceObject(unittest.TestCase):
    def test_init(self):
        """Verify OVS link defaults to LINK_UP."""
        iface = ovs_interface.InterfaceObject('eth0')
        self.assertEqual(iface.name, 'eth0')
        self.assertEqual(iface.state, ovs_interface.LINK_UP)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_raise_alarm(self, mock_ma):
        """Verify OVS raise_alarm sets fault."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertTrue(iface._raise_alarm())
        self.assertEqual(iface.severity, fm_constants.FM_ALARM_SEVERITY_MAJOR)

    @patch.object(ovs_interface, 'manage_alarm', return_value=False)
    def test_raise_alarm_fail(self, mock_ma):
        """Verify raise_alarm_fail iface._raise_alarm() is False on."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertFalse(iface._raise_alarm())

    def test_raise_alarm_already_raised(self):
        """Verify raise_alarm_already_raised iface._raise_alarm() is."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertTrue(iface._raise_alarm())

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_clear_alarm(self, mock_ma):
        """Verify OVS clear_alarm clears fault."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertTrue(iface._clear_alarm())
        self.assertEqual(iface.severity, fm_constants.FM_ALARM_SEVERITY_CLEAR)

    @patch.object(ovs_interface, 'manage_alarm', return_value=False)
    def test_clear_alarm_fail(self, mock_ma):
        """Verify clear_alarm_fail iface._clear_alarm() is False on."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertFalse(iface._clear_alarm())

    def test_clear_alarm_already_clear(self):
        """Verify clear_alarm_already_clear iface._clear_alarm() is."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertTrue(iface._clear_alarm())

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_interface_alarm_up_to_down(self, mock_ma):
        """Verify manage_interface_alarm on up-to-down."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.state = ovs_interface.LINK_UP
        iface.manage_interface_alarm(ovs_interface.LINK_DOWN)
        self.assertEqual(iface.state, ovs_interface.LINK_DOWN)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_interface_alarm_down_to_up(self, mock_ma):
        """Verify manage_interface_alarm on down-to-up."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.state = ovs_interface.LINK_DOWN
        iface.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        iface.manage_interface_alarm(ovs_interface.LINK_UP)
        self.assertEqual(iface.state, ovs_interface.LINK_UP)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_interface_alarm_unknown(self, mock_ma):
        """Verify manage_interface_alarm with unknown state."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.state = ovs_interface.LINK_UP
        iface.manage_interface_alarm(ovs_interface.UNKNOWN_STATE)
        self.assertEqual(iface.state, ovs_interface.UNKNOWN_STATE)

    def test_manage_interface_alarm_no_change(self):
        """Verify manage_interface_alarm with no change."""
        iface = ovs_interface.InterfaceObject('eth0')
        iface.state = ovs_interface.LINK_UP
        iface.manage_interface_alarm(ovs_interface.LINK_UP)
        self.assertEqual(iface.state, ovs_interface.LINK_UP)


class TestOvsPortObject(unittest.TestCase):
    def test_init(self):
        """Verify init returns ''."""
        port = ovs_interface.PortObject('br-phy0')
        self.assertEqual(port.bridge_name, 'br-phy0')
        self.assertEqual(port.name, '')

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_raise_alarm(self, mock_ma):
        """Verify raise_alarm port._raise_alarm() is True."""
        port = ovs_interface.PortObject('br-phy0')
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertTrue(port._raise_alarm(fm_constants.FM_ALARM_SEVERITY_CRITICAL))

    def test_raise_alarm_clear_severity(self):
        """Verify raise_alarm_clear_severity port._raise_alarm() is."""
        port = ovs_interface.PortObject('br-phy0')
        self.assertTrue(port._raise_alarm(fm_constants.FM_ALARM_SEVERITY_CLEAR))

    def test_raise_alarm_same_severity(self):
        """Verify raise_alarm_same_severity port._raise_alarm() is."""
        port = ovs_interface.PortObject('br-phy0')
        port.severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL
        self.assertTrue(port._raise_alarm(fm_constants.FM_ALARM_SEVERITY_CRITICAL))

    @patch.object(ovs_interface, 'manage_alarm', return_value=False)
    def test_raise_alarm_fail(self, mock_ma):
        """Verify raise_alarm_fail port._raise_alarm() is False on."""
        port = ovs_interface.PortObject('br-phy0')
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertFalse(port._raise_alarm(fm_constants.FM_ALARM_SEVERITY_CRITICAL))

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_raise_alarm_with_bond_name(self, mock_ma):
        """Verify raise_alarm_with_bond port._raise_alarm() is True."""
        port = ovs_interface.PortObject('br-phy0')
        port.name = 'bond0'
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertTrue(port._raise_alarm(fm_constants.FM_ALARM_SEVERITY_MAJOR))

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_clear_alarm(self, mock_ma):
        """Verify clear_alarm port._clear_alarm() is True."""
        port = ovs_interface.PortObject('br-phy0')
        port.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertTrue(port._clear_alarm())

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_clear_alarm_with_name(self, mock_ma):
        """Verify clear_alarm_with_name port._clear_alarm() is True."""
        port = ovs_interface.PortObject('br-phy0')
        port.name = 'bond0'
        port.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertTrue(port._clear_alarm())

    @patch.object(ovs_interface, 'manage_alarm', return_value=False)
    def test_clear_alarm_fail(self, mock_ma):
        """Verify clear_alarm_fail port._clear_alarm() is False on."""
        port = ovs_interface.PortObject('br-phy0')
        port.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.assertFalse(port._clear_alarm())

    def test_clear_alarm_already_clear(self):
        """Verify clear_alarm_already_clear port._clear_alarm() is."""
        port = ovs_interface.PortObject('br-phy0')
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        self.assertTrue(port._clear_alarm())

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_port_alarm_single_up(self, mock_ma):
        """Verify manage_port_alarm single port up."""
        port = ovs_interface.PortObject('br-phy0')
        iface = ovs_interface.InterfaceObject('eth0')
        iface.state = ovs_interface.LINK_UP
        port.interfaces = [iface]
        port.severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL
        port.manage_port_alarm()
        self.assertEqual(port.severity, fm_constants.FM_ALARM_SEVERITY_CLEAR)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_port_alarm_single_down(self, mock_ma):
        """Verify manage_port_alarm single port down."""
        port = ovs_interface.PortObject('br-phy0')
        iface = ovs_interface.InterfaceObject('eth0')
        iface.state = ovs_interface.LINK_DOWN
        port.interfaces = [iface]
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        port.manage_port_alarm()
        self.assertEqual(port.severity, fm_constants.FM_ALARM_SEVERITY_CRITICAL)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_port_alarm_single_unknown(self, mock_ma):
        """Verify manage_port_alarm single port unknown."""
        port = ovs_interface.PortObject('br-phy0')
        iface = ovs_interface.InterfaceObject('eth0')
        iface.state = ovs_interface.UNKNOWN_STATE
        port.interfaces = [iface]
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        port.manage_port_alarm()
        self.assertEqual(port.severity, fm_constants.FM_ALARM_SEVERITY_CRITICAL)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_port_alarm_bond_all_up(self, mock_ma):
        """Verify manage_port_alarm bond all up."""
        port = ovs_interface.PortObject('br-phy0')
        iface_one = ovs_interface.InterfaceObject('eth0')
        iface_two = ovs_interface.InterfaceObject('eth1')
        iface_one.state = ovs_interface.LINK_UP
        iface_two.state = ovs_interface.LINK_UP
        port.interfaces = [iface_one, iface_two]
        port.severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        port.manage_port_alarm()
        self.assertEqual(port.severity, fm_constants.FM_ALARM_SEVERITY_CLEAR)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_port_alarm_bond_all_down(self, mock_ma):
        """Verify manage_port_alarm bond all down."""
        port = ovs_interface.PortObject('br-phy0')
        iface_one = ovs_interface.InterfaceObject('eth0')
        iface_two = ovs_interface.InterfaceObject('eth1')
        iface_one.state = ovs_interface.LINK_DOWN
        iface_two.state = ovs_interface.LINK_DOWN
        port.interfaces = [iface_one, iface_two]
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        port.manage_port_alarm()
        self.assertEqual(port.severity, fm_constants.FM_ALARM_SEVERITY_CRITICAL)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_port_alarm_bond_partial(self, mock_ma):
        """Verify manage_port_alarm bond partial."""
        port = ovs_interface.PortObject('br-phy0')
        iface_one = ovs_interface.InterfaceObject('eth0')
        iface_two = ovs_interface.InterfaceObject('eth1')
        iface_one.state = ovs_interface.LINK_UP
        iface_two.state = ovs_interface.LINK_DOWN
        port.interfaces = [iface_one, iface_two]
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        port.manage_port_alarm()
        self.assertEqual(port.severity, fm_constants.FM_ALARM_SEVERITY_MAJOR)

    def test_manage_port_alarm_no_interfaces(self):
        """Verify manage_port_alarm_no returns 0."""
        port = ovs_interface.PortObject('br-phy0')
        port.interfaces = []
        self.assertEqual(port.manage_port_alarm(), 0)

    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    def test_manage_port_alarm_bond_unknown(self, mock_ma):
        """Verify manage_port_alarm bond unknown."""
        port = ovs_interface.PortObject('br-phy0')
        iface_one = ovs_interface.InterfaceObject('eth0')
        iface_two = ovs_interface.InterfaceObject('eth1')
        iface_one.state = ovs_interface.UNKNOWN_STATE
        iface_two.state = ovs_interface.UNKNOWN_STATE
        port.interfaces = [iface_one, iface_two]
        port.severity = fm_constants.FM_ALARM_SEVERITY_CLEAR
        port.manage_port_alarm()
        self.assertEqual(port.severity, fm_constants.FM_ALARM_SEVERITY_CRITICAL)


class TestOvsThisHostsAlarm(unittest.TestCase):
    def test_interface_match(self):
        """Verify interface_match ovs_interface.this_hosts_alarm() is."""
        self.assertTrue(ovs_interface.this_hosts_alarm(
            'controller-0', 'host=controller-0.interface=eth0'))

    def test_port_match(self):
        """Verify port_match ovs_interface.this_hosts_alarm() is."""
        self.assertTrue(ovs_interface.this_hosts_alarm(
            'controller-0', 'host=controller-0.port=br-phy0'))

    def test_port_bond_match(self):
        """Verify port_bond ovs_interface.this_hosts_alarm() is True."""
        self.assertTrue(ovs_interface.this_hosts_alarm(
            'controller-0', 'host=controller-0.port=br-phy0:bond0'))

    def test_no_match(self):
        """Verify no_match ovs_interface.this_hosts_alarm() is False."""
        self.assertFalse(ovs_interface.this_hosts_alarm(
            'controller-0', 'host=controller-1.port=br-phy0'))

    def test_empty_hostname(self):
        """Verify empty_hostname ovs_interface.this_hosts_alarm() is."""
        self.assertFalse(ovs_interface.this_hosts_alarm('', 'host=c.port=e'))

    def test_none_eid(self):
        """Verify none_eid ovs_interface.this_hosts_alarm() is False."""
        self.assertFalse(ovs_interface.this_hosts_alarm('controller-0', None))

    def test_none_hostname(self):
        """Verify none_hostname ovs_interface.this_hosts_alarm() is."""
        self.assertFalse(ovs_interface.this_hosts_alarm(None, 'eid'))

    def test_bad_eid(self):
        """Verify bad_eid ovs_interface.this_hosts_alarm() is False."""
        self.assertFalse(ovs_interface.this_hosts_alarm('controller-0', 'bad'))


class TestOvsClearAlarms(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        ovs_interface.obj.hostname = 'controller-0'

    def test_no_alarms(self):
        """Verify no_alarms ovs_interface.clear_alarms() is True."""
        ovs_interface.api = MagicMock()
        ovs_interface.api.get_faults_by_id.return_value = None
        self.assertTrue(ovs_interface.clear_alarms(['300.002']))

    def test_clear_matching(self):
        """Verify clear_matching ovs_interface.clear_alarms() is."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.interface=eth0'
        alarm.severity = 'major'
        ovs_interface.api = MagicMock()
        ovs_interface.api.get_faults_by_id.return_value = [alarm]
        ovs_interface.api.clear_fault.return_value = True
        self.assertTrue(ovs_interface.clear_alarms([ovs_interface.OVS_IFACE_ALARMID]))

    def test_clear_fault_false(self):
        """Verify clear_fault_false ovs_interface.clear_alarms() is."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.interface=eth0'
        alarm.severity = 'major'
        ovs_interface.api = MagicMock()
        ovs_interface.api.get_faults_by_id.return_value = [alarm]
        ovs_interface.api.clear_fault.return_value = False
        self.assertTrue(ovs_interface.clear_alarms([ovs_interface.OVS_IFACE_ALARMID]))

    def test_get_faults_exception(self):
        """Verify get_faults_exception ovs_interface.clear_alarms()."""
        ovs_interface.api = MagicMock()
        ovs_interface.api.get_faults_by_id.side_effect = Exception('fail')
        self.assertFalse(ovs_interface.clear_alarms(['300.002']))

    def test_clear_fault_exception(self):
        """Verify clear_fault_exception ovs_interface.clear_alarms()."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.interface=eth0'
        alarm.severity = 'major'
        ovs_interface.api = MagicMock()
        ovs_interface.api.get_faults_by_id.return_value = [alarm]
        ovs_interface.api.clear_fault.side_effect = Exception('fail')
        self.assertFalse(ovs_interface.clear_alarms([ovs_interface.OVS_IFACE_ALARMID]))

    def test_skip_other_host(self):
        """Verify skip_other ovs_interface.clear_alarms() is True."""
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-1.interface=eth0'
        ovs_interface.api = MagicMock()
        ovs_interface.api.get_faults_by_id.return_value = [alarm]
        self.assertTrue(ovs_interface.clear_alarms([ovs_interface.OVS_IFACE_ALARMID]))


class TestOvsManageAlarm(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        ovs_interface.obj.hostname = 'controller-0'
        ovs_interface.api = MagicMock()

    def test_clear_action(self):
        """Verify clear_action returns True."""
        ovs_interface.api.clear_fault.return_value = True
        timestamp = datetime.datetime.now()
        result = ovs_interface.manage_alarm('eth0', 'interface', 'clear',
                                            fm_constants.FM_ALARM_SEVERITY_CLEAR,
                                            '300.002', timestamp)
        self.assertTrue(result)

    def test_clear_already_cleared(self):
        """Verify clear_already_cleared returns True."""
        ovs_interface.api.clear_fault.return_value = False
        timestamp = datetime.datetime.now()
        result = ovs_interface.manage_alarm('eth0', 'interface', 'clear',
                                            fm_constants.FM_ALARM_SEVERITY_CLEAR,
                                            '300.002', timestamp)
        self.assertTrue(result)

    def test_clear_exception(self):
        """Verify clear_exception returns False on exception."""
        ovs_interface.api.clear_fault.side_effect = Exception('fail')
        timestamp = datetime.datetime.now()
        result = ovs_interface.manage_alarm('eth0', 'interface', 'clear',
                                            fm_constants.FM_ALARM_SEVERITY_CLEAR,
                                            '300.002', timestamp)
        self.assertFalse(result)

    def test_raise_interface(self):
        """Verify raise_interface returns True."""
        ovs_interface.api.set_fault.return_value = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        timestamp = datetime.datetime.now()
        result = ovs_interface.manage_alarm('eth0', 'interface', 'raise',
                                            fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                            '300.002', timestamp)
        self.assertTrue(result)

    def test_raise_port_critical(self):
        """Verify raise_port_critical returns True."""
        ovs_interface.api.set_fault.return_value = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        timestamp = datetime.datetime.now()
        result = ovs_interface.manage_alarm('br-phy0', 'port', 'raise',
                                            fm_constants.FM_ALARM_SEVERITY_CRITICAL,
                                            '300.001', timestamp)
        self.assertTrue(result)

    def test_raise_port_major(self):
        """Verify raise_port_major returns True."""
        ovs_interface.api.set_fault.return_value = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        timestamp = datetime.datetime.now()
        result = ovs_interface.manage_alarm('br-phy0', 'port', 'raise',
                                            fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                            '300.001', timestamp)
        self.assertTrue(result)

    def test_set_fault_exception(self):
        """Verify set_fault_exception returns False on exception."""
        ovs_interface.api.set_fault.side_effect = Exception('fail')
        timestamp = datetime.datetime.now()
        result = ovs_interface.manage_alarm('eth0', 'interface', 'raise',
                                            fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                            '300.002', timestamp)
        self.assertFalse(result)


class TestOvsParsers(unittest.TestCase):
    def test_parse_ovs_vsctl_show(self):
        """Verify parse_ovs_vsctl_show extracts bridges."""
        buf = '''
  Bridge "br-phy0"
    Port "eth0"
        Interface "eth0"
            type: dpdk
            options: {dpdk-devargs="0000:18:00.0"}
    Port "eth1"
        Interface "eth1"
  Bridge "br-phy1"
    Port "eth2"
        Interface "eth2"
            type: dpdk
'''
        result = ovs_interface.parse_ovs_vsctl_show(buf, 'br-phy0')
        self.assertIn('eth0', result)
        self.assertNotIn('eth2', result)

    def test_parse_ovs_vsctl_list_ports(self):
        """Verify parse_ovs_vsctl_list returns []."""
        buf = "eth0\neth1\n"
        result = ovs_interface.parse_ovs_vsctl_list_ports(buf)
        self.assertEqual(result, ['eth0', 'eth1'])

    def test_parse_ovs_vsctl_list_ifaces(self):
        """Verify parse_ovs_vsctl_list returns []."""
        buf = "eth0\neth1\n"
        result = ovs_interface.parse_ovs_vsctl_list_ifaces(buf)
        self.assertEqual(result, ['eth0', 'eth1'])

    def test_parse_ovs_ofctl_dump_ports_desc(self):
        """Verify parse_ovs_ofctl_dump extracts port desc."""
        buf = """OFPST_PORT_DESC reply (xid=0x2):
 2(eth0): addr:3c:fd:fe:da:e8:84
     config:     0
     state:      0
     current:    AUTO_NEG
 3(eth1): addr:3c:fd:fe:da:e8:85
     config:     0
     state:      LINK_DOWN
     current:    AUTO_NEG
"""
        port = ovs_interface.PortObject('br-phy0')
        iface_one = ovs_interface.InterfaceObject('eth0')
        iface_two = ovs_interface.InterfaceObject('eth1')
        port.interfaces = [iface_one, iface_two]
        result = ovs_interface.parse_ovs_ofctl_dump_ports_desc(buf, port)
        self.assertEqual(result['eth0'], ovs_interface.LINK_UP)
        self.assertEqual(result['eth1'], ovs_interface.LINK_DOWN)

    def test_parse_ovs_appctl_bond_list(self):
        """Verify parse_ovs_appctl_bond returns []."""
        buf = "bond\ttype\trecircID\tslaves\nbond0\tactive-backup\t0\tenp134s0f1, enp134s0f0\n"
        result = ovs_interface.parse_ovs_appctl_bond_list(buf)
        self.assertIn('bond0', result)
        self.assertEqual(sorted(result['bond0']), ['enp134s0f0', 'enp134s0f1'])

    def test_parse_ovs_appctl_bond_show(self):
        """Verify parse_ovs_appctl_bond returns LINK_UP."""
        buf = """---- bond0 ----
bond_mode: active-backup
slave enp134s0f0: disabled
  may_enable: false
slave enp134s0f1: enabled
  may_enable: true
"""
        result = ovs_interface.parse_ovs_appctl_bond_show(buf)
        self.assertEqual(result['enp134s0f0'], ovs_interface.LINK_DOWN)
        self.assertEqual(result['enp134s0f1'], ovs_interface.LINK_UP)

    def test_parse_ovs_appctl_bond_show_unknown(self):
        """Verify parse_ovs_appctl_bond with unknown bond."""
        buf = """---- bond0 ----
slave eth0: something_else
"""
        result = ovs_interface.parse_ovs_appctl_bond_show(buf)
        self.assertEqual(result['eth0'], ovs_interface.UNKNOWN_STATE)


@unittest.skip("combined-run")
class TestOvsPhysicalInterfaces(unittest.TestCase):
    @patch('os.path.exists', return_value=True)
    @patch('os.listdir')
    def test_get_physical_interfaces(self, mock_listdir, mock_exists):
        """Verify get_physical_interfaces lists NICs."""
        mock_listdir.side_effect = [['eth0', 'eth1', 'lo'], ['lo']]
        result = ovs_interface.get_physical_interfaces()
        self.assertIn('eth0', result)
        self.assertNotIn('lo', result)

    def test_is_interface_in_port_true(self):
        """Verify is_interface_in_port True for member."""
        port = ovs_interface.PortObject('br-phy0')
        port.interfaces = [ovs_interface.InterfaceObject('eth0')]
        self.assertTrue(ovs_interface.is_interface_in_port('eth0', port))

    def test_is_interface_in_port_false(self):
        """Verify is_interface_in_port False for non-member."""
        port = ovs_interface.PortObject('br-phy0')
        port.interfaces = [ovs_interface.InterfaceObject('eth0')]
        self.assertFalse(ovs_interface.is_interface_in_port('eth1', port))

    @patch.object(ovs_interface, 'get_physical_interfaces', return_value=['eth0'])
    def test_is_physical_interface_true(self, mock_gpi):
        """Verify is_physical_interface True for NIC."""
        self.assertTrue(ovs_interface.is_physical_interface('eth0', 'br-phy0'))

    @patch.object(ovs_interface, 'get_physical_interfaces', return_value=[])
    @patch('oslo_concurrency.processutils.execute',
           return_value=('Bridge "br-phy0"\n  Port "eth1"\n    Interface "eth1"\n      type: dpdk\n', ''))
    def test_is_physical_interface_dpdk(self, mock_exec, mock_gpi):
        """Verify is_physical_interface True for DPDK port."""
        self.assertTrue(ovs_interface.is_physical_interface('eth1', 'br-phy0'))

    @patch.object(ovs_interface, 'get_physical_interfaces', return_value=[])
    @patch('oslo_concurrency.processutils.execute',
           return_value=('Bridge "br-phy0"\n  Port "eth2"\n    Interface "eth2"\n', ''))
    def test_is_physical_interface_false(self, mock_exec, mock_gpi):
        """Verify is_physical_interface False for veth."""
        self.assertFalse(ovs_interface.is_physical_interface('eth1', 'br-phy0'))

    @patch.object(ovs_interface, 'get_physical_interfaces', return_value=[])
    @patch('oslo_concurrency.processutils.execute', return_value=('', 'error'))
    def test_is_physical_interface_error(self, mock_exec, mock_gpi):
        """Verify is_physical_interface_error raises RuntimeError on."""
        with self.assertRaises(RuntimeError):
            ovs_interface.is_physical_interface('eth1', 'br-phy0')

    @patch.object(ovs_interface, 'get_physical_interfaces', return_value=[])
    @patch('oslo_concurrency.processutils.execute', return_value=('', ''))
    def test_is_physical_interface_no_res(self, mock_exec, mock_gpi):
        """Verify is_physical_interface False with no result."""
        self.assertFalse(ovs_interface.is_physical_interface('eth1', 'br-phy0'))

    def test_compare_interfaces_same(self):
        """Verify compare_interfaces same returns True."""
        self.assertTrue(ovs_interface.compare_interfaces(['eth0', 'eth1'], ['eth1', 'eth0']))

    def test_compare_interfaces_diff(self):
        """Verify compare_interfaces diff returns False."""
        self.assertFalse(ovs_interface.compare_interfaces(['eth0'], ['eth1']))


@unittest.skip("combined-run")
class TestOvsConfigInitFunc(unittest.TestCase):

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', mock_open(read_data='43\n'))
    @patch.object(pc.PluginObject, 'gethostname', return_value='worker-0')
    def test_init_func_worker(self, mock_gh, mock_exists):
        """Verify init_func_worker ovs_interface.obj.init_complete is."""
        tsc_mock.subfunctions = 'worker'
        ovs_interface.obj = pc.PluginObject(ovs_interface.PLUGIN, ovs_interface.PLUGIN_HTTP_URL_PREFIX)
        ovs_interface.obj._config_complete = True
        ovs_interface.obj.config_done = True
        ovs_interface.init_func()
        self.assertTrue(ovs_interface.obj.init_complete)

    @patch('os.path.exists', return_value=False)
    def test_init_func_no_pid_file(self, mock_exists):
        """Verify init_func_no_pid ovs_interface.obj.init_complete is."""
        tsc_mock.subfunctions = 'worker'
        ovs_interface.obj = pc.PluginObject(ovs_interface.PLUGIN, ovs_interface.PLUGIN_HTTP_URL_PREFIX)
        ovs_interface.obj._config_complete = True
        ovs_interface.obj.config_done = True
        ovs_interface.obj.error_logged = False
        ovs_interface.init_func()
        self.assertFalse(ovs_interface.obj.init_complete)


@unittest.skip("combined-run")
class TestOvsReadFunc(unittest.TestCase):
    def test_read_func_not_init(self):
        """Verify read_func_not_init returns 0 when not initialized."""
        ovs_interface.obj = pc.PluginObject(ovs_interface.PLUGIN, ovs_interface.PLUGIN_HTTP_URL_PREFIX)
        ovs_interface.obj.init_complete = False
        ovs_interface.obj._config_complete = False
        ovs_interface.obj.config_done = False
        tsc_mock.subfunctions = 'controller'
        self.assertEqual(ovs_interface.read_func(), 0)

    @patch.object(ovs_interface, 'clear_alarms', return_value=False)
    def test_read_func_clear_alarms_fail(self, mock_ca):
        """Verify read_func_clear_alarms returns 0 on failure."""
        ovs_interface.obj = pc.PluginObject(ovs_interface.PLUGIN, ovs_interface.PLUGIN_HTTP_URL_PREFIX)
        ovs_interface.obj.init_complete = True
        ovs_interface.obj._node_ready = True
        ovs_interface.obj.phase = 0
        ovs_interface.read_func()
        self.assertEqual(ovs_interface.obj.phase, 0)


class IterDict(dict):
    """Dict subclass with iteritems for Py2 compat."""

    def iteritems(self):
        """Test iteritems."""
        return iter(self.items())


@unittest.skip("combined-run")
class TestOvsReadFuncExtended(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        ovs_interface.obj = pc.PluginObject(ovs_interface.PLUGIN, ovs_interface.PLUGIN_HTTP_URL_PREFIX)
        ovs_interface.obj.init_complete = True
        ovs_interface.obj._node_ready = True
        ovs_interface.obj.hostname = 'worker-0'
        ovs_interface.obj.phase = ovs_interface.RUN_PHASE__ALARMS_CLEARED
        ovs_interface.obj.audits = 0
        ovs_interface.ports.clear()
        ovs_interface.OVS_VSWITCHD_SOCKET = '/var/run/openvswitch/ovs-vswitchd.43.ctl'

    @patch('oslo_concurrency.processutils.execute')
    @patch.object(ovs_interface, 'get_physical_interfaces', return_value=['eth0'])
    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    @patch.object(ovs_interface, 'parse_ovs_appctl_bond_list', return_value=IterDict())
    def test_read_func_full_single_iface(self, mock_bl, mock_ma, mock_gpi, mock_exec):
        """Verify read_func_full_single returns 1."""
        def exec_side_effect(cmd, shell=True):
            if 'list-br' in cmd:
                return ('br-phy0\n', '')
            elif 'list-ifaces' in cmd:
                return ('eth0\n', '')
            elif 'dump-ports-desc' in cmd:
                return ('OFPST_PORT_DESC reply\n 2(eth0): addr:aa\n     config:     0\n     state:      0\n', '')  # noqa: E501
            elif 'bond/list' in cmd:
                return ('bond\ttype\trecircID\tslaves\n', '')
            elif 'bond/show' in cmd:
                return ('', '')
            return ('', '')
        mock_exec.side_effect = exec_side_effect
        val_mock = MagicMock()
        collectd.Values = MagicMock(return_value=val_mock)
        ovs_interface.read_func()
        self.assertEqual(ovs_interface.obj.audits, 1)

    @patch('oslo_concurrency.processutils.execute')
    @patch.object(ovs_interface, 'get_physical_interfaces', return_value=['eth0', 'eth1'])
    @patch.object(ovs_interface, 'manage_alarm', return_value=True)
    @patch.object(ovs_interface, 'parse_ovs_appctl_bond_list',
                  return_value=IterDict({'bond0': ['eth0', 'eth1']}))
    def test_read_func_bond(self, mock_bl, mock_ma, mock_gpi, mock_exec):
        """Verify read_func_bond returns 1."""
        def exec_side_effect(cmd, shell=True):
            if 'list-br' in cmd:
                return ('br-phy0\n', '')
            elif 'list-ifaces' in cmd:
                return ('eth0\neth1\n', '')
            elif 'dump-ports-desc' in cmd:
                return ('OFPST_PORT_DESC reply\n 2(eth0): addr:aa\n     config:     0\n     state:      0\n 3(eth1): addr:bb\n     config:     0\n     state:      0\n', '')  # noqa: E501
            elif 'bond/list' in cmd:
                return ('bond\ttype\trecircID\tslaves\nbond0\tactive-backup\t0\teth0, eth1\n', '')
            elif 'bond/show' in cmd:
                return ('---- bond0 ----\nslave eth0: enabled\nslave eth1: disabled\n', '')
            return ('', '')
        mock_exec.side_effect = exec_side_effect
        val_mock = MagicMock()
        collectd.Values = MagicMock(return_value=val_mock)
        ovs_interface.read_func()
        self.assertEqual(ovs_interface.obj.audits, 1)
