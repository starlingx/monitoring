#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import logging
import multiprocessing
import os
import signal
import sys
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '..',
    'vm-topology', 'vm-topology'))

sys.modules.setdefault('libvirt', MagicMock())

multiprocessing.Manager = MagicMock(
    return_value=MagicMock(dict=MagicMock(return_value={})))
multiprocessing.Pool = MagicMock()
from vm_topology.exec import vm_topology as vt

from oslo_config import cfg
from prettytable import PrettyTable


def _make_server(**overrides):
    server = MagicMock()
    defaults = dict(
        id='sid1', name='srv1', instance_name='instance-0001',
        host='compute-0', nodename='compute-0',
        vm_state='active', task_state=None, power_state=1,
        flavor={'id': 'f1'}, image={'id': 'img1'},
        tenant_id='t1', server_group='grp1 (sg1)',
        topology='node:0', volumes_attached=[],
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(server, key, value)
    server._info = defaults
    server.__dict__.update(defaults)
    return server


def _make_flavor(**overrides):
    flavor = MagicMock()
    defaults = dict(
        id='f1', name='m1.small', vcpus=2, ram=2048, disk=20,
        ephemeral=0, swap='', rxtx_factor=1.0, is_public=True,
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(flavor, key, value)
    flavor._info = defaults
    flavor.__dict__.update(defaults)
    flavor.get_keys.return_value = {'hw:cpu_policy': 'dedicated'}
    return flavor


def _make_image(**overrides):
    image = MagicMock()
    defaults = dict(
        id='img1', name='cirros', min_disk=1, min_ram=64,
        size=13287936, status='active', properties={},
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(image, key, value)
    image._info = defaults
    image.__dict__.update(defaults)
    return image


def _make_hypervisor(hostname='compute-0', **overrides):
    hypervisor = MagicMock()
    defaults = dict(
        hypervisor_hostname=hostname, status='enabled',
        running_vms=1,
        cpu_info={'model': 'Xeon', 'arch': 'x86_64',
                  'vendor': 'Intel',
                  'topology': {'sockets': 1, 'cores': 4, 'threads': 2}},
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(hypervisor, key, value)
    hypervisor._info = defaults
    hypervisor.__dict__.update(defaults)
    return hypervisor


def _make_aggregate(**overrides):
    aggregate = MagicMock()
    defaults = dict(
        id=1, name='agg1', availability_zone='nova',
        hosts=['compute-0'], metadata={},
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(aggregate, key, value)
    aggregate._info = defaults
    aggregate.__dict__.update(defaults)
    return aggregate


def _make_migration(**overrides):
    migration = MagicMock()
    defaults = dict(
        id=1, instance_uuid='sid1', status='migrating',
        source_node='n1', dest_node='n2',
        source_compute='c1', dest_compute='c2',
        new_instance_type_id=1, old_instance_type_id=2,
        created_at='2024-01-01',
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(migration, key, value)
    return migration


def _make_server_group(**overrides):
    server_grp = MagicMock()
    defaults = dict(
        id='sg1', name='mygroup', project_id='t1',
        policies=['anti-affinity'], metadata={}, members=['sid1'],
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(server_grp, key, value)
    server_grp._info = defaults
    server_grp.__dict__.update(defaults)
    return server_grp


def _make_tenant(**overrides):
    tenant = MagicMock()
    defaults = dict(id='t1', name='admin')
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(tenant, key, value)
    return tenant


def _all_show_false():
    return {key: False for key in [
        'brief', 'all', 'computes', 'servers', 'server_groups',
        'migrations', 'flavors', 'images', 'volumes', 'libvirt',
        'aggregates', 'topology', 'topology-long', 'show']}


def _all_debug_false():
    flags_dict = {}
    vt.define_debug_flags(flags_dict)
    return flags_dict


class TestAtoi(unittest.TestCase):
    def test_digit(self):
        """Verify atoi converts digit string to int."""
        self.assertEqual(vt.atoi('42'), 42)

    def test_non_digit(self):
        """Verify non_digit returns 'abc'."""
        self.assertEqual(vt.atoi('abc'), 'abc')

    def test_empty(self):
        """Verify empty returns '' with empty input."""
        self.assertEqual(vt.atoi(''), '')

    def test_mixed(self):
        """Verify mixed returns '12abc'."""
        self.assertEqual(vt.atoi('12abc'), '12abc')


class TestNaturalKeys(unittest.TestCase):
    def test_sort_order(self):
        """Verify sort_order returns []."""
        items = ['node10', 'node2', 'node1']
        items.sort(key=vt.natural_keys)
        self.assertEqual(items, ['node1', 'node2', 'node10'])

    def test_no_digits(self):
        """Verify no_digits returns []."""
        self.assertEqual(vt.natural_keys('abc'), ['abc'])

    def test_only_digits(self):
        """Verify only_digits returns []."""
        self.assertEqual(vt.natural_keys('123'), ['', 123, ''])

    def test_mixed(self):
        """Verify mixed returns []."""
        result = vt.natural_keys('a1b2')
        self.assertEqual(result, ['a', 1, 'b', 2, ''])


class TestHelpTextEpilog(unittest.TestCase):
    def test_returns_string(self):
        """Verify help_text_epilog returns a string."""
        result = vt.help_text_epilog()
        self.assertIsInstance(result, str)

    def test_contains_sections(self):
        """Verify contains_sections section in result."""
        result = vt.help_text_epilog()
        for section in ['COMPUTE HOSTS', 'SERVERS', 'MIGRATIONS',
                        'FLAVORS', 'IMAGES', 'SERVER GROUPS']:
            self.assertIn(section, result)


class TestRangeToList(unittest.TestCase):
    def test_single(self):
        """Verify single returns []."""
        self.assertEqual(vt.range_to_list('5'), [5])

    def test_range(self):
        """Verify range returns []."""
        self.assertEqual(vt.range_to_list('1-3'), [1, 2, 3])

    def test_mixed(self):
        """Verify mixed returns []."""
        self.assertEqual(vt.range_to_list('1-3,8-9,15'), [1, 2, 3, 8, 9, 15])

    def test_none(self):
        """Verify none returns [] with None input."""
        self.assertEqual(vt.range_to_list(None), [])

    def test_empty(self):
        """Verify empty returns [] with empty input."""
        self.assertEqual(vt.range_to_list(''), [])


class TestListToRange(unittest.TestCase):
    def test_contiguous(self):
        """Verify contiguous returns '1-3'."""
        self.assertEqual(vt.list_to_range([1, 2, 3]), '1-3')

    def test_mixed(self):
        """Verify mixed returns '1-3,8-9,15'."""
        self.assertEqual(vt.list_to_range([1, 2, 3, 8, 9, 15]), '1-3,8-9,15')

    def test_single(self):
        """Verify single returns '5'."""
        self.assertEqual(vt.list_to_range([5]), '5')

    def test_none(self):
        """Verify none returns '' with None input."""
        self.assertEqual(vt.list_to_range(None), '')

    def test_empty(self):
        """Verify empty returns '' with empty input."""
        self.assertEqual(vt.list_to_range([]), '')

    def test_non_contiguous(self):
        """Verify non_contiguous returns '1,3,5'."""
        self.assertEqual(vt.list_to_range([1, 3, 5]), '1,3,5')


class TestStringToCpulist(unittest.TestCase):
    def test_single(self):
        """Verify single returns []."""
        self.assertEqual(vt.string_to_cpulist('5'), [5])

    def test_range(self):
        """Verify range returns []."""
        self.assertEqual(vt.string_to_cpulist('1-3'), [1, 2, 3])

    def test_mixed(self):
        """Verify mixed returns []."""
        self.assertEqual(vt.string_to_cpulist('1,2,6-7'), [1, 2, 6, 7])

    def test_empty(self):
        """Verify empty returns [] with empty input."""
        self.assertEqual(vt.string_to_cpulist(''), [])

    def test_whitespace(self):
        """Verify whitespace returns []."""
        self.assertEqual(vt.string_to_cpulist('  1,2  '), [1, 2])

    def test_reverse_range_ignored(self):
        """Verify reverse_range returns []."""
        self.assertEqual(vt.string_to_cpulist('5-3'), [])

    def test_single_and_range(self):
        """Verify single_and returns []."""
        self.assertEqual(vt.string_to_cpulist('0,4-6'), [0, 4, 5, 6])


class TestMaskToCpulist(unittest.TestCase):
    def test_single_bit(self):
        """Verify single_bit returns []."""
        self.assertEqual(vt._mask_to_cpulist(0x1), [0])

    def test_multiple_bits(self):
        """Verify multiple_bits returns []."""
        self.assertEqual(vt._mask_to_cpulist(0x5), [0, 2])

    def test_zero(self):
        """Verify zero returns []."""
        self.assertEqual(vt._mask_to_cpulist(0), [])

    def test_none(self):
        """Verify none returns [] with None input."""
        self.assertEqual(vt._mask_to_cpulist(None), [])

    def test_negative(self):
        """Verify negative returns []."""
        self.assertEqual(vt._mask_to_cpulist(-1), [])

    def test_high_bit(self):
        """Verify high_bit 64 in vt._mask_to_cpulist()."""
        self.assertIn(64, vt._mask_to_cpulist(1 << 64))

    def test_contiguous(self):
        """Verify contiguous returns []."""
        self.assertEqual(vt._mask_to_cpulist(0xF), [0, 1, 2, 3])


class TestTranslateVirDomainState(unittest.TestCase):
    def test_all_states(self):
        """Verify translate_vir_domain_state maps all states."""
        expected = {
            0: 'NOSTATE', 1: 'Running', 2: 'Blocked', 3: 'Paused',
            4: 'Shutdown', 5: 'Shutoff', 6: 'Crashed', 7: 'pmSuspended',
            8: 'Last',
        }
        for code, name in expected.items():
            self.assertEqual(vt._translate_virDomainState(code), name)


class TestTranslateVirVcpuState(unittest.TestCase):
    def test_all_states(self):
        """Verify translate_vir_vcpu_state maps all states."""
        expected = {0: 'Offline', 1: 'Running', 2: 'Blocked', 3: 'Last'}
        for code, name in expected.items():
            self.assertEqual(vt._translate_virVcpuState(code), name)


class TestTranslateExtendedStates(unittest.TestCase):
    def test_running(self):
        """Verify running returns 'Running'."""
        item = MagicMock()
        item.power_state = 1
        item.task_state = None
        vt._translate_extended_states({'s1': item})
        self.assertEqual(item.power_state, 'Running')

    def test_no_power_state(self):
        """Verify no_power returns 'N/A'."""
        item = MagicMock(spec=[])
        vt._translate_extended_states({'s1': item})
        self.assertEqual(item.power_state, 'N/A')
        self.assertEqual(item.task_state, 'N/A')

    def test_nostate(self):
        """Verify nostate returns 'NOSTATE'."""
        item = MagicMock()
        item.power_state = 0
        item.task_state = 'migrating'
        vt._translate_extended_states({'s1': item})
        self.assertEqual(item.power_state, 'NOSTATE')

    def test_multiple_items(self):
        """Verify multiple_items returns 'Paused'."""
        item_one = MagicMock()
        item_one.power_state = 1
        item_one.task_state = None
        item_two = MagicMock()
        item_two.power_state = 3
        item_two.task_state = None
        vt._translate_extended_states({'a': item_one, 'b': item_two})
        self.assertEqual(item_one.power_state, 'Running')
        self.assertEqual(item_two.power_state, 'Paused')


class _FakeItem:
    """Simple object that behaves like a nova resource with _info."""

    def __init__(self, **kwargs):
        """Test   init  ."""
        self._info = dict(kwargs)
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestTranslateKeys(unittest.TestCase):
    def test_basic_translate(self):
        """Verify basic_translate returns 'h1'."""
        item = _FakeItem(**{'OS-EXT-SRV-ATTR:host': 'h1'})
        convert = [('OS-EXT-SRV-ATTR:host', 'host')]
        vt._translate_keys({'s1': item}, convert)
        self.assertEqual(item.host, 'h1')

    def test_skip_existing_key(self):
        """Verify skip_existing returns 'existing'."""
        item = _FakeItem(from_key='v1', to_key='existing')
        convert = [('from_key', 'to_key')]
        vt._translate_keys({'s1': item}, convert)
        self.assertEqual(item.to_key, 'existing')


class TestConfigureLogging(unittest.TestCase):
    def test_sets_level(self):
        """Verify configure_logging sets WARNING level."""
        lgr = logging.getLogger('test_vm_topo_cfg')
        vt.configure_logging(lgr, level=logging.WARNING)
        self.assertEqual(lgr.level, logging.WARNING)

    def test_default_debug(self):
        """Verify configure_logging defaults to DEBUG."""
        lgr = logging.getLogger('test_vm_topo_dbg')
        vt.configure_logging(lgr)
        self.assertEqual(lgr.level, logging.DEBUG)

    def test_adds_handler(self):
        """Verify adds_handler ... is True."""
        lgr = logging.getLogger('test_vm_topo_hdl')
        lgr.handlers.clear()
        vt.configure_logging(lgr, level=logging.INFO)
        self.assertTrue(len(lgr.handlers) > 0)


class TestSuppressStdoutStderr(unittest.TestCase):

    def test_init_attributes(self):
        """Verify SuppressStdoutStderr stores null fds."""
        server = vt.suppress_stdout_stderr()
        self.assertEqual(len(server.null_fds), 2)
        self.assertEqual(len(server.save_fds), 2)
        # Clean up opened fds
        os.close(server.null_fds[0])
        os.close(server.null_fds[1])
        os.close(server.save_fds[0])
        os.close(server.save_fds[1])


class TestTimeoutErrorAndHandler(unittest.TestCase):
    def test_raise(self):
        """Verify raise raises vt.TimeoutError."""
        with self.assertRaises(vt.TimeoutError):
            raise vt.TimeoutError('timeout')

    def test_handler_raises(self):
        """Verify handler_raises raises vt.TimeoutError."""
        with self.assertRaises(vt.TimeoutError):
            vt.timeout_handler(signal.SIGALRM, None)

    def test_message(self):
        """Verify message 'custom msg' in str()."""
        try:
            raise vt.TimeoutError('custom msg')
        except vt.TimeoutError as e:
            self.assertIn('custom msg', str(e))


class TestGetHostId(unittest.TestCase):
    def test_returns_hex(self):
        """Verify get_host_id returns hex string."""
        result = vt._get_host_id(tenant_id=b'tenant1', host_name=b'host1')
        self.assertIsInstance(result, str)
        # sha224 hex digest length
        self.assertEqual(len(result), 56)

    def test_deterministic(self):
        """Verify get_host_id is deterministic."""
        result_one = vt._get_host_id(tenant_id=b'a', host_name=b'b')
        result_two = vt._get_host_id(tenant_id=b'a', host_name=b'b')
        self.assertEqual(result_one, result_two)


class TestChoiceOpt(unittest.TestCase):
    def test_instantiation(self):
        """Verify instantiation returns 'myopt'."""
        opt = vt.ChoiceOpt('myopt', choices=['a', 'b'])
        self.assertEqual(opt.name, 'myopt')

    def test_no_choices(self):
        """Verify no_choices returns 'myopt2'."""
        opt = vt.ChoiceOpt('myopt2')
        self.assertEqual(opt.name, 'myopt2')


class TestDefineDebugFlags(unittest.TestCase):
    def test_sets_all_false(self):
        """Verify sets_all value is False."""
        flags_dict = {}
        vt.define_debug_flags(flags_dict)
        self.assertIn('all', flags_dict)
        self.assertIn('creds', flags_dict)
        self.assertIn('libvirt_xml', flags_dict)
        for value in flags_dict.values():
            self.assertFalse(value)

    def test_preserves_nothing_extra(self):
        """Verify preserves_nothing flags_dict[...] is False."""
        flags_dict = {'extra': True}
        vt.define_debug_flags(flags_dict)
        # extra key remains
        self.assertTrue(flags_dict['extra'])
        self.assertFalse(flags_dict['all'])


class TestDefineOptions(unittest.TestCase):
    def test_returns_four_lists(self):
        """Verify returns_four 'topology' in L_other."""
        result = vt.define_options()
        self.assertEqual(len(result), 4)
        L_opts, L_brief, L_details, L_other = result
        self.assertIn('brief', L_opts)
        self.assertIn('all', L_opts)
        self.assertIn('computes', L_brief)
        self.assertIn('topology', L_other)

    def test_details_superset_of_brief(self):
        """Verify details_superset item in L_details."""
        _, L_brief, L_details, _ = vt.define_options()
        for item in L_brief:
            self.assertIn(item, L_details)


class TestDefineOptionFlags(unittest.TestCase):
    def test_default_all_false(self):
        """Verify default_all show.get() is False."""
        show = {}
        L_opts, L_brief, L_details, L_other = vt.define_options()
        vt.define_option_flags(show, options=[],
                               L_opts=L_opts, L_brief=L_brief,
                               L_details=L_details, L_other=L_other)
        self.assertFalse(show.get('computes', True))

    def test_brief_enables_brief_set(self):
        """Verify brief_enables show[...] is True."""
        show = {}
        L_opts, L_brief, L_details, L_other = vt.define_options()
        vt.define_option_flags(show, options=['brief'],
                               L_opts=L_opts, L_brief=L_brief,
                               L_details=L_details, L_other=L_other)
        self.assertTrue(show['computes'])
        self.assertTrue(show['servers'])

    def test_all_enables_details(self):
        """Verify all_enables show[...] is True."""
        show = {}
        L_opts, L_brief, L_details, L_other = vt.define_options()
        vt.define_option_flags(show, options=['all'],
                               L_opts=L_opts, L_brief=L_brief,
                               L_details=L_details, L_other=L_other)
        self.assertTrue(show['libvirt'])
        self.assertTrue(show['volumes'])

    def test_specific_option(self):
        """Verify specific_option show[...] is False."""
        show = {}
        L_opts, L_brief, L_details, L_other = vt.define_options()
        vt.define_option_flags(show, options=['topology'],
                               L_opts=L_opts, L_brief=L_brief,
                               L_details=L_details, L_other=L_other)
        self.assertTrue(show['topology'])
        self.assertFalse(show['computes'])

    def test_none_defaults(self):
        """Verify none_defaults returns [] with None input."""
        show = {}
        vt.define_option_flags(show)
        self.assertEqual(show.get('show'), [])


class TestDoLibvirtDomainInfo(unittest.TestCase):
    def test_empty_host(self):
        """Verify empty_host returns {} with empty input."""
        domains, topology = vt.do_libvirt_domain_info((''))
        self.assertEqual(domains, {})
        self.assertEqual(topology, {})

    def test_none_host(self):
        """Verify none_host returns {} with None input."""
        domains, topology = vt.do_libvirt_domain_info((None))
        self.assertEqual(domains, {})
        self.assertEqual(topology, {})

    @patch('vm_topology.exec.vm_topology.libvirt')
    @patch('vm_topology.exec.vm_topology.signal')
    @patch.dict('vm_topology.exec.vm_topology.debug', {'libvirt_xml': False}, clear=False)
    def test_connection_success(self, mock_signal, mock_libvirt):
        # Build mock domain
        """Verify connection_success is called once on success."""
        mock_dom = MagicMock()
        mock_dom.name.return_value = 'instance-0001'
        mock_dom.ID.return_value = 1
        mock_dom.UUIDString.return_value = 'uuid-1234'
        mock_dom.OSType.return_value = 'hvm'
        mock_dom.info.return_value = (1, 2097152, 2097152, 2, 50000)
        mock_dom.vcpus.return_value = (
            [(0, 1, 100, 0), (1, 1, 200, 1)],
            [(True, False, False, False), (False, True, False, False)]
        )
        numatune_xml = '<domain><numatune><memnode nodeset="0"/></numatune></domain>'
        mock_dom.XMLDesc.return_value = numatune_xml

        # Build mock connection
        caps_xml = '''<capabilities>
          <host>
            <topology>
              <cells>
                <cell id="0">
                  <cpus>
                    <cpu id="0" socket_id="0" core_id="0"/>
                    <cpu id="1" socket_id="0" core_id="1"/>
                  </cpus>
                </cell>
              </cells>
            </topology>
          </host>
        </capabilities>'''
        mock_conn = MagicMock()
        mock_conn.getCapabilities.return_value = caps_xml
        mock_conn.listAllDomains.return_value = [mock_dom]
        mock_libvirt.openReadOnly.return_value = mock_conn

        domains, topology = vt.do_libvirt_domain_info(('compute-0'))
        self.assertIn('uuid-1234', domains)
        self.assertEqual(domains['uuid-1234']['name'], 'instance-0001')
        self.assertEqual(domains['uuid-1234']['state'], 'Running')
        self.assertEqual(domains['uuid-1234']['vcpus'], 2)
        self.assertIn(0, topology)
        mock_conn.close.assert_called_once()

    @patch('vm_topology.exec.vm_topology.libvirt')
    @patch('vm_topology.exec.vm_topology.signal')
    def test_connection_none(self, mock_signal, mock_libvirt):
        """Verify connection_none returns {} with None input."""
        mock_libvirt.openReadOnly.return_value = None
        domains, topology = vt.do_libvirt_domain_info(('host1'))
        self.assertEqual(domains, {})
        self.assertEqual(topology, {})

    @patch('vm_topology.exec.vm_topology.libvirt')
    @patch('vm_topology.exec.vm_topology.signal')
    def test_timeout(self, mock_signal, mock_libvirt):
        """Verify timeout raises vt.TimeoutError on timeout."""
        mock_libvirt.openReadOnly.side_effect = vt.TimeoutError('timeout')
        with self.assertRaises(vt.TimeoutError):
            vt.do_libvirt_domain_info(('host1'))

    @patch('vm_topology.exec.vm_topology.libvirt')
    @patch('vm_topology.exec.vm_topology.signal')
    def test_connection_exception(self, mock_signal, mock_libvirt):
        """Verify connection_exception raises Exception on exception."""
        mock_libvirt.openReadOnly.side_effect = Exception('conn failed')
        self.assertRaises(Exception,  # noqa: H202
                          vt.do_libvirt_domain_info, ('host1'))

    @patch('vm_topology.exec.vm_topology.libvirt')
    @patch('vm_topology.exec.vm_topology.signal')
    @patch.dict('vm_topology.exec.vm_topology.debug', {'libvirt_xml': False}, clear=False)
    def test_vcpus_exception_fallback(self, mock_signal, mock_libvirt):
        """Verify vcpus_exception 'uuid-5678' in domains on."""
        mock_dom = MagicMock()
        mock_dom.name.return_value = 'inst-0002'
        mock_dom.ID.return_value = 2
        mock_dom.UUIDString.return_value = 'uuid-5678'
        mock_dom.OSType.return_value = 'hvm'
        mock_dom.info.return_value = (1, 1048576, 1048576, 1, 1000)
        mock_dom.vcpus.side_effect = Exception('vcpus failed')
        mock_dom.XMLDesc.return_value = '<domain><numatune/></domain>'

        caps_xml = '''<capabilities><host><topology><cells>
            <cell id="0"><cpus><cpu id="0" socket_id="0" core_id="0"/></cpus></cell>
            </cells></topology></host></capabilities>'''
        mock_conn = MagicMock()
        mock_conn.getCapabilities.return_value = caps_xml
        mock_conn.listAllDomains.return_value = [mock_dom]
        mock_libvirt.openReadOnly.return_value = mock_conn

        domains, topology = vt.do_libvirt_domain_info(('host2'))
        self.assertIn('uuid-5678', domains)

    @patch('vm_topology.exec.vm_topology.libvirt')
    @patch('vm_topology.exec.vm_topology.signal')
    @patch.dict('vm_topology.exec.vm_topology.debug', {'libvirt_xml': False}, clear=False)
    def test_floating_vcpus(self, mock_signal, mock_libvirt):
        """Test floating cpulist when up_total > nrVirtCpu."""
        mock_dom = MagicMock()
        mock_dom.name.return_value = 'inst-float'
        mock_dom.ID.return_value = 3
        mock_dom.UUIDString.return_value = 'uuid-float'
        mock_dom.OSType.return_value = 'hvm'
        mock_dom.info.return_value = (1, 2097152, 2097152, 1, 5000)
        # 1 vcpu but mapped to 2 pcpus -> floating
        mock_dom.vcpus.return_value = (
            [(0, 1, 100, 0)],
            [(True, True, False, False)]
        )
        mock_dom.XMLDesc.return_value = '<domain><numatune/></domain>'

        caps_xml = '''<capabilities><host><topology><cells>
            <cell id="0"><cpus>
              <cpu id="0" socket_id="0" core_id="0"/>
              <cpu id="1" socket_id="0" core_id="1"/>
            </cpus></cell>
            </cells></topology></host></capabilities>'''
        mock_conn = MagicMock()
        mock_conn.getCapabilities.return_value = caps_xml
        mock_conn.listAllDomains.return_value = [mock_dom]
        mock_libvirt.openReadOnly.return_value = mock_conn

        domains, _ = vt.do_libvirt_domain_info(('host-f'))
        self.assertEqual(domains['uuid-float']['cpulist'], [0, 1])

    @patch('vm_topology.exec.vm_topology.libvirt')
    @patch('vm_topology.exec.vm_topology.signal')
    @patch.dict('vm_topology.exec.vm_topology.debug', {'libvirt_xml': True}, clear=False)
    def test_debug_xml(self, mock_signal, mock_libvirt):
        """Verify debug_xml 'uuid-dbg' in domains."""
        mock_dom = MagicMock()
        mock_dom.name.return_value = 'inst-dbg'
        mock_dom.ID.return_value = 4
        mock_dom.UUIDString.return_value = 'uuid-dbg'
        mock_dom.OSType.return_value = 'hvm'
        mock_dom.info.return_value = (1, 1048576, 1048576, 1, 100)
        mock_dom.vcpus.return_value = ([(0, 1, 10, 0)], [(True,)])
        mock_dom.XMLDesc.return_value = '<domain><numatune/></domain>'

        caps_xml = '''<capabilities><host><topology><cells>
            <cell id="0"><cpus><cpu id="0" socket_id="0" core_id="0"/></cpus></cell>
            </cells></topology></host></capabilities>'''
        mock_conn = MagicMock()
        mock_conn.getCapabilities.return_value = caps_xml
        mock_conn.listAllDomains.return_value = [mock_dom]
        mock_libvirt.openReadOnly.return_value = mock_conn

        domains, _ = vt.do_libvirt_domain_info(('host-dbg'))
        self.assertIn('uuid-dbg', domains)


class TestLibvirtDomainInfoWorker(unittest.TestCase):
    @patch('vm_topology.exec.vm_topology.do_libvirt_domain_info')
    def test_success(self, mock_do):
        """Verify success returns None on success."""
        mock_do.return_value = ({'uuid1': {}}, {0: {0: {0: 0}}})
        host, domain, topology, tm, error = vt.libvirt_domain_info_worker(('host1'))
        self.assertEqual(host, 'host1')
        self.assertIn('uuid1', domain)
        self.assertIsNone(error)

    @patch('vm_topology.exec.vm_topology.do_libvirt_domain_info')
    def test_exception(self, mock_do):
        """Verify exception 'cannot connect' in error on exception."""
        mock_do.side_effect = Exception('fail')
        host, domain, topology, tm, error = vt.libvirt_domain_info_worker(('host1'))
        self.assertEqual(domain, {})
        self.assertEqual(topology, {})
        self.assertIn('cannot connect', error)


class TestParseArguments(unittest.TestCase):
    @patch('vm_topology.exec.vm_topology.CONF')
    def test_basic(self, mock_conf):
        """Verify basic show.get() is True."""
        mock_conf.dbg = []
        mock_conf.show = ['brief']
        mock_conf.keystone_authtoken = MagicMock()
        debug = {}
        show = {}
        vt.define_debug_flags(debug)
        # Mock CONF() call and register_cli_opts
        mock_conf.register_cli_opts = MagicMock()
        mock_conf.side_effect = None
        mock_conf.__call__ = MagicMock()
        vt.parse_arguments(debug, show)
        self.assertTrue(show.get('computes', False))

    @patch('vm_topology.exec.vm_topology.CONF')
    def test_debug_all(self, mock_conf):
        """Verify debug_all debug[...] is False."""
        mock_conf.dbg = ['all']
        mock_conf.show = ['brief']
        mock_conf.register_cli_opts = MagicMock()
        mock_conf.__call__ = MagicMock()
        debug = {}
        show = {}
        vt.define_debug_flags(debug)
        vt.parse_arguments(debug, show)
        self.assertTrue(debug['all'])
        # libvirt_xml should be preserved (not set to True by 'all')
        self.assertFalse(debug['libvirt_xml'])

    @patch('vm_topology.exec.vm_topology.CONF')
    def test_debug_specific(self, mock_conf):
        """Verify debug_specific debug[...] is False."""
        mock_conf.dbg = ['servers']
        mock_conf.show = ['brief']
        mock_conf.register_cli_opts = MagicMock()
        mock_conf.__call__ = MagicMock()
        debug = {}
        show = {}
        vt.define_debug_flags(debug)
        vt.parse_arguments(debug, show)
        self.assertTrue(debug['servers'])
        self.assertFalse(debug['flavors'])


class TestGetInfoAndDisplay(unittest.TestCase):

    @patch('vm_topology.exec.vm_topology.select')
    @patch('vm_topology.exec.vm_topology.print_all_tables')
    @patch('vm_topology.exec.vm_topology.print_debug_info')
    @patch('vm_topology.exec.vm_topology.automap_base')
    @patch('vm_topology.exec.vm_topology.MetaData')
    @patch('vm_topology.exec.vm_topology.create_engine')
    @patch('vm_topology.exec.vm_topology.psutil')
    @patch('vm_topology.exec.vm_topology.multiprocessing')
    @patch('vm_topology.exec.vm_topology.nova_client')
    @patch('vm_topology.exec.vm_topology.cinder_client')
    @patch('vm_topology.exec.vm_topology.glance_client')
    @patch('vm_topology.exec.vm_topology.keystone_client')
    @patch('vm_topology.exec.vm_topology.session')
    @patch('vm_topology.exec.vm_topology.keystone')
    @patch('vm_topology.exec.vm_topology.CONF')
    def test_keystone_connect_failure(self, mock_conf, mock_ks_loading,
                                      mock_session, mock_kc, mock_gc,
                                      mock_cc, mock_nc, mock_mp, mock_psutil,
                                      mock_engine, mock_metadata_cls,
                                      mock_automap, mock_print_debug,
                                      mock_print_tables, mock_select):
        """Test keystone connect failure raises expected error."""
        mock_conf.keystone_authtoken = MagicMock()
        mock_conf.keystone_authtoken.region_name = 'RegionOne'
        mock_ks_loading.load_auth_from_conf_options.return_value = MagicMock()
        mock_session.Session.return_value = MagicMock()

        mock_conn = MagicMock()
        mock_conn.execute.return_value = []
        mock_engine.return_value.connect.return_value = mock_conn
        mock_metadata_cls.return_value = MagicMock()
        mock_automap.return_value = MagicMock()
        mock_select.return_value.where.return_value = MagicMock()

        mock_kc.Client.side_effect = Exception('keystone fail')

        with self.assertRaises(SystemExit):
            vt.get_info_and_display(show=_all_show_false())


if __name__ == '__main__':
    unittest.main()
