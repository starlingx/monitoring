#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import unittest
import sys
import os
from unittest.mock import MagicMock
from unittest.mock import patch

# Mock all external dependencies before importing ptp module
sys.modules['collectd'] = MagicMock()
sys.modules['tsconfig'] = MagicMock()
sys.modules['tsconfig.tsconfig'] = MagicMock()
sys.modules['plugin_common'] = MagicMock()
sys.modules['fm_api'] = MagicMock()
sys.modules['fm_api.constants'] = MagicMock()
sys.modules['fm_api.fm_api'] = MagicMock()
sys.modules['ptp_interface'] = MagicMock()
sys.modules['ptp_gnss_monitor'] = MagicMock()
sys.modules['cgu_handler'] = MagicMock()
sys.modules['pynetlink'] = MagicMock()
sys.modules['oslo_utils'] = MagicMock()
sys.modules['oslo_utils.timeutils'] = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import ptp
from ptp import check_ptp_regular
from ptp import PTP_ctrl_object
from ptp import PTP_alarm_object


class TestCheckPtpRegular(unittest.TestCase):
    """Test check_ptp_regular with upstream instance up and down"""

    PORT_DATA_MASTER = b"""sending: GET PORT_DATA_SET
        b49691.fffe.dc787d-1 seq 0 RESPONSE MANAGEMENT PORT_DATA_SET
                portIdentity            b49691.fffe.dc787d-1
                portState               MASTER
                logMinDelayReqInterval  -4
                peerMeanPathDelay       0
                logAnnounceInterval     -3
                announceReceiptTimeout  3
                logSyncInterval         -4
                delayMechanism          1
                logMinPdelayReqInterval 0
                versionNumber           2
        b49691.fffe.dc787d-2 seq 0 RESPONSE MANAGEMENT PORT_DATA_SET
                portIdentity            b49691.fffe.dc787d-2
                portState               FAULTY
                logMinDelayReqInterval  -4
                peerMeanPathDelay       0
                logAnnounceInterval     -3
                announceReceiptTimeout  3
                logSyncInterval         -4
                delayMechanism          1
                logMinPdelayReqInterval 0
                versionNumber           2
"""

    TIME_STATUS_LOCAL_GM = b"""sending: GET TIME_STATUS_NP
        b49691.fffe.dc787d-0 seq 0 RESPONSE MANAGEMENT TIME_STATUS_NP
                master_offset              0
                ingress_time               0
                cumulativeScaledRateOffset +0.000000000
                scaledLastGmPhaseChange    0
                gmTimeBaseIndicator        0
                lastGmPhaseChange          0x0000'0000000000000000.0000
                gmPresent                  false
                gmIdentity                 b49691.fffe.dc787d
"""

    UPSTREAM_PORT_INSTANCE_DOWN = b'sending: GET PORT_DATA_SET\n'
    UPSTREAM_TIME_INSTANCE_DOWN = b'sending: GET TIME_STATUS_NP\n'

    UPSTREAM_PORT_SLAVE = b"""sending: GET PORT_DATA_SET
        b49691.fffe.dc785e-1 seq 0 RESPONSE MANAGEMENT PORT_DATA_SET
                portIdentity            b49691.fffe.dc785e-1
                portState               SLAVE
                logMinDelayReqInterval  -4
                peerMeanPathDelay       0
                logAnnounceInterval     -3
                announceReceiptTimeout  3
                logSyncInterval         -4
                delayMechanism          1
                logMinPdelayReqInterval 0
                versionNumber           2
        b49691.fffe.dc785e-2 seq 0 RESPONSE MANAGEMENT PORT_DATA_SET
                portIdentity            b49691.fffe.dc785e-2
                portState               FAULTY
                logMinDelayReqInterval  -4
                peerMeanPathDelay       0
                logAnnounceInterval     -3
                announceReceiptTimeout  3
                logSyncInterval         -4
                delayMechanism          1
                logMinPdelayReqInterval 0
                versionNumber           2
"""

    UPSTREAM_TIME_LOCKED = b"""sending: GET TIME_STATUS_NP
        b49691.fffe.dc785e-0 seq 0 RESPONSE MANAGEMENT TIME_STATUS_NP
                master_offset              -1
                ingress_time               1771429877613143311
                cumulativeScaledRateOffset +0.000000000
                scaledLastGmPhaseChange    0
                gmTimeBaseIndicator        0
                lastGmPhaseChange          0x0000'0000000000000000.0000
                gmPresent                  true
                gmIdentity                 acde48.0000.000003
"""

    # Local instance is itself the Grand Master (T-GM): my_identity ==
    # gmIdentity. The master_offset here is a stale value populated while the
    # instance was still a slave before becoming master; it must be ignored.
    TIME_STATUS_LOCAL_GM_STALE_OFFSET = b"""sending: GET TIME_STATUS_NP
        b49691.fffe.dc787d-0 seq 0 RESPONSE MANAGEMENT TIME_STATUS_NP
                master_offset              123456
                ingress_time               0
                cumulativeScaledRateOffset +0.000000000
                scaledLastGmPhaseChange    0
                gmTimeBaseIndicator        0
                lastGmPhaseChange          0x0000'0000000000000000.0000
                gmPresent                  false
                gmIdentity                 b49691.fffe.dc787d
"""

    # Local instance is locked to a remote Grand Master (T-BC, or a T-GM that
    # lost GNSS and fell back to an external PTP GM): my_identity != gmIdentity.
    # The master_offset is meaningful and must be forwarded to check_time_drift.
    TIME_STATUS_LOCKED_TO_REMOTE_GM = b"""sending: GET TIME_STATUS_NP
        b49691.fffe.dc787d-0 seq 0 RESPONSE MANAGEMENT TIME_STATUS_NP
                master_offset              -42
                ingress_time               1771429877613143311
                cumulativeScaledRateOffset +0.000000000
                scaledLastGmPhaseChange    0
                gmTimeBaseIndicator        0
                lastGmPhaseChange          0x0000'0000000000000000.0000
                gmPresent                  true
                gmIdentity                 acde48.0000.000003
"""

    def setUp(self):
        """Set up test fixtures"""
        self.instance = 'test-instance'
        self.upstream_instance = 'upstream-instance'
        self.conf_file = '/etc/linuxptp/ptpinstance/ptp4l-test-instance.conf'

        ctrl = PTP_ctrl_object()
        ctrl.instance_type = 'ptp4l'
        ctrl.interface = 'ens0f0'
        ctrl.log_throttle_count = 0
        ctrl.nolock_alarm_object = PTP_alarm_object(self.instance)
        ctrl.nolock_alarm_object.raised = False
        ctrl.nolock_alarm_object.eid = 'test-eid'
        ptp.ptpinstances[self.instance] = ctrl

        upstream_ctrl = PTP_ctrl_object()
        upstream_ctrl.instance_type = 'ptp4l'
        upstream_ctrl.interface = 'ens0f1'
        ptp.ptpinstances[self.upstream_instance] = upstream_ctrl

        ptp.obj.hostname = 'test-host'
        ptp.obj.capabilities = {'ts2phc_source': 'generic'}
        ptp.obj.INIT_LOG_THROTTLE = 10
        ptp.phc2sys_source = 'ens0f1'
        ptp.ptp4l_instance_map = {'ens0f1': self.upstream_instance}

    def tearDown(self):
        """Clean up after tests"""
        if self.instance in ptp.ptpinstances:
            del ptp.ptpinstances[self.instance]
        if self.upstream_instance in ptp.ptpinstances:
            del ptp.ptpinstances[self.upstream_instance]

    @patch('ptp.get_base_port')
    @patch('subprocess.check_output')
    def test_with_upstream_instance_down(self, mock_check_output, mock_get_base_port):
        """Test downstream instance when upstream instance is down"""
        mock_check_output.side_effect = [
            self.PORT_DATA_MASTER,
            self.TIME_STATUS_LOCAL_GM,
            self.UPSTREAM_PORT_INSTANCE_DOWN,
            self.UPSTREAM_TIME_INSTANCE_DOWN
        ]
        mock_get_base_port.return_value = 'ens0f1'

        result = check_ptp_regular(self.instance, ptp.ptpinstances[self.instance], self.conf_file)

        self.assertEqual(result, 0)
        self.assertTrue(ptp.ptpinstances[self.instance].nolock_alarm_object.raised)

    @patch('ptp.check_time_drift')
    @patch('ptp.clear_alarm')
    @patch('ptp.get_base_port')
    @patch('subprocess.check_output')
    def test_with_upstream_instance_locked(
        self, mock_check_output, mock_get_base_port, mock_clear_alarm,
        mock_check_time_drift
    ):
        """Test downstream instance when upstream instance is locked"""
        mock_check_output.side_effect = [
            self.PORT_DATA_MASTER,
            self.TIME_STATUS_LOCAL_GM,
            self.UPSTREAM_PORT_SLAVE,
            self.UPSTREAM_TIME_LOCKED
        ]
        mock_get_base_port.return_value = 'ens0f1'
        mock_clear_alarm.return_value = True

        result = check_ptp_regular(self.instance, ptp.ptpinstances[self.instance], self.conf_file)

        self.assertEqual(result, 0)
        self.assertEqual(ptp.ptpinstances[self.instance].nolock_alarm_object.raised, False)
        mock_check_time_drift.assert_called_once()


class TestCheckPtpRegularMasterOffset(unittest.TestCase):
    """Test check_ptp_regular master offset

    Verify master_offset from TIME_STATUS_NP is only forwarded to
    check_time_drift when the local instance is NOT the Grand Master.

    When the local ptp4l instance is itself the GM (my_identity ==
    gmIdentity), the reported master_offset can be a stale value left over
    from when the instance was still a slave, so it must be ignored. When the
    instance is locked to a remote GM (T-BC, or a T-GM that lost GNSS and fell
    back to an external PTP GM), the master_offset is meaningful and must be
    forwarded.
    """

    # Local instance is the GM: my_identity (b49691.fffe.dc787d) ==
    # gmIdentity. Stale master_offset must be ignored.
    TIME_STATUS_LOCAL_GM_STALE_OFFSET = \
        TestCheckPtpRegular.TIME_STATUS_LOCAL_GM_STALE_OFFSET

    # Local instance is locked to a remote GM: my_identity != gmIdentity.
    # master_offset must be forwarded.
    TIME_STATUS_LOCKED_TO_REMOTE_GM = \
        TestCheckPtpRegular.TIME_STATUS_LOCKED_TO_REMOTE_GM

    # A single SLAVE port so port_locked is True (needed for the T-BC path to
    # avoid entering the no-lock branch).
    PORT_DATA_SLAVE = b"""sending: GET PORT_DATA_SET
        b49691.fffe.dc787d-1 seq 0 RESPONSE MANAGEMENT PORT_DATA_SET
                portIdentity            b49691.fffe.dc787d-1
                portState               SLAVE
                logMinDelayReqInterval  -4
                peerMeanPathDelay       0
                logAnnounceInterval     -3
                announceReceiptTimeout  3
                logSyncInterval         -4
                delayMechanism          1
                logMinPdelayReqInterval 0
                versionNumber           2
"""

    def setUp(self):
        self.instance = 'test-instance'
        self.conf_file = '/etc/linuxptp/ptpinstance/ptp4l-test-instance.conf'

        ctrl = PTP_ctrl_object()
        ctrl.instance_type = 'ptp4l'
        ctrl.interface = 'ens0f0'
        ctrl.log_throttle_count = 0
        ctrl.disciplined_by_ts2phc = True
        ctrl.nolock_alarm_object = PTP_alarm_object(self.instance)
        ctrl.nolock_alarm_object.raised = False
        ctrl.nolock_alarm_object.eid = 'test-eid'
        ptp.ptpinstances[self.instance] = ctrl

        ptp.obj.hostname = 'test-host'
        # nmea path lets us control clock_locked via get_netlink_dpll_status
        ptp.obj.capabilities = {'ts2phc_source': 'nmea'}
        ptp.obj.INIT_LOG_THROTTLE = 10

    def tearDown(self):
        if self.instance in ptp.ptpinstances:
            del ptp.ptpinstances[self.instance]

    @patch('ptp.check_time_drift')
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port')
    @patch('subprocess.check_output')
    def test_tgm_local_gm_ignores_stale_master_offset(
        self, mock_check_output, mock_get_base_port, mock_get_dpll_status,
        mock_check_time_drift
    ):
        """T-GM: local instance is GM, stale master_offset must be ignored."""
        mock_check_output.side_effect = [
            TestCheckPtpRegular.PORT_DATA_MASTER,
            self.TIME_STATUS_LOCAL_GM_STALE_OFFSET,
        ]
        mock_get_base_port.return_value = 'ens0f0'
        # DPLL locked so clock_locked is True and we reach check_time_drift
        mock_get_dpll_status.return_value = (ptp.CLOCK_STATE_LOCKED, None)

        check_ptp_regular(self.instance, ptp.ptpinstances[self.instance], self.conf_file)

        # master_offset must NOT be forwarded (called with gm_identity only)
        mock_check_time_drift.assert_called_once_with(
            self.instance, 'b49691.fffe.dc787d')

    @patch('ptp.check_time_drift')
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port')
    @patch('subprocess.check_output')
    def test_tbc_locked_to_remote_gm_forwards_master_offset(
        self, mock_check_output, mock_get_base_port, mock_get_dpll_status,
        mock_check_time_drift
    ):
        """T-BC: locked to a remote GM, master_offset must be forwarded."""
        mock_check_output.side_effect = [
            self.PORT_DATA_SLAVE,
            self.TIME_STATUS_LOCKED_TO_REMOTE_GM,
        ]
        mock_get_base_port.return_value = 'ens0f0'
        # DPLL locked so clock_locked is True and we reach check_time_drift
        mock_get_dpll_status.return_value = (ptp.CLOCK_STATE_LOCKED, None)

        check_ptp_regular(self.instance, ptp.ptpinstances[self.instance], self.conf_file)

        # master_offset (-42) must be forwarded to check_time_drift
        mock_check_time_drift.assert_called_once_with(
            self.instance, 'acde48.0000.000003', -42.0)


class TestCheckPhc2sysTimeDriftMasterOffset(unittest.TestCase):
    """Test check_phc2sys_time_drift master offset

    Verify check_phc2sys_time_drift applies the same master_offset gating:
    forward master_offset only when the local instance is not the GM.
    """

    def setUp(self):
        self.instance = 'test-instance'
        self.conf_file = '/etc/linuxptp/ptpinstance/ptp4l-test-instance.conf'

        ctrl = PTP_ctrl_object()
        ctrl.instance_type = 'ptp4l'
        ctrl.interface = 'ens0f0'
        ctrl.disciplined_by_ts2phc = True
        # config: no HA, default domain
        ctrl.timing_instance = MagicMock()
        ctrl.timing_instance.config = {'global': {}}
        ptp.ptpinstances[self.instance] = ctrl

        ptp.obj.hostname = 'test-host'

    def tearDown(self):
        if self.instance in ptp.ptpinstances:
            del ptp.ptpinstances[self.instance]

    @patch('ptp.check_time_drift')
    @patch('ptp.read_time_status_np')
    def test_tgm_local_gm_ignores_stale_master_offset(
        self, mock_read_time_status, mock_check_time_drift
    ):
        """T-GM: my_identity == gm_identity, stale master_offset ignored."""
        # my_identity, gm_present, gm_identity, got_master_offset, master_offset
        mock_read_time_status.return_value = (
            'b49691.fffe.dc787d', 'false', 'b49691.fffe.dc787d', True, 123456.0)

        ptp.check_phc2sys_time_drift(
            self.instance, ptp.ptpinstances[self.instance], self.conf_file)

        mock_check_time_drift.assert_called_once_with(
            self.instance, 'b49691.fffe.dc787d')

    @patch('ptp.check_time_drift')
    @patch('ptp.read_time_status_np')
    def test_tbc_locked_to_remote_gm_forwards_master_offset(
        self, mock_read_time_status, mock_check_time_drift
    ):
        """T-BC: my_identity != gm_identity, master_offset forwarded."""
        mock_read_time_status.return_value = (
            'b49691.fffe.dc787d', 'true', 'acde48.0000.000003', True, -42.0)

        ptp.check_phc2sys_time_drift(
            self.instance, ptp.ptpinstances[self.instance], self.conf_file)

        mock_check_time_drift.assert_called_once_with(
            self.instance, 'acde48.0000.000003', -42.0)


if __name__ == '__main__':
    unittest.main()
