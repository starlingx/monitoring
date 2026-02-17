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

if __name__ == '__main__':
    unittest.main()
