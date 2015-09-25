#  Copyright 2014 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock
from oslotest import base

from os_win import exceptions
from os_win.utils.network import networkutils


class NetworkUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V NetworkUtils class."""

    _FAKE_VSWITCH_NAME = "fake_vswitch_name"
    _FAKE_PORT_NAME = "fake_port_name"
    _FAKE_JOB_PATH = 'fake_job_path'
    _FAKE_RET_VAL = 0
    _FAKE_RES_PATH = "fake_res_path"
    _FAKE_VSWITCH = "fake_vswitch"
    _FAKE_VLAN_ID = "fake_vlan_id"
    _FAKE_CLASS_NAME = "fake_class_name"
    _FAKE_ELEMENT_NAME = "fake_element_name"
    _FAKE_HYPERV_VM_STATE = 'fake_hyperv_state'

    _FAKE_ACL_ACT = 'fake_acl_action'
    _FAKE_ACL_DIR = 'fake_acl_dir'
    _FAKE_ACL_TYPE = 'fake_acl_type'
    _FAKE_LOCAL_PORT = 'fake_local_port'
    _FAKE_PROTOCOL = 'fake_port_protocol'
    _FAKE_REMOTE_ADDR = '0.0.0.0/0'
    _FAKE_WEIGHT = 'fake_weight'

    _MSVM_VIRTUAL_SWITCH = 'Msvm_VirtualEthernetSwitch'

    def setUp(self):
        super(NetworkUtilsTestCase, self).setUp()
        self.netutils = networkutils.NetworkUtils()
        self.netutils._conn = mock.MagicMock()
        self.netutils._jobutils = mock.MagicMock()

    def test_get_external_vswitch(self):
        mock_vswitch = mock.MagicMock()
        mock_vswitch.path_.return_value = mock.sentinel.FAKE_VSWITCH_PATH
        getattr(self.netutils._conn,
                self._MSVM_VIRTUAL_SWITCH).return_value = [mock_vswitch]

        switch_path = self.netutils.get_external_vswitch(
            mock.sentinel.FAKE_VSWITCH_NAME)

        self.assertEqual(mock.sentinel.FAKE_VSWITCH_PATH, switch_path)

    def test_get_external_vswitch_not_found(self):
        self.netutils._conn.Msvm_VirtualEthernetSwitch.return_value = []

        self.assertRaises(exceptions.HyperVException,
                          self.netutils.get_external_vswitch,
                          mock.sentinel.FAKE_VSWITCH_NAME)

    def test_get_external_vswitch_no_name(self):
        mock_vswitch = mock.MagicMock()
        mock_vswitch.path_.return_value = mock.sentinel.FAKE_VSWITCH_PATH

        mock_ext_port = self.netutils._conn.Msvm_ExternalEthernetPort()[0]
        self._prepare_external_port(mock_vswitch, mock_ext_port)

        switch_path = self.netutils.get_external_vswitch(None)
        self.assertEqual(mock.sentinel.FAKE_VSWITCH_PATH, switch_path)

    def _prepare_external_port(self, mock_vswitch, mock_ext_port):
        mock_lep = mock_ext_port.associators()[0]
        mock_lep1 = mock_lep.associators()[0]
        mock_esw = mock_lep1.associators()[0]
        mock_esw.associators.return_value = [mock_vswitch]

    def test_vswitch_port_needed(self):
        self.assertFalse(self.netutils.vswitch_port_needed())

    def test_connect_vnic_to_vswitch_found(self):
        self._test_connect_vnic_to_vswitch(True)

    def test_connect_vnic_to_vswitch_not_found(self):
        self._test_connect_vnic_to_vswitch(False)

    def _test_connect_vnic_to_vswitch(self, found):
        self.netutils._get_vnic_settings = mock.MagicMock()

        if not found:
            mock_vm = mock.MagicMock()
            self.netutils._get_vm_from_res_setting_data = mock.MagicMock(
                return_value=mock_vm)
            self.netutils._add_virt_resource = mock.MagicMock()
        else:
            self.netutils._modify_virt_resource = mock.MagicMock()

        self.netutils._get_vswitch = mock.MagicMock()
        mock_port = self._mock_get_switch_port_alloc(found=found)
        mock_port.HostResource = []

        self.netutils.connect_vnic_to_vswitch(self._FAKE_VSWITCH_NAME,
                                              self._FAKE_PORT_NAME)

        if not found:
            mock_add_resource = self.netutils._jobutils.add_virt_resource
            mock_add_resource.assert_called_once_with(mock_port, mock_vm)
        else:
            mock_modify_resource = self.netutils._jobutils.modify_virt_resource
            mock_modify_resource.assert_called_once_with(mock_port)

    def test_connect_vnic_to_vswitch_already_connected(self):
        mock_port = self._mock_get_switch_port_alloc()
        mock_port.HostResource = [mock.sentinel.vswitch_path]

        self.netutils.connect_vnic_to_vswitch(mock.sentinel.switch_name,
                                              mock.sentinel.port_name)

        self.assertFalse(self.netutils._jobutils.modify_virt_resource.called)

    def _mock_get_switch_port_alloc(self, found=True):
        mock_port = mock.MagicMock()
        patched = mock.patch.object(
            self.netutils, '_get_switch_port_allocation',
            return_value=(mock_port, found))
        patched.start()
        self.addCleanup(patched.stop)
        return mock_port

    def test_disconnect_switch_port_delete_port(self):
        self._test_disconnect_switch_port(True)

    def test_disconnect_switch_port_modify_port(self):
        self._test_disconnect_switch_port(False)

    def _test_disconnect_switch_port(self, delete_port):
        mock_sw_port = self._mock_get_switch_port_alloc()

        self.netutils.disconnect_switch_port(self._FAKE_PORT_NAME,
                                             True, delete_port)

        if delete_port:
            mock_remove_resource = self.netutils._jobutils.remove_virt_resource
            mock_remove_resource.assert_called_once_with(mock_sw_port)
        else:
            mock_modify_resource = self.netutils._jobutils.modify_virt_resource
            mock_modify_resource.assert_called_once_with(mock_sw_port)

    def test_get_vswitch(self):
        self.netutils._conn.Msvm_VirtualEthernetSwitch.return_value = [
            self._FAKE_VSWITCH]
        vswitch = self.netutils._get_vswitch(self._FAKE_VSWITCH_NAME)

        self.assertEqual(self._FAKE_VSWITCH, vswitch)

    def test_get_vswitch_not_found(self):
        self.netutils._conn.Msvm_VirtualEthernetSwitch.return_value = []
        self.assertRaises(exceptions.HyperVException,
                          self.netutils._get_vswitch,
                          self._FAKE_VSWITCH_NAME)

    def test_set_vswitch_port_vlan_id(self):
        mock_port = self._mock_get_switch_port_alloc(found=True)
        old_vlan_settings = mock.MagicMock()
        self.netutils._get_vlan_setting_data_from_port_alloc = mock.MagicMock(
            return_value=old_vlan_settings)
        mock_vlan_settings = mock.MagicMock()
        self.netutils._get_vlan_setting_data = mock.MagicMock(return_value=(
            mock_vlan_settings, True))

        self.netutils.set_vswitch_port_vlan_id(self._FAKE_VLAN_ID,
                                               self._FAKE_PORT_NAME)

        mock_remove_feature = self.netutils._jobutils.remove_virt_feature
        mock_remove_feature.assert_called_once_with(old_vlan_settings)
        mock_add_feature = self.netutils._jobutils.add_virt_feature
        mock_add_feature.assert_called_once_with(mock_vlan_settings, mock_port)

    @mock.patch.object(networkutils.NetworkUtils,
                       '_get_vlan_setting_data_from_port_alloc')
    def test_set_vswitch_port_vlan_id_already_set(self, mock_get_vlan_sd):
        self._mock_get_switch_port_alloc()
        mock_get_vlan_sd.return_value = mock.MagicMock(
            AccessVlanId=mock.sentinel.vlan_id,
            OperationMode=self.netutils._OPERATION_MODE_ACCESS)

        self.netutils.set_vswitch_port_vlan_id(mock.sentinel.vlan_id,
                                               mock.sentinel.port_name)

        mock_remove_feature = self.netutils._jobutils.remove_virt_feature
        self.assertFalse(mock_remove_feature.called)
        mock_add_feature = self.netutils._jobutils.add_virt_feature
        self.assertFalse(mock_add_feature.called)

    def test_get_setting_data(self):
        self.netutils._get_first_item = mock.MagicMock(return_value=None)

        mock_data = mock.MagicMock()
        self.netutils._get_default_setting_data = mock.MagicMock(
            return_value=mock_data)

        ret_val = self.netutils._get_setting_data(self._FAKE_CLASS_NAME,
                                                  self._FAKE_ELEMENT_NAME,
                                                  True)

        self.assertEqual(ret_val, (mock_data, False))

    def test_enable_port_metrics_collection(self):
        mock_port = self._mock_get_switch_port_alloc()
        mock_acl = mock.MagicMock()

        with mock.patch.multiple(
            self.netutils,
            _get_default_setting_data=mock.MagicMock(return_value=mock_acl)):

            self.netutils.enable_port_metrics_collection(self._FAKE_PORT_NAME)

            mock_add_feature = self.netutils._jobutils.add_virt_feature
            actual_calls = len(mock_add_feature.mock_calls)
            self.assertEqual(4, actual_calls)
            mock_add_feature.assert_called_with(mock_acl, mock_port)

    def test_enable_control_metrics_ok(self):
        mock_metrics_svc = self.netutils._conn.Msvm_MetricService()[0]
        mock_metrics_def_source = self.netutils._conn.CIM_BaseMetricDefinition
        mock_metric_def = mock.MagicMock()
        mock_port = self._mock_get_switch_port_alloc()

        mock_metrics_def_source.return_value = [mock_metric_def]
        m_call = mock.call(
            Subject=mock_port.path_.return_value,
            Definition=mock_metric_def.path_.return_value,
            MetricCollectionEnabled=self.netutils._METRIC_ENABLED)

        self.netutils.enable_control_metrics(self._FAKE_PORT_NAME)

        mock_metrics_svc.ControlMetrics.assert_has_calls([m_call, m_call])

    def test_enable_control_metrics_no_port(self):
        mock_metrics_svc = self.netutils._conn.Msvm_MetricService()[0]
        self._mock_get_switch_port_alloc(found=False)

        self.netutils.enable_control_metrics(self._FAKE_PORT_NAME)
        self.assertEqual(0, mock_metrics_svc.ControlMetrics.call_count)

    def test_enable_control_metrics_no_def(self):
        mock_metrics_svc = self.netutils._conn.Msvm_MetricService()[0]
        mock_metrics_def_source = self.netutils._conn.CIM_BaseMetricDefinition

        self._mock_get_switch_port_alloc()
        mock_metrics_def_source.return_value = None

        self.netutils.enable_control_metrics(self._FAKE_PORT_NAME)
        self.assertEqual(0, mock_metrics_svc.ControlMetrics.call_count)

    @mock.patch.object(networkutils.NetworkUtils, '_is_port_vm_started')
    def test_can_enable_control_metrics_true(self, mock_is_started):
        mock_acl = mock.MagicMock()
        mock_acl.Action = self.netutils._ACL_ACTION_METER
        self._test_can_enable_control_metrics(mock_is_started,
                                              [mock_acl, mock_acl], True)

    @mock.patch.object(networkutils.NetworkUtils, '_is_port_vm_started')
    def test_can_enable_control_metrics_false(self, mock_is_started):
        self._test_can_enable_control_metrics(mock_is_started, [],
                                              False)

    def _test_can_enable_control_metrics(self, mock_vm_started, acls,
                                         expected_result):
        mock_port = self._mock_get_switch_port_alloc()
        mock_acl = mock.MagicMock()
        mock_acl.Action = self.netutils._ACL_ACTION_METER

        mock_port.associators.return_value = acls
        mock_vm_started.return_value = True

        result = self.netutils.can_enable_control_metrics(self._FAKE_PORT_NAME)
        self.assertEqual(expected_result, result)

    def test_is_port_vm_started_true(self):
        self._test_is_port_vm_started(self.netutils._HYPERV_VM_STATE_ENABLED,
                                      True)

    def test_is_port_vm_started_false(self):
        self._test_is_port_vm_started(self._FAKE_HYPERV_VM_STATE, False)

    def _test_is_port_vm_started(self, vm_state, expected_result):
        mock_svc = self.netutils._conn.Msvm_VirtualSystemManagementService()[0]
        mock_port = mock.MagicMock()
        mock_vmsettings = mock.MagicMock()
        mock_summary = mock.MagicMock()
        mock_summary.EnabledState = vm_state
        mock_vmsettings.path_.return_value = self._FAKE_RES_PATH

        mock_port.associators.return_value = [mock_vmsettings]
        mock_svc.GetSummaryInformation.return_value = (self._FAKE_RET_VAL,
                                                       [mock_summary])

        result = self.netutils._is_port_vm_started(mock_port)
        self.assertEqual(expected_result, result)
        mock_svc.GetSummaryInformation.assert_called_once_with(
            [self.netutils._VM_SUMMARY_ENABLED_STATE],
            [self._FAKE_RES_PATH])

    @mock.patch.object(networkutils.NetworkUtils, '_bind_security_rules')
    def test_create_security_rules(self, mock_bind):
        (m_port, m_acl) = self._setup_security_rule_test()
        fake_rule = mock.MagicMock()

        self.netutils.create_security_rules(self._FAKE_PORT_NAME, fake_rule)
        mock_bind.assert_called_once_with(m_port, fake_rule)

    @mock.patch.object(networkutils.NetworkUtils, '_create_security_acl')
    @mock.patch.object(networkutils.NetworkUtils, '_get_new_weights')
    @mock.patch.object(networkutils.NetworkUtils, '_filter_security_acls')
    def test_bind_security_rules(self, mock_filtered_acls, mock_get_weights,
                                 mock_create_acl):
        m_port = mock.MagicMock()
        m_acl = mock.MagicMock()
        m_port.associators.return_value = [m_acl]
        mock_filtered_acls.return_value = []
        mock_get_weights.return_value = [mock.sentinel.FAKE_WEIGHT]
        mock_create_acl.return_value = m_acl
        fake_rule = mock.MagicMock()

        self.netutils._bind_security_rules(m_port, [fake_rule])

        mock_create_acl.assert_called_once_with(fake_rule,
                                                mock.sentinel.FAKE_WEIGHT)
        mock_add_features = self.netutils._jobutils.add_multiple_virt_features
        mock_add_features.assert_called_once_with([m_acl], m_port)

    @mock.patch.object(networkutils.NetworkUtils, '_get_new_weights')
    @mock.patch.object(networkutils.NetworkUtils, '_filter_security_acls')
    def test_bind_security_rules_existent(self, mock_filtered_acls,
                                          mock_get_weights):
        m_port = mock.MagicMock()
        m_acl = mock.MagicMock()
        m_port.associators.return_value = [m_acl]
        mock_filtered_acls.return_value = [m_acl]
        fake_rule = mock.MagicMock()

        self.netutils._bind_security_rules(m_port, [fake_rule])
        mock_filtered_acls.assert_called_once_with(fake_rule, [m_acl])
        mock_get_weights.assert_called_once_with([fake_rule], [m_acl])

    @mock.patch.object(networkutils.NetworkUtils, '_filter_security_acls')
    def test_remove_security_rules(self, mock_filter):
        mock_acl = self._setup_security_rule_test()[1]
        fake_rule = mock.MagicMock()
        mock_filter.return_value = [mock_acl]

        self.netutils.remove_security_rules(self._FAKE_PORT_NAME, [fake_rule])

        mock_remove_features = (
            self.netutils._jobutils.remove_multiple_virt_features)
        mock_remove_features.assert_called_once_with([mock_acl])

    def test_remove_all_security_rules(self):
        mock_acl = self._setup_security_rule_test()[1]
        self.netutils.remove_all_security_rules(self._FAKE_PORT_NAME)
        mock_remove_features = (
            self.netutils._jobutils.remove_multiple_virt_features)
        mock_remove_features.assert_called_once_with([mock_acl])

    @mock.patch.object(networkutils.NetworkUtils,
                       '_get_default_setting_data')
    def test_create_security_acl(self, mock_get_set_data):
        mock_acl = mock_get_set_data.return_value
        fake_rule = mock.MagicMock()
        fake_rule.to_dict.return_value = {"Action": self._FAKE_ACL_ACT}

        self.netutils._create_security_acl(fake_rule, self._FAKE_WEIGHT)
        mock_acl.set.assert_called_once_with(Action=self._FAKE_ACL_ACT)

    def _setup_security_rule_test(self):
        mock_port = self._mock_get_switch_port_alloc()
        mock_acl = mock.MagicMock()
        mock_port.associators.return_value = [mock_acl]

        self.netutils._filter_security_acls = mock.MagicMock(
            return_value=[mock_acl])

        return (mock_port, mock_acl)

    def test_filter_acls(self):
        mock_acl = mock.MagicMock()
        mock_acl.Action = self._FAKE_ACL_ACT
        mock_acl.Applicability = self.netutils._ACL_APPLICABILITY_LOCAL
        mock_acl.Direction = self._FAKE_ACL_DIR
        mock_acl.AclType = self._FAKE_ACL_TYPE
        mock_acl.RemoteAddress = self._FAKE_REMOTE_ADDR

        acls = [mock_acl, mock_acl]
        good_acls = self.netutils._filter_acls(
            acls, self._FAKE_ACL_ACT, self._FAKE_ACL_DIR,
            self._FAKE_ACL_TYPE, self._FAKE_REMOTE_ADDR)
        bad_acls = self.netutils._filter_acls(
            acls, self._FAKE_ACL_ACT, self._FAKE_ACL_DIR, self._FAKE_ACL_TYPE)

        self.assertEqual(acls, good_acls)
        self.assertEqual([], bad_acls)

    def test_get_new_weights_allow(self):
        actual = self.netutils._get_new_weights([mock.ANY, mock.ANY], mock.ANY)
        self.assertEqual([0, 0], actual)


class TestNetworkUtilsR2(base.BaseTestCase):

    def setUp(self):
        super(TestNetworkUtilsR2, self).setUp()
        self.netutils = networkutils.NetworkUtilsR2()

    @mock.patch.object(networkutils.NetworkUtilsR2,
                       '_get_default_setting_data')
    def test_create_security_acl(self, mock_get_default_setting_data):
        sg_rule = mock.MagicMock()
        sg_rule.to_dict.return_value = {}

        acl = self.netutils._create_security_acl(sg_rule, mock.sentinel.weight)

        self.assertEqual(mock.sentinel.weight, acl.Weight)

    def test_get_new_weights_no_acls_deny(self):
        mock_rule = mock.MagicMock(Action=self.netutils._ACL_ACTION_DENY)
        actual = self.netutils._get_new_weights([mock_rule], [])
        self.assertEqual([1], actual)

    def test_get_new_weights_no_acls_allow(self):
        mock_rule = mock.MagicMock(Action=self.netutils._ACL_ACTION_ALLOW)
        actual = self.netutils._get_new_weights([mock_rule, mock_rule], [])

        expected = [self.netutils._MAX_WEIGHT - 1,
                    self.netutils._MAX_WEIGHT - 2]
        self.assertEqual(expected, actual)

    def test_get_new_weights_deny(self):
        mock_rule = mock.MagicMock(Action=self.netutils._ACL_ACTION_DENY)
        mockacl1 = mock.MagicMock(Action=self.netutils._ACL_ACTION_DENY,
                                  Weight=1)
        mockacl2 = mock.MagicMock(Action=self.netutils._ACL_ACTION_DENY,
                                  Weight=3)

        actual = self.netutils._get_new_weights([mock_rule, mock_rule],
                                                [mockacl1, mockacl2])

        self.assertEqual([2, 4], actual)

    def test_get_new_weights_allow(self):
        mock_rule = mock.MagicMock(Action=self.netutils._ACL_ACTION_ALLOW)
        mockacl = mock.MagicMock(Action=self.netutils._ACL_ACTION_ALLOW,
                                 Weight=self.netutils._MAX_WEIGHT - 3)

        actual = self.netutils._get_new_weights([mock_rule, mock_rule],
                                                [mockacl])

        expected = [self.netutils._MAX_WEIGHT - 4,
                    self.netutils._MAX_WEIGHT - 5]
        self.assertEqual(expected, actual)

    def test_get_new_weights_search_available(self):
        mock_rule = mock.MagicMock(Action=self.netutils._ACL_ACTION_ALLOW)
        mockacl1 = mock.MagicMock(Action=self.netutils._ACL_ACTION_ALLOW,
                                  Weight=self.netutils._REJECT_ACLS_COUNT + 1)
        mockacl2 = mock.MagicMock(Action=self.netutils._ACL_ACTION_ALLOW,
                                  Weight=self.netutils._MAX_WEIGHT - 1)

        actual = self.netutils._get_new_weights([mock_rule],
                                                [mockacl1, mockacl2])

        self.assertEqual([self.netutils._MAX_WEIGHT - 2], actual)
