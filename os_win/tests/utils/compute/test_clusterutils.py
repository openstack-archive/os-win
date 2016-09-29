# Copyright 2016 Cloudbase Solutions Srl
# All Rights Reserved.
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

import ddt
import mock

from os_win import constants
from os_win import exceptions
from os_win.tests import test_base
from os_win.utils.compute import _clusapi_utils
from os_win.utils.compute import clusterutils


@ddt.ddt
class ClusterUtilsTestCase(test_base.OsWinBaseTestCase):
    """Unit tests for the Hyper-V ClusterUtilsBase class."""

    _FAKE_RES_NAME = "fake_res_name"
    _FAKE_HOST = "fake_host"
    _FAKE_PREV_HOST = "fake_prev_host"
    _FAKE_VM_NAME = 'instance-00000001'
    _FAKE_RESOURCEGROUP_NAME = 'Virtual Machine %s' % _FAKE_VM_NAME

    def setUp(self):
        super(ClusterUtilsTestCase, self).setUp()
        self._clusterutils = clusterutils.ClusterUtils()
        self._clusterutils._conn_cluster = mock.MagicMock()
        self._clusterutils._cluster = mock.MagicMock()
        self._clusterutils._clusapi_utils = mock.Mock()
        self._clusapi = self._clusterutils._clusapi_utils

    def test_init_hyperv_conn(self):
        fake_cluster_name = "fake_cluster"
        mock_cluster = mock.MagicMock()
        mock_cluster.path_.return_value = r"\\%s\root" % fake_cluster_name

        mock_conn = mock.MagicMock()
        mock_conn.MSCluster_Cluster.return_value = [mock_cluster]

        self._clusterutils._get_wmi_conn = mock.MagicMock()
        self._clusterutils._get_wmi_conn.return_value = mock_conn

        self._clusterutils._init_hyperv_conn("fake_host")

    def test_init_hyperv_conn_exception(self):
        self._clusterutils._get_wmi_conn = mock.MagicMock()
        self._clusterutils._get_wmi_conn.side_effect = AttributeError
        self.assertRaises(exceptions.HyperVClusterException,
                          self._clusterutils._init_hyperv_conn, "fake_host")

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_get_cluster_nodes')
    def test_check_cluster_state_not_enough_nodes(self, mock_get_nodes):
        self.assertRaises(exceptions.HyperVClusterException,
                          self._clusterutils.check_cluster_state)

    def test_get_node_name(self):
        self._clusterutils._this_node = mock.sentinel.fake_node_name
        self.assertEqual(mock.sentinel.fake_node_name,
                         self._clusterutils.get_node_name())

    def test_get_cluster_nodes(self):
        fake_node1 = mock.MagicMock(Dependent=mock.sentinel.cluster_node1)
        fake_node2 = mock.MagicMock(Dependent=mock.sentinel.cluster_node2)
        node_list = [fake_node1, fake_node2]
        expected = [mock.sentinel.cluster_node1, mock.sentinel.cluster_node2]
        fake_class = self._clusterutils._conn_cluster.MSCluster_ClusterToNode
        fake_class.return_value = node_list

        self.assertEqual(expected, self._clusterutils._get_cluster_nodes())

    def test_get_vm_groups(self):
        vm_gr1 = mock.MagicMock(GroupType=self._clusterutils._VM_GROUP_TYPE)
        vm_gr2 = mock.MagicMock()
        vm_gr3 = mock.MagicMock(GroupType=self._clusterutils._VM_GROUP_TYPE)

        fake_assoc1 = mock.MagicMock(PartComponent=vm_gr1)
        fake_assoc2 = mock.MagicMock(PartComponent=vm_gr2)
        fake_assoc3 = mock.MagicMock(PartComponent=vm_gr3)

        assoc_list = [fake_assoc1, fake_assoc2, fake_assoc3]
        fake_conn = self._clusterutils._conn_cluster
        fake_conn.MSCluster_ClusterToResourceGroup.return_value = assoc_list

        res = list(self._clusterutils._get_vm_groups())

        self.assertIn(vm_gr1, res)
        self.assertNotIn(vm_gr2, res)
        self.assertIn(vm_gr3, res)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_vm_group')
    def test_lookup_vm_group_check(self, mock_lookup_vm_group):
        mock_lookup_vm_group.return_value = mock.sentinel.fake_vm

        ret = self._clusterutils._lookup_vm_group_check(
            self._FAKE_VM_NAME)
        self.assertEqual(mock.sentinel.fake_vm, ret)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_vm_group')
    def test_lookup_vm_group_check_no_vm(self, mock_lookup_vm_group):
        mock_lookup_vm_group.return_value = None

        self.assertRaises(exceptions.HyperVVMNotFoundException,
                          self._clusterutils._lookup_vm_group_check,
                          self._FAKE_VM_NAME)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_res')
    def test_lookup_vm_group(self, mock_lookup_res):
        self._clusterutils._lookup_vm_group(self._FAKE_VM_NAME)
        mock_lookup_res.assert_called_once_with(
            self._clusterutils._conn_cluster.MSCluster_ResourceGroup,
            self._FAKE_VM_NAME)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_vm')
    def test_lookup_vm_check(self, mock_lookup_vm):
        mock_lookup_vm.return_value = mock.sentinel.fake_vm

        ret = self._clusterutils._lookup_vm_check(
            self._FAKE_VM_NAME)
        self.assertEqual(mock.sentinel.fake_vm, ret)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_vm')
    def test_lookup_vm_check_no_vm(self, mock_lookup_vm):
        mock_lookup_vm.return_value = None

        self.assertRaises(exceptions.HyperVVMNotFoundException,
                          self._clusterutils._lookup_vm_check,
                          self._FAKE_VM_NAME)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_res')
    def test_lookup_vm(self, mock_lookup_res):
        self._clusterutils._lookup_vm(self._FAKE_VM_NAME)
        mock_lookup_res.assert_called_once_with(
            self._clusterutils._conn_cluster.MSCluster_Resource,
            self._clusterutils._VM_BASE_NAME % self._FAKE_VM_NAME)

    def test_lookup_res_no_res(self):
        res_list = []
        resource_source = mock.MagicMock()
        resource_source.return_value = res_list

        self.assertIsNone(
            self._clusterutils._lookup_res(resource_source,
                                           self._FAKE_RES_NAME))
        resource_source.assert_called_once_with(
            Name=self._FAKE_RES_NAME)

    def test_lookup_res_duplicate_res(self):
        res_list = [mock.sentinel.r1,
                    mock.sentinel.r1]
        resource_source = mock.MagicMock()
        resource_source.return_value = res_list

        self.assertRaises(exceptions.HyperVClusterException,
                          self._clusterutils._lookup_res,
                          resource_source,
                          self._FAKE_RES_NAME)
        resource_source.assert_called_once_with(
            Name=self._FAKE_RES_NAME)

    def test_lookup_res(self):
        res_list = [mock.sentinel.r1]
        resource_source = mock.MagicMock()
        resource_source.return_value = res_list

        self.assertEqual(
            mock.sentinel.r1,
            self._clusterutils._lookup_res(resource_source,
                                           self._FAKE_RES_NAME))
        resource_source.assert_called_once_with(
            Name=self._FAKE_RES_NAME)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_get_cluster_nodes')
    def test_get_cluster_node_names(self, mock_get_cluster_nodes):
        cluster_nodes = [mock.Mock(Name='node1'),
                         mock.Mock(Name='node2')]
        mock_get_cluster_nodes.return_value = cluster_nodes

        ret = self._clusterutils.get_cluster_node_names()

        self.assertItemsEqual(['node1', 'node2'], ret)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_vm_group_check')
    def test_get_vm_host(self, mock_lookup_vm_group_check):
        owner_node = "fake_owner_node"
        vm = mock.Mock(OwnerNode=owner_node)
        mock_lookup_vm_group_check.return_value = vm

        self.assertEqual(
            owner_node,
            self._clusterutils.get_vm_host(self._FAKE_VM_NAME))

    @mock.patch.object(clusterutils.ClusterUtils, '_get_vm_groups')
    def test_list_instances(self, mock_get_vm_groups):
        mock_get_vm_groups.return_value = [mock.Mock(Name='vm1'),
                                           mock.Mock(Name='vm2')]
        ret = self._clusterutils.list_instances()
        self.assertItemsEqual(['vm1', 'vm2'], ret)

    @mock.patch.object(clusterutils.ClusterUtils, '_get_vm_groups')
    def test_list_instance_uuids(self, mock_get_vm_groups):
        mock_get_vm_groups.return_value = [mock.Mock(Id='uuid1'),
                                           mock.Mock(Id='uuid2')]
        ret = self._clusterutils.list_instance_uuids()
        self.assertItemsEqual(['uuid1', 'uuid2'], ret)

    @mock.patch.object(clusterutils.ClusterUtils,
                       '_lookup_vm_group_check')
    def test_add_vm_to_cluster(self, mock_lookup_vm_group_check):
        self._clusterutils._cluster.AddVirtualMachine = mock.MagicMock()
        vm_group = mock.Mock()
        mock_lookup_vm_group_check.return_value = vm_group

        self._clusterutils.add_vm_to_cluster(self._FAKE_VM_NAME)

        self.assertTrue(vm_group.PersistentState)
        self.assertEqual(vm_group.AutoFailbackType,
                         self._clusterutils._FAILBACK_TRUE)
        self.assertEqual(vm_group.FailbackWindowStart,
                         self._clusterutils._FAILBACK_WINDOW_MIN)
        self.assertEqual(vm_group.FailbackWindowEnd,
                         self._clusterutils._FAILBACK_WINDOW_MAX)
        vm_group.put.assert_called_once_with()

    @mock.patch.object(clusterutils.ClusterUtils, '_lookup_vm_check')
    def test_bring_online(self, mock_lookup_vm_check):
        vm = mock.MagicMock()
        mock_lookup_vm_check.return_value = vm

        self._clusterutils.bring_online(self._FAKE_VM_NAME)
        vm.BringOnline.assert_called_once_with()

    @mock.patch.object(clusterutils.ClusterUtils, '_lookup_vm')
    def test_take_offline(self, mock_lookup_vm):
        vm = mock.MagicMock()
        mock_lookup_vm.return_value = vm

        self._clusterutils.take_offline(self._FAKE_VM_NAME)
        vm.TakeOffline.assert_called_once_with()

    @mock.patch.object(clusterutils.ClusterUtils, '_lookup_vm_group')
    def test_delete(self, mock_lookup_vm_group):
        vm = mock.MagicMock()
        mock_lookup_vm_group.return_value = vm

        self._clusterutils.delete(self._FAKE_VM_NAME)
        vm.DestroyGroup.assert_called_once_with(
            self._clusterutils._DESTROY_GROUP)

    @mock.patch.object(clusterutils.ClusterUtils, '_lookup_vm')
    def test_vm_exists_true(self, mock_lookup_vm):
        vm = mock.MagicMock()
        mock_lookup_vm.return_value = vm

        self.assertTrue(self._clusterutils.vm_exists(self._FAKE_VM_NAME))

    @mock.patch.object(clusterutils.ClusterUtils, '_lookup_vm')
    def test_vm_exists_false(self, mock_lookup_vm):
        mock_lookup_vm.return_value = None

        self.assertFalse(self._clusterutils.vm_exists(self._FAKE_VM_NAME))

    @mock.patch.object(clusterutils.ClusterUtils, '_migrate_vm')
    def test_live_migrate_vm(self, mock_migrate_vm):
        self._clusterutils.live_migrate_vm(self._FAKE_VM_NAME,
                                           self._FAKE_HOST,
                                           mock.sentinel.timeout)

        exp_valid_transition_states = [constants.CLUSTER_GROUP_PENDING]
        mock_migrate_vm.assert_called_once_with(
            self._FAKE_VM_NAME, self._FAKE_HOST,
            self._clusterutils._LIVE_MIGRATION_TYPE,
            constants.CLUSTER_GROUP_ONLINE,
            exp_valid_transition_states,
            mock.sentinel.timeout)

    @mock.patch.object(_clusapi_utils, 'DWORD')
    @mock.patch.object(clusterutils.ClusterUtils,
                       '_wait_for_cluster_group_state')
    @ddt.data(None, exceptions.ClusterException)
    def test_migrate_vm(self, raised_exc, mock_wait_group, mock_dword):
        mock_wait_group.side_effect = raised_exc

        migrate_args = (self._FAKE_VM_NAME,
                        self._FAKE_HOST,
                        self._clusterutils._LIVE_MIGRATION_TYPE,
                        constants.CLUSTER_GROUP_ONLINE,
                        mock.sentinel.valid_transition_states,
                        mock.sentinel.timeout)

        if raised_exc:
            self.assertRaises(raised_exc,
                              self._clusterutils._migrate_vm,
                              *migrate_args)
        else:
            self._clusterutils._migrate_vm(*migrate_args)

        mock_dword.assert_called_once_with(
            self._clusterutils._LIVE_MIGRATION_TYPE)

        self._clusapi.get_property_list_entry.assert_has_calls(
            [mock.call(prop_name,
                       _clusapi_utils.CLUSPROP_SYNTAX_LIST_VALUE_DWORD,
                       mock_dword.return_value)
             for prop_name in (_clusapi_utils.CLUSPROP_NAME_VM,
                               _clusapi_utils.CLUSPROP_NAME_VM_CONFIG)])

        expected_prop_entries = [
            self._clusapi.get_property_list_entry.return_value] * 2
        self._clusapi.get_property_list.assert_called_once_with(
            expected_prop_entries)

        expected_migrate_flags = (
            _clusapi_utils.CLUSAPI_GROUP_MOVE_RETURN_TO_SOURCE_NODE_ON_ERROR |
            _clusapi_utils.CLUSAPI_GROUP_MOVE_QUEUE_ENABLED |
            _clusapi_utils.CLUSAPI_GROUP_MOVE_HIGH_PRIORITY_START)

        exp_clus_h = self._clusapi.open_cluster.return_value
        exp_clus_node_h = self._clusapi.open_cluster_node.return_value
        exp_clus_group_h = self._clusapi.open_cluster_group.return_value

        self._clusapi.open_cluster.assert_called_once_with()
        self._clusapi.open_cluster_group.assert_called_once_with(
            exp_clus_h, self._FAKE_VM_NAME)
        self._clusapi.open_cluster_node.assert_called_once_with(
            exp_clus_h, self._FAKE_HOST)

        self._clusapi.move_cluster_group.assert_called_once_with(
            exp_clus_group_h, exp_clus_node_h, expected_migrate_flags,
            self._clusapi.get_property_list.return_value)

        mock_wait_group.assert_called_once_with(
            self._FAKE_VM_NAME, exp_clus_group_h,
            constants.CLUSTER_GROUP_ONLINE,
            self._FAKE_HOST,
            mock.sentinel.valid_transition_states,
            mock.sentinel.timeout)

        self._clusapi.close_cluster_group.assert_called_once_with(
            exp_clus_group_h)
        self._clusapi.close_cluster_node.assert_called_once_with(
            exp_clus_node_h)
        self._clusapi.close_cluster.assert_called_once_with(exp_clus_h)

    @mock.patch.object(clusterutils._utils, 'time')
    def test_wait_for_clus_group_state_failed(self, mock_time):
        desired_host = self._FAKE_HOST
        desired_state = constants.CLUSTER_GROUP_ONLINE
        valid_transition_states = [constants.CLUSTER_GROUP_PENDING]

        group_states = [dict(owner_node=desired_host,
                             state=constants.CLUSTER_GROUP_PENDING),
                        dict(owner_node=desired_host,
                             state=constants.CLUSTER_GROUP_FAILED)]
        self._clusapi.get_cluster_group_state.side_effect = group_states

        # We don't want a timeout to be raised. We expect the tested
        # function to force breaking the retry loop when the cluster
        # group gets into a 'failed' state.
        #
        # As a precaution measure, we're still forcing a timeout at
        # some point, to avoid an infinite loop if something goes wrong.
        mock_time.time.side_effect = [0] * 10 + [100]

        self.assertRaises(exceptions.InvalidClusterGroupState,
                          self._clusterutils._wait_for_cluster_group_state,
                          mock.sentinel.group_name,
                          mock.sentinel.group_handle,
                          desired_state,
                          desired_host,
                          valid_transition_states,
                          timeout=10)

        self._clusapi.get_cluster_group_state.assert_has_calls(
            [mock.call(mock.sentinel.group_handle)] * len(group_states))

    @mock.patch.object(clusterutils._utils, 'time')
    def test_wait_for_clus_group_state_success(self, mock_time):
        desired_host = self._FAKE_HOST
        desired_state = constants.CLUSTER_GROUP_ONLINE

        group_state = dict(owner_node=desired_host.upper(),
                           state=desired_state)
        self._clusapi.get_cluster_group_state.return_value = group_state

        self._clusterutils._wait_for_cluster_group_state(
            mock.sentinel.group_name,
            mock.sentinel.group_handle,
            desired_state,
            desired_host,
            [],
            timeout=10)

        self._clusapi.get_cluster_group_state.assert_called_once_with(
            mock.sentinel.group_handle)

    @mock.patch.object(clusterutils, 'tpool')
    @mock.patch.object(clusterutils, 'patcher')
    def test_monitor_vm_failover_no_vm(self, mock_patcher, mock_tpool):
        self._clusterutils._watcher = mock.MagicMock()
        fake_prev = mock.MagicMock(OwnerNode=self._FAKE_PREV_HOST)
        fake_wmi_object = mock.MagicMock(OwnerNode=self._FAKE_HOST,
                                         Name='Virtual Machine',
                                         previous=fake_prev)
        mock_tpool.execute.return_value = fake_wmi_object
        fake_callback = mock.MagicMock()

        self._clusterutils.monitor_vm_failover(fake_callback)

        mock_tpool.execute.assert_called_once_with(
            self._clusterutils._watcher,
            self._clusterutils._WMI_EVENT_TIMEOUT_MS)
        fake_callback.assert_not_called()

    @mock.patch.object(clusterutils, 'tpool')
    @mock.patch.object(clusterutils, 'patcher')
    def test_monitor_vm_failover(self, mock_patcher, mock_tpool):
        self._clusterutils._watcher = mock.MagicMock()
        fake_prev = mock.MagicMock(OwnerNode=self._FAKE_PREV_HOST)
        fake_wmi_object = mock.MagicMock(OwnerNode=self._FAKE_HOST,
                                         Name=self._FAKE_RESOURCEGROUP_NAME,
                                         previous=fake_prev)
        mock_tpool.execute.return_value = fake_wmi_object
        fake_callback = mock.MagicMock()

        self._clusterutils.monitor_vm_failover(fake_callback)

        mock_tpool.execute.assert_called_once_with(
            self._clusterutils._watcher,
            self._clusterutils._WMI_EVENT_TIMEOUT_MS)
        fake_callback.assert_called_once_with(self._FAKE_VM_NAME,
                                              self._FAKE_PREV_HOST,
                                              self._FAKE_HOST)
