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

"""
Utility class for VM related operations on Hyper-V Clusters.
"""

import re
import sys

if sys.platform == 'win32':
    import wmi

from eventlet import patcher
from eventlet import tpool
from oslo_log import log as logging

from os_win._i18n import _, _LE
from os_win import exceptions
from os_win.utils import baseutils


LOG = logging.getLogger(__name__)


class ClusterUtils(baseutils.BaseUtils):

    _MSCLUSTER_NODE = 'MSCluster_Node'
    _MSCLUSTER_RES = 'MSCluster_Resource'

    _VM_BASE_NAME = 'Virtual Machine %s'
    _VM_TYPE = 'Virtual Machine'
    _VM_GROUP_TYPE = 111

    _MS_CLUSTER_NAMESPACE = '//%s/root/MSCluster'

    _LIVE_MIGRATION_TYPE = 4
    _IGNORE_LOCKED = 1
    _DESTROY_GROUP = 1

    _FAILBACK_TRUE = 1
    _FAILBACK_WINDOW_MIN = 0
    _FAILBACK_WINDOW_MAX = 23

    _WMI_EVENT_TIMEOUT_MS = 100
    _WMI_EVENT_CHECK_INTERVAL = 2

    def __init__(self, host='.'):
        self._instance_name_regex = re.compile('Virtual Machine (.*)')

        if sys.platform == 'win32':
            self._init_hyperv_conn(host)
            self._watcher = self._get_failover_watcher()

    def _init_hyperv_conn(self, host):
        try:
            self._conn_cluster = self._get_wmi_conn(
                self._MS_CLUSTER_NAMESPACE % host)
            self._cluster = self._conn_cluster.MSCluster_Cluster()[0]

            # extract this node name from cluster's path
            path = self._cluster.path_()
            self._this_node = re.search(r'\\\\(.*)\\root', path,
                                        re.IGNORECASE).group(1)
        except AttributeError:
            raise exceptions.HyperVClusterException(
                _("Could not initialize cluster wmi connection."))

    def _get_failover_watcher(self):
        raw_query = (
                "SELECT * FROM __InstanceModificationEvent "
                "WITHIN %(wmi_check_interv)s WHERE TargetInstance ISA "
                "'%(cluster_res)s' AND "
                "TargetInstance.Type='%(cluster_res_type)s' AND "
                "TargetInstance.OwnerNode != PreviousInstance.OwnerNode" %
                {'wmi_check_interv': self._WMI_EVENT_CHECK_INTERVAL,
                 'cluster_res': self._MSCLUSTER_RES,
                 'cluster_res_type': self._VM_TYPE})
        return self._conn_cluster.watch_for(raw_wql=raw_query)

    def check_cluster_state(self):
        if len(self._get_cluster_nodes()) < 1:
            raise exceptions.HyperVClusterException(
                _("Not enough cluster nodes."))

    def get_node_name(self):
        return self._this_node

    def _get_cluster_nodes(self):
        cluster_assoc = self._conn_cluster.MSCluster_ClusterToNode(
            Antecedent=self._cluster.path_())
        return [x.Dependent for x in cluster_assoc]

    def _get_vm_groups(self):
        assocs = self._conn_cluster.MSCluster_ClusterToResourceGroup(
            GroupComponent=self._cluster.path_())
        resources = [a.PartComponent for a in assocs]
        return (r for r in resources if
                hasattr(r, 'GroupType') and
                r.GroupType == self._VM_GROUP_TYPE)

    def _lookup_vm_group_check(self, vm_name):
        vm = self._lookup_vm_group(vm_name)
        if not vm:
            raise exceptions.HyperVVMNotFoundException(vm_name=vm_name)
        return vm

    def _lookup_vm_group(self, vm_name):
        return self._lookup_res(self._conn_cluster.MSCluster_ResourceGroup,
                                vm_name)

    def _lookup_vm_check(self, vm_name):
        vm = self._lookup_vm(vm_name)
        if not vm:
            raise exceptions.HyperVVMNotFoundException(vm_name=vm_name)
        return vm

    def _lookup_vm(self, vm_name):
        vm_name = self._VM_BASE_NAME % vm_name
        return self._lookup_res(self._conn_cluster.MSCluster_Resource, vm_name)

    def _lookup_res(self, resource_source, res_name):
        res = resource_source(Name=res_name)
        n = len(res)
        if n == 0:
            return None
        elif n > 1:
            raise exceptions.HyperVClusterException(
                _('Duplicate resource name %s found.') % res_name)
        else:
            return res[0]

    def get_cluster_node_names(self):
        nodes = self._get_cluster_nodes()
        return [n.Name for n in nodes]

    def get_vm_host(self, vm_name):
        return self._lookup_vm_group_check(vm_name).OwnerNode

    def list_instances(self):
        return [r.Name for r in self._get_vm_groups()]

    def list_instance_uuids(self):
        return [r.Id for r in self._get_vm_groups()]

    def add_vm_to_cluster(self, vm_name):
        LOG.debug("Add vm to cluster called for vm %s" % vm_name)
        self._cluster.AddVirtualMachine(vm_name)

        vm_group = self._lookup_vm_group_check(vm_name)
        vm_group.PersistentState = True
        vm_group.AutoFailbackType = self._FAILBACK_TRUE
        # set the earliest and latest time that the group can be moved
        # back to its preferred node. The unit is in hours.
        vm_group.FailbackWindowStart = self._FAILBACK_WINDOW_MIN
        vm_group.FailbackWindowEnd = self._FAILBACK_WINDOW_MAX
        vm_group.put()

    def bring_online(self, vm_name):
        vm = self._lookup_vm_check(vm_name)
        vm.BringOnline()

    def take_offline(self, vm_name):
        vm = self._lookup_vm_check(vm_name)
        vm.TakeOffline()

    def delete(self, vm_name):
        vm = self._lookup_vm_group_check(vm_name)
        vm.DestroyGroup(self._DESTROY_GROUP)

    def vm_exists(self, vm_name):
        return self._lookup_vm(vm_name) is not None

    def live_migrate_vm(self, vm_name, new_host):
        self._migrate_vm(vm_name, new_host, self._LIVE_MIGRATION_TYPE)

    def _migrate_vm(self, vm_name, new_host, migration_type):
        vm_group = self._lookup_vm_group_check(vm_name)
        try:
            vm_group.MoveToNewNodeParams(self._IGNORE_LOCKED, new_host,
                                         [migration_type])
        except Exception as e:
            LOG.error(_LE('Exception during cluster live migration of '
                          '%(vm_name)s to %(host)s: %(exception)s'),
                          {'vm_name': vm_name,
                           'host': new_host,
                           'exception': e})

    def monitor_vm_failover(self, callback):
        """Creates a monitor to check for new WMI MSCluster_Resource
        events.

        This method will poll the last _WMI_EVENT_CHECK_INTERVAL + 1
        seconds for new events and listens for _WMI_EVENT_TIMEOUT_MS
        miliseconds, since listening is a thread blocking action.

        Any event object caught will then be processed.
        """
        vm_name = None
        new_host = None
        try:
            # wait for new event for _WMI_EVENT_TIMEOUT_MS miliseconds.
            if patcher.is_monkey_patched('thread'):
                wmi_object = tpool.execute(self._watcher,
                                           self._WMI_EVENT_TIMEOUT_MS)
            else:
                wmi_object = self._watcher(self._WMI_EVENT_TIMEOUT_MS)

            old_host = wmi_object.previous.OwnerNode
            new_host = wmi_object.OwnerNode
            # wmi_object.Name field is of the form:
            # 'Virtual Machine nova-instance-template'
            # wmi_object.Name filed is a key and as such is not affected
            # by locale, so it will always be 'Virtual Machine'
            match = self._instance_name_regex.search(wmi_object.Name)
            if match:
                vm_name = match.group(1)

            if vm_name:
                try:
                    callback(vm_name, old_host, new_host)
                except Exception:
                    LOG.exception(
                        _LE("Exception during failover callback."))
        except wmi.x_wmi_timed_out:
            pass
