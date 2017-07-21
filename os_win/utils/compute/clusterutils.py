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

import ctypes
import re
import sys
import threading
import time

from eventlet import patcher
from eventlet import tpool
from oslo_log import log as logging
from oslo_utils import excutils
from six.moves import queue

from os_win._i18n import _
from os_win import _utils
from os_win import constants
from os_win import exceptions
from os_win.utils import baseutils
from os_win.utils.compute import _clusapi_utils
from os_win.utils.winapi import constants as w_const
from os_win.utils.winapi.libs import clusapi as clusapi_def
from os_win.utils.winapi import wintypes

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

    _FAILBACK_WINDOW_MIN = 0
    _FAILBACK_WINDOW_MAX = 23

    _WMI_EVENT_TIMEOUT_MS = 100
    _WMI_EVENT_CHECK_INTERVAL = 2

    def __init__(self, host='.'):
        self._instance_name_regex = re.compile('Virtual Machine (.*)')
        self._clusapi_utils = _clusapi_utils.ClusApiUtils()

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
        raw_query = ("SELECT * FROM __InstanceModificationEvent "
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

    def add_vm_to_cluster(self, vm_name, max_failover_count=1,
                          failover_period=6, auto_failback=True):
        """Adds the VM to the Hyper-V Cluster.

        :param vm_name: The name of the VM to be added to the Hyper-V Cluster
        :param max_failover_count: The number of times the Hyper-V Cluster will
            try to failover the VM within the given failover period. If the VM
            will try to failover more than this number of the given
            failover_period, the VM will end up in a failed state.
        :param failover_period: The period (hours) over which the given
            max_failover_count failovers can occur. After this period expired,
            the failover count for the given VM is reset.
        :param auto_failback: boolean, whether the VM will be allowed to
            move back to its original host when it is available again.
        """
        LOG.debug("Add vm to cluster called for vm %s" % vm_name)
        self._cluster.AddVirtualMachine(vm_name)

        vm_group = self._lookup_vm_group_check(vm_name)
        vm_group.FailoverThreshold = max_failover_count
        vm_group.FailoverPeriod = failover_period
        vm_group.PersistentState = True
        vm_group.AutoFailbackType = int(bool(auto_failback))
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

    def live_migrate_vm(self, vm_name, new_host, timeout=None):
        self._migrate_vm(vm_name, new_host, self._LIVE_MIGRATION_TYPE,
                         constants.CLUSTER_GROUP_ONLINE,
                         timeout)

    def _migrate_vm(self, vm_name, new_host, migration_type,
                    exp_state_after_migr, timeout):
        syntax = w_const.CLUSPROP_SYNTAX_LIST_VALUE_DWORD
        migr_type = wintypes.DWORD(migration_type)

        prop_entries = [
            self._clusapi_utils.get_property_list_entry(
                w_const.CLUS_RESTYPE_NAME_VM, syntax, migr_type),
            self._clusapi_utils.get_property_list_entry(
                w_const.CLUS_RESTYPE_NAME_VM_CONFIG, syntax, migr_type)
        ]
        prop_list = self._clusapi_utils.get_property_list(prop_entries)

        flags = (
            w_const.CLUSAPI_GROUP_MOVE_RETURN_TO_SOURCE_NODE_ON_ERROR |
            w_const.CLUSAPI_GROUP_MOVE_QUEUE_ENABLED |
            w_const.CLUSAPI_GROUP_MOVE_HIGH_PRIORITY_START)

        cluster_handle = None
        group_handle = None
        dest_node_handle = None

        try:
            cluster_handle = self._clusapi_utils.open_cluster()
            group_handle = self._clusapi_utils.open_cluster_group(
                cluster_handle, vm_name)
            dest_node_handle = self._clusapi_utils.open_cluster_node(
                cluster_handle, new_host)

            with _ClusterGroupStateChangeListener(cluster_handle,
                                                  vm_name) as listener:
                self._clusapi_utils.move_cluster_group(group_handle,
                                                       dest_node_handle,
                                                       flags,
                                                       prop_list)
                try:
                    self._wait_for_cluster_group_migration(
                        listener,
                        vm_name,
                        group_handle,
                        exp_state_after_migr,
                        timeout)
                except exceptions.ClusterGroupMigrationTimeOut:
                    with excutils.save_and_reraise_exception() as ctxt:
                        self._cancel_cluster_group_migration(
                            listener, vm_name, group_handle,
                            exp_state_after_migr, timeout)

                        # This is rather unlikely to happen but we're
                        # covering it out.
                        try:
                            self._validate_migration(group_handle,
                                                     vm_name,
                                                     exp_state_after_migr,
                                                     new_host)
                            LOG.warning(
                                'Cluster group migration completed '
                                'successfuly after cancel attempt. '
                                'Suppressing timeout exception.')
                            ctxt.reraise = False
                        except exceptions.ClusterGroupMigrationFailed:
                            pass
                else:
                    self._validate_migration(group_handle,
                                             vm_name,
                                             exp_state_after_migr,
                                             new_host)
        finally:
            if group_handle:
                self._clusapi_utils.close_cluster_group(group_handle)
            if dest_node_handle:
                self._clusapi_utils.close_cluster_node(dest_node_handle)
            if cluster_handle:
                self._clusapi_utils.close_cluster(cluster_handle)

    def _validate_migration(self, group_handle, group_name,
                            expected_state, expected_node):
        state_info = self._clusapi_utils.get_cluster_group_state(group_handle)
        owner_node = state_info['owner_node']
        group_state = state_info['state']

        if (expected_state != group_state or
                expected_node.lower() != owner_node.lower()):
            raise exceptions.ClusterGroupMigrationFailed(
                group_name=group_name,
                expected_state=expected_state,
                expected_node=expected_node,
                group_state=group_state,
                owner_node=owner_node)

    def cancel_cluster_group_migration(self, group_name, expected_state,
                                       timeout=None):
        cluster_handle = None
        group_handle = None

        try:
            cluster_handle = self._clusapi_utils.open_cluster()
            group_handle = self._clusapi_utils.open_cluster_group(
                cluster_handle, group_name)

            with _ClusterGroupStateChangeListener(cluster_handle,
                                                  group_name) as listener:
                self._cancel_cluster_group_migration(
                    listener, group_name, group_handle,
                    expected_state, timeout)
        finally:
            if group_handle:
                self._clusapi_utils.close_cluster_group(group_handle)
            if cluster_handle:
                self._clusapi_utils.close_cluster(cluster_handle)

    def _cancel_cluster_group_migration(self, event_listener,
                                        group_name, group_handle,
                                        expected_state,
                                        timeout=None):
        LOG.info("Canceling cluster group '%s' migration", group_name)
        try:
            cancel_finished = (
                self._clusapi_utils.cancel_cluster_group_operation(
                    group_handle))
        except exceptions.Win32Exception as ex:
            group_state_info = self._get_cluster_group_state(group_handle)
            migration_pending = self._is_migration_pending(
                group_state_info['state'],
                group_state_info['status_info'],
                expected_state)

            if (ex.error_code == w_const.ERROR_INVALID_STATE and
                    not migration_pending):
                LOG.debug('Ignoring group migration cancel error. '
                          'No migration is pending.')
                cancel_finished = True
            else:
                raise

        if not cancel_finished:
            LOG.debug("Waiting for group migration to be canceled.")
            try:
                self._wait_for_cluster_group_migration(
                    event_listener, group_name, group_handle,
                    expected_state,
                    timeout=timeout)
            except Exception:
                LOG.exception("Failed to cancel cluster group migration.")
                raise exceptions.JobTerminateFailed()

        LOG.info("Cluster group migration canceled.")

    def _is_migration_queued(self, group_status_info):
        return bool(
            group_status_info &
            w_const.CLUSGRP_STATUS_WAITING_IN_QUEUE_FOR_MOVE)

    def _is_migration_pending(self, group_state, group_status_info,
                              expected_state):
        migration_pending = (
            group_state != expected_state or
            self._is_migration_queued(group_status_info))
        return migration_pending

    def _wait_for_cluster_group_migration(self, event_listener,
                                          group_name, group_handle,
                                          expected_state,
                                          timeout=None):
        time_start = time.time()
        time_left = timeout if timeout else 'undefined'

        group_state_info = self._get_cluster_group_state(group_handle)
        group_state = group_state_info['state']
        group_status_info = group_state_info['status_info']

        migration_pending = self._is_migration_pending(
            group_state,
            group_status_info,
            expected_state)
        if not migration_pending:
            return

        while not timeout or time_left > 0:
            time_elapsed = time.time() - time_start
            time_left = timeout - time_elapsed if timeout else 'undefined'

            LOG.debug("Waiting for cluster group '%(group_name)s' "
                      "migration to finish. "
                      "Time left: %(time_left)s.",
                      dict(group_name=group_name,
                           time_left=time_left))

            try:
                event = event_listener.get(time_left if timeout else None)
            except queue.Empty:
                break

            group_state = event.get('state', group_state)
            group_status_info = event.get('status_info', group_status_info)

            migration_pending = self._is_migration_pending(group_state,
                                                           group_status_info,
                                                           expected_state)
            if not migration_pending:
                return

        LOG.error("Cluster group migration timed out.")
        raise exceptions.ClusterGroupMigrationTimeOut(
            group_name=group_name,
            time_elapsed=time.time() - time_start)

    def get_cluster_group_state_info(self, group_name):
        """Gets cluster group state info.

        :return: a dict containing the following keys:
            ['state', 'migration_queued', 'owner_node']
        """
        cluster_handle = None
        group_handle = None

        try:
            cluster_handle = self._clusapi_utils.open_cluster()
            group_handle = self._clusapi_utils.open_cluster_group(
                cluster_handle, group_name)

            state_info = self._get_cluster_group_state(group_handle)
            migration_queued = self._is_migration_queued(
                state_info['status_info'])

            return dict(owner_node=state_info['owner_node'],
                        state=state_info['state'],
                        migration_queued=migration_queued)
        finally:
            if group_handle:
                self._clusapi_utils.close_cluster_group(group_handle)
            if cluster_handle:
                self._clusapi_utils.close_cluster(cluster_handle)

    def _get_cluster_group_state(self, group_handle):
        state_info = self._clusapi_utils.get_cluster_group_state(group_handle)

        buff, buff_sz = self._clusapi_utils.cluster_group_control(
            group_handle,
            w_const.CLUSCTL_GROUP_GET_RO_COMMON_PROPERTIES)
        status_info = self._clusapi_utils.get_cluster_group_status_info(
            ctypes.byref(buff), buff_sz)

        state_info['status_info'] = status_info
        return state_info

    def monitor_vm_failover(self, callback,
                            event_timeout_ms=_WMI_EVENT_TIMEOUT_MS):
        """Creates a monitor to check for new WMI MSCluster_Resource

        events.

        This method will poll the last _WMI_EVENT_CHECK_INTERVAL + 1
        seconds for new events and listens for _WMI_EVENT_TIMEOUT_MS
        milliseconds, since listening is a thread blocking action.

        Any event object caught will then be processed.
        """

        # TODO(lpetrut): mark this method as private once compute-hyperv
        # stops using it. We should also remove the instance '_watcher'
        # attribute since we end up spawning unused event listeners.

        vm_name = None
        new_host = None
        try:
            # wait for new event for _WMI_EVENT_TIMEOUT_MS milliseconds.
            if patcher.is_monkey_patched('thread'):
                wmi_object = tpool.execute(self._watcher,
                                           event_timeout_ms)
            else:
                wmi_object = self._watcher(event_timeout_ms)

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
                        "Exception during failover callback.")
        except exceptions.x_wmi_timed_out:
            pass

    def get_vm_owner_change_listener(self):
        def listener(callback):
            while True:
                # We avoid setting an infinite timeout in order to let
                # the process gracefully stop. Note that the os-win WMI
                # event listeners are meant to be used as long running
                # daemons, so no stop API is provided ATM.
                try:
                    self.monitor_vm_failover(
                        callback,
                        constants.DEFAULT_WMI_EVENT_TIMEOUT_MS)
                except Exception:
                    LOG.exception("The VM cluster group owner change "
                                  "event listener encountered an "
                                  "unexpected exception.")
                    time.sleep(constants.DEFAULT_WMI_EVENT_TIMEOUT_MS / 1000)

        return listener


# At the moment, those event listeners are not meant to be used outside
# os-win, mostly because of the underlying API limitations.
class _ClusterEventListener(object):
    _notif_keys = {}
    _notif_port_h = None
    _cluster_handle = None
    _running = False

    def __init__(self, cluster_handle, notif_filters_list):
        self._cluster_handle = cluster_handle
        self._notif_filters_list = notif_filters_list

        self._clusapi_utils = _clusapi_utils.ClusApiUtils()
        self._event_queue = queue.Queue()

        self._setup()

    def __enter__(self):
        self._ensure_listener_running()
        return self

    def _get_notif_key_dw(self, notif_key):
        notif_key_dw = self._notif_keys.get(notif_key)
        if notif_key_dw is None:
            notif_key_dw = wintypes.DWORD(notif_key)
            # We have to make sure those addresses are preserved.
            self._notif_keys[notif_key] = notif_key_dw
        return notif_key_dw

    def _add_filter(self, notif_filter, notif_key=0):
        notif_key_dw = self._get_notif_key_dw(notif_key)

        # We'll get a notification handle if not already existing.
        self._notif_port_h = self._clusapi_utils.create_cluster_notify_port_v2(
            self._cluster_handle, notif_filter,
            self._notif_port_h, notif_key_dw)

    def _setup_notif_port(self):
        for notif_filter in self._notif_filters_list:
            filter_struct = clusapi_def.NOTIFY_FILTER_AND_TYPE(
                dwObjectType=notif_filter['object_type'],
                FilterFlags=notif_filter['filter_flags'])
            notif_key = notif_filter.get('notif_key', 0)

            self._add_filter(filter_struct, notif_key)

    def _setup(self):
        self._setup_notif_port()

        # If eventlet monkey patching is used, this will actually be a
        # greenthread. We just don't want to enforce eventlet usage.
        worker = threading.Thread(target=self._listen)
        worker.setDaemon(True)

        self._running = True
        worker.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def _signal_stopped(self):
        self._running = False
        self._event_queue.put(None)

    def stop(self):
        self._signal_stopped()

        if self._notif_port_h:
            self._clusapi_utils.close_cluster_notify_port(self._notif_port_h)

    def _listen(self):
        while self._running:
            try:
                # We're using an indefinite timeout here. When the listener is
                # closed, this will raise an 'invalid handle value' error,
                # which we're going to ignore.
                event = _utils.avoid_blocking_call(
                    self._clusapi_utils.get_cluster_notify_v2,
                    self._notif_port_h,
                    timeout_ms=-1)

                processed_event = self._process_event(event)
                if processed_event:
                    self._event_queue.put(processed_event)
            except Exception:
                if self._running:
                    LOG.exception(
                        "Unexpected exception in event listener loop. "
                        "The cluster event listener will now close.")
                    self._signal_stopped()

    def _process_event(self, event):
        return event

    def get(self, timeout=None):
        self._ensure_listener_running()

        event = self._event_queue.get(timeout=timeout)

        self._ensure_listener_running()
        return event

    def _ensure_listener_running(self):
        if not self._running:
            raise exceptions.OSWinException(
                _("Cluster event listener is not running."))


class _ClusterGroupStateChangeListener(_ClusterEventListener):
    _NOTIF_KEY_GROUP_STATE = 0
    _NOTIF_KEY_GROUP_COMMON_PROP = 1

    _notif_filters_list = [
        dict(object_type=w_const.CLUSTER_OBJECT_TYPE_GROUP,
             filter_flags=w_const.CLUSTER_CHANGE_GROUP_STATE_V2,
             notif_key=_NOTIF_KEY_GROUP_STATE),
        dict(object_type=w_const.CLUSTER_OBJECT_TYPE_GROUP,
             filter_flags=w_const.CLUSTER_CHANGE_GROUP_COMMON_PROPERTY_V2,
             notif_key=_NOTIF_KEY_GROUP_COMMON_PROP)]

    def __init__(self, cluster_handle, group_name=None):
        self._group_name = group_name

        super(_ClusterGroupStateChangeListener, self).__init__(
            cluster_handle, self._notif_filters_list)

    def _process_event(self, event):
        group_name = event['cluster_object_name']
        if self._group_name and self._group_name.lower() != group_name.lower():
            return

        preserved_keys = ['cluster_object_name', 'object_type',
                          'filter_flags', 'notif_key']
        processed_event = {key: event[key] for key in preserved_keys}

        notif_key = event['notif_key']
        if notif_key == self._NOTIF_KEY_GROUP_STATE:
            if event['buff_sz'] != ctypes.sizeof(wintypes.DWORD):
                raise exceptions.ClusterPropertyRetrieveFailed()
            state_p = ctypes.cast(event['buff'], wintypes.PDWORD)
            state = state_p.contents.value
            processed_event['state'] = state
            return processed_event
        elif notif_key == self._NOTIF_KEY_GROUP_COMMON_PROP:
            try:
                status_info = (
                    self._clusapi_utils.get_cluster_group_status_info(
                        ctypes.byref(event['buff']), event['buff_sz']))
                processed_event['status_info'] = status_info
                return processed_event
            except exceptions.ClusterPropertyListEntryNotFound:
                # At the moment, we only care about the 'StatusInformation'
                # common property.
                pass
