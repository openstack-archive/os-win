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

import ctypes

from os_win import constants
from os_win import exceptions
from os_win.utils import win32utils
from os_win.utils.winapi import constants as w_const
from os_win.utils.winapi import libs as w_lib
from os_win.utils.winapi.libs import clusapi as clusapi_def
from os_win.utils.winapi import wintypes

clusapi = w_lib.get_shared_lib_handle(w_lib.CLUSAPI)


class ClusApiUtils(object):
    _open_handle_check_flags = dict(ret_val_is_err_code=False,
                                    error_on_nonzero_ret_val=False,
                                    error_ret_vals=[0, None])

    def __init__(self):
        self._win32utils = win32utils.Win32Utils()

    def _run_and_check_output(self, *args, **kwargs):
        kwargs['failure_exc'] = exceptions.ClusterWin32Exception
        return self._win32utils.run_and_check_output(*args, **kwargs)

    def _dword_align(self, value):
        return (value + 3) & ~3

    def _get_clusprop_value_struct(self, val_type):
        def _get_padding():
            # The cluster property entries must be 4B aligned.
            val_sz = ctypes.sizeof(val_type)
            return self._dword_align(val_sz) - val_sz

        # For convenience, as opposed to the homonymous ClusAPI
        # structure, we add the actual value as well.
        class CLUSPROP_VALUE(ctypes.Structure):
            _fields_ = [('syntax', wintypes.DWORD),
                        ('length', wintypes.DWORD),
                        ('value', val_type),
                        ('_padding', ctypes.c_ubyte * _get_padding())]
        return CLUSPROP_VALUE

    def get_property_list_entry(self, name, syntax, value):
        # The value argument must have a ctypes type.
        name_len = len(name) + 1
        val_sz = ctypes.sizeof(value)

        class CLUSPROP_LIST_ENTRY(ctypes.Structure):
            _fields_ = [
                ('name', self._get_clusprop_value_struct(
                    val_type=ctypes.c_wchar * name_len)),
                ('value', self._get_clusprop_value_struct(
                    val_type=ctypes.c_ubyte * val_sz)),
                ('_endmark', wintypes.DWORD)
            ]

        entry = CLUSPROP_LIST_ENTRY()
        entry.name.syntax = w_const.CLUSPROP_SYNTAX_NAME
        entry.name.length = name_len * ctypes.sizeof(ctypes.c_wchar)
        entry.name.value = name

        entry.value.syntax = syntax
        entry.value.length = val_sz
        entry.value.value[0:val_sz] = bytearray(value)

        entry._endmark = w_const.CLUSPROP_SYNTAX_ENDMARK

        return entry

    def get_property_list(self, property_entries):
        prop_entries_sz = sum([ctypes.sizeof(entry)
                              for entry in property_entries])

        class CLUSPROP_LIST(ctypes.Structure):
            _fields_ = [('count', wintypes.DWORD),
                        ('entries_buff', ctypes.c_ubyte * prop_entries_sz)]

        prop_list = CLUSPROP_LIST(count=len(property_entries))

        pos = 0
        for prop_entry in property_entries:
            prop_entry_sz = ctypes.sizeof(prop_entry)
            prop_list.entries_buff[pos:prop_entry_sz + pos] = bytearray(
                prop_entry)
            pos += prop_entry_sz

        return prop_list

    def open_cluster(self, cluster_name=None):
        """Returns a handle for the requested cluster.

        :param cluster_name: (Optional) specifies the name of the cluster
                             to be opened. If None, the cluster that the
                             local node belongs to will be opened.
        """
        p_clus_name = ctypes.c_wchar_p(cluster_name) if cluster_name else None
        handle = self._run_and_check_output(clusapi.OpenCluster,
                                            p_clus_name,
                                            **self._open_handle_check_flags)
        return handle

    def open_cluster_group(self, cluster_handle, group_name):
        handle = self._run_and_check_output(clusapi.OpenClusterGroup,
                                            cluster_handle,
                                            ctypes.c_wchar_p(group_name),
                                            **self._open_handle_check_flags)
        return handle

    def open_cluster_node(self, cluster_handle, node_name):
        handle = self._run_and_check_output(clusapi.OpenClusterNode,
                                            cluster_handle,
                                            ctypes.c_wchar_p(node_name),
                                            **self._open_handle_check_flags)
        return handle

    def close_cluster(self, cluster_handle):
        # This function will always return 'True'. Closing the cluster
        # handle will also invalidate handles opened using it.
        clusapi.CloseCluster(cluster_handle)

    def close_cluster_group(self, group_handle):
        # TODO(lpetrut): The following functions can fail, in which case
        # 'False' will be returned. We may want to handle this situation.
        clusapi.CloseClusterGroup(group_handle)

    def close_cluster_node(self, node_handle):
        clusapi.CloseClusterNode(node_handle)

    def cancel_cluster_group_operation(self, group_handle):
        """Requests a pending move operation to be canceled.

        This only applies to move operations requested by
        MoveClusterGroup(Ex), thus it will not apply to fail overs.

        return: True if the cancel request completed successfuly,
                False if it's still in progress.
        """
        ret_val = self._run_and_check_output(
            clusapi.CancelClusterGroupOperation,
            group_handle,
            0,  # cancel flags (reserved for future use by MS)
            ignored_error_codes=[w_const.ERROR_IO_PENDING])

        cancel_completed = ret_val != w_const.ERROR_IO_PENDING
        return cancel_completed

    def move_cluster_group(self, group_handle, destination_node_handle,
                           move_flags, property_list):
        prop_list_p = ctypes.byref(property_list) if property_list else None
        prop_list_sz = ctypes.sizeof(property_list) if property_list else 0

        self._run_and_check_output(clusapi.MoveClusterGroupEx,
                                   group_handle,
                                   destination_node_handle,
                                   move_flags,
                                   prop_list_p,
                                   prop_list_sz,
                                   ignored_error_codes=[
                                       w_const.ERROR_IO_PENDING])

    def get_cluster_group_state(self, group_handle):
        node_name_len = wintypes.DWORD(w_const.MAX_PATH)
        node_name_buff = (ctypes.c_wchar * node_name_len.value)()

        group_state = self._run_and_check_output(
            clusapi.GetClusterGroupState,
            group_handle,
            node_name_buff,
            ctypes.byref(node_name_len),
            error_ret_vals=[constants.CLUSTER_GROUP_STATE_UNKNOWN],
            error_on_nonzero_ret_val=False,
            ret_val_is_err_code=False)

        return {'state': group_state,
                'owner_node': node_name_buff.value}

    def create_cluster_notify_port_v2(self, cluster_handle, notif_filters,
                                      notif_port_h=None, notif_key=None):
        """Creates or updates a cluster notify port.

        This allows us to subscribe to specific types of cluster events.

        :param cluster_handle: an open cluster handle, for which we'll
                               receive events. This handle must remain open
                               while fetching events.
        :param notif_filters: an array of NOTIFY_FILTER_AND_TYPE structures,
                              specifying the event types we're listening to.
        :param notif_port_h: an open cluster notify port handle, when adding
                             new filters to an existing cluster notify port,
                             or INVALID_HANDLE_VALUE when creating a new
                             notify port.
        :param notif_key: a DWORD value that will be mapped to a specific
                          event type. When fetching events, the cluster API
                          will send us back a reference to the according
                          notification key. For this reason, we must ensure
                          that this variable will not be garbage collected
                          while waiting for events.
        :return: the requested notify port handle,
        """
        notif_port_h = notif_port_h or w_const.INVALID_HANDLE_VALUE
        notif_filters_len = (len(notif_filters)
                             if isinstance(notif_filters, ctypes.Array)
                             else 1)
        notif_key_p = (ctypes.byref(notif_key)
                       if notif_key is not None else None)
        # If INVALID_HANDLE_VALUE is passed as the notification handle,
        # a new one will be created. Otherwise, new events are added to the
        # specified notification port.
        notif_port_h = self._run_and_check_output(
            clusapi.CreateClusterNotifyPortV2,
            notif_port_h,
            cluster_handle,
            ctypes.byref(notif_filters),
            ctypes.c_ulong(notif_filters_len),
            notif_key_p,
            **self._open_handle_check_flags)
        return notif_port_h

    def close_cluster_notify_port(self, notif_port_h):
        # Always returns True.
        clusapi.CloseClusterNotifyPort(notif_port_h)

    def get_cluster_notify_v2(self, notif_port_h, timeout_ms):
        filter_and_type = clusapi_def.NOTIFY_FILTER_AND_TYPE()
        obj_name_buff_sz = ctypes.c_ulong(w_const.MAX_PATH)
        notif_key_p = wintypes.PDWORD()
        buff_sz = ctypes.c_ulong(w_const.MAX_PATH)

        # Event notification buffer. The notification format depends
        # on the event type and filter flags.
        buff = (wintypes.BYTE * buff_sz.value)()
        obj_name_buff = (ctypes.c_wchar * obj_name_buff_sz.value)()

        def get_args(buff, obj_name_buff):
            return (clusapi.GetClusterNotifyV2,
                    notif_port_h,
                    ctypes.byref(notif_key_p),
                    ctypes.byref(filter_and_type),
                    buff,
                    ctypes.byref(buff_sz),
                    None,  # object id
                    None,  # object id sz
                    None,  # parent id
                    None,  # parent id sz
                    obj_name_buff,
                    ctypes.byref(obj_name_buff_sz),
                    None,  # object type
                    None,  # object type sz
                    timeout_ms)
        try:
            self._run_and_check_output(*get_args(buff, obj_name_buff))
        except exceptions.ClusterWin32Exception as ex:
            if ex.error_code == w_const.ERROR_MORE_DATA:
                # This function will specify the buffer sizes it needs using
                # the references we pass.
                buff = (wintypes.BYTE * buff_sz.value)()
                obj_name_buff = (ctypes.c_wchar * obj_name_buff_sz.value)()

                self._run_and_check_output(*get_args(buff, obj_name_buff))
            else:
                raise

        # We'll leverage notification key values instead of their addresses,
        # although this returns us the address we passed in when setting up
        # the notification port.
        notif_key = notif_key_p.contents.value
        event = {'cluster_object_name': obj_name_buff.value,
                 'object_type': filter_and_type.dwObjectType,
                 'filter_flags': filter_and_type.FilterFlags,
                 'buff': buff,
                 'buff_sz': buff_sz.value,
                 'notif_key': notif_key}
        return event

    def get_prop_list_entry_p(self, prop_list_p, prop_list_sz, property_name):
        # We may add a nice property list parser at some point.
        # ResUtilFindULargeIntegerProperty is also helpful for our use case
        # but it's available only starting with WS 2016.
        #
        # NOTE(lpetrut): in most cases, we're using 'byref' when passing
        # references to DLL functions. The issue is that those pointers
        # cannot be used directly, for which reason we have a cast here.
        prop_list_p = ctypes.cast(
            prop_list_p, ctypes.POINTER(ctypes.c_ubyte * prop_list_sz))
        wb_prop_name = bytearray(ctypes.create_unicode_buffer(property_name))

        prop_list_addr = ctypes.addressof(prop_list_p.contents)
        prop_name_pos = bytearray(prop_list_p.contents).find(wb_prop_name)
        if prop_name_pos == -1:
            raise exceptions.ClusterPropertyListEntryNotFound(
                property_name=property_name)

        prop_name_len_pos = prop_name_pos - ctypes.sizeof(wintypes.DWORD)
        prop_name_len_addr = prop_list_addr + prop_name_len_pos
        prop_name_len = self._dword_align(
            wintypes.DWORD.from_address(prop_name_len_addr).value)
        prop_addr = prop_name_len_addr + prop_name_len + ctypes.sizeof(
            wintypes.DWORD)
        if (prop_addr + ctypes.sizeof(wintypes.DWORD * 3) >
                prop_list_addr + prop_list_sz):
            raise exceptions.ClusterPropertyListParsingError()

        prop_entry = {
            'syntax': wintypes.DWORD.from_address(prop_addr).value,
            'length': wintypes.DWORD.from_address(
                prop_addr + ctypes.sizeof(wintypes.DWORD)).value,
            'val_p': ctypes.c_void_p(prop_addr + 2 * ctypes.sizeof(
                wintypes.DWORD))
        }

        return prop_entry

    def cluster_group_control(self, group_handle, control_code,
                              node_handle=None,
                              in_buff_p=None, in_buff_sz=0):
        out_buff_sz = ctypes.c_ulong(w_const.MAX_PATH)
        out_buff = (ctypes.c_ubyte * out_buff_sz.value)()

        def get_args(out_buff):
            return (clusapi.ClusterGroupControl,
                    group_handle,
                    node_handle,
                    control_code,
                    in_buff_p,
                    in_buff_sz,
                    out_buff,
                    out_buff_sz,
                    ctypes.byref(out_buff_sz))

        try:
            self._run_and_check_output(*get_args(out_buff))
        except exceptions.ClusterWin32Exception as ex:
            if ex.error_code == w_const.ERROR_MORE_DATA:
                out_buff = (ctypes.c_ubyte * out_buff_sz.value)()
                self._run_and_check_output(*get_args(out_buff))
            else:
                raise

        return out_buff, out_buff_sz.value

    def get_cluster_group_status_info(self, prop_list_p, prop_list_sz):
        prop_entry = self.get_prop_list_entry_p(
            prop_list_p, prop_list_sz,
            w_const.CLUSREG_NAME_GRP_STATUS_INFORMATION)

        if (prop_entry['length'] != ctypes.sizeof(ctypes.c_ulonglong) or
                prop_entry['syntax'] !=
                w_const.CLUSPROP_SYNTAX_LIST_VALUE_ULARGE_INTEGER):
            raise exceptions.ClusterPropertyListParsingError()

        status_info_p = prop_entry['val_p']
        status_info = ctypes.c_ulonglong.from_address(
            status_info_p.value).value
        return status_info
