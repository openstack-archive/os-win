# Copyright 2015 Cloudbase Solutions Srl
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

import contextlib
import ctypes
import six
import sys
import textwrap

if sys.platform == 'win32':
    hbaapi = ctypes.cdll.hbaapi

from os_win._i18n import _
from os_win import _utils
from os_win import exceptions
from os_win.utils.storage.initiator import fc_structures as fc_struct
from os_win.utils import win32utils

HBA_STATUS_OK = 0
HBA_STATUS_ERROR_MORE_DATA = 7


class FCUtils(object):
    def __init__(self):
        self._win32_utils = win32utils.Win32Utils()

    def _run_and_check_output(self, *args, **kwargs):
        kwargs['failure_exc'] = exceptions.FCWin32Exception
        return self._win32_utils.run_and_check_output(*args, **kwargs)

    def get_fc_hba_count(self):
        return hbaapi.HBA_GetNumberOfAdapters()

    def _open_adapter(self, adapter_name=None, adapter_wwn=None):
        if adapter_name:
            func = hbaapi.HBA_OpenAdapter
            arg = ctypes.c_char_p(six.b(adapter_name))
        elif adapter_wwn:
            func = hbaapi.HBA_OpenAdapterByWWN
            arg = fc_struct.HBA_WWN(*adapter_wwn)
        else:
            err_msg = _("Could not open HBA adapter. "
                        "No HBA name or WWN was specified")
            raise exceptions.FCException(err_msg)

        handle = self._run_and_check_output(func, arg,
                                            ret_val_is_err_code=False,
                                            error_on_nonzero_ret_val=False,
                                            error_ret_vals=[0])
        return handle

    def _close_adapter(self, hba_handle):
        hbaapi.HBA_CloseAdapter(hba_handle)

    @contextlib.contextmanager
    def _get_hba_handle(self, *args, **kwargs):
        hba_handle = self._open_adapter(*args, **kwargs)
        try:
            yield hba_handle
        finally:
            self._close_adapter(hba_handle)

    def _get_adapter_name(self, adapter_index):
        buff = (ctypes.c_char * 256)()
        self._run_and_check_output(hbaapi.HBA_GetAdapterName,
                                   ctypes.c_uint32(adapter_index),
                                   ctypes.byref(buff))

        return buff.value.decode('utf-8')

    def _get_target_mapping(self, hba_handle):
        entry_count = 0
        hba_status = HBA_STATUS_ERROR_MORE_DATA

        while hba_status == HBA_STATUS_ERROR_MORE_DATA:
            mapping = fc_struct.get_target_mapping_struct(entry_count)
            hba_status = self._run_and_check_output(
                hbaapi.HBA_GetFcpTargetMapping,
                hba_handle,
                ctypes.byref(mapping),
                ignored_error_codes=[HBA_STATUS_ERROR_MORE_DATA])
            entry_count = mapping.NumberOfEntries

        return mapping

    def _get_adapter_port_attributes(self, hba_handle, port_index):
        port_attributes = fc_struct.HBA_PortAttributes()

        self._run_and_check_output(
            hbaapi.HBA_GetAdapterPortAttributes,
            hba_handle, port_index,
            ctypes.byref(port_attributes))
        return port_attributes

    def _get_adapter_attributes(self, hba_handle):
        hba_attributes = fc_struct.HBA_AdapterAttributes()

        self._run_and_check_output(
            hbaapi.HBA_GetAdapterAttributes,
            hba_handle, ctypes.byref(hba_attributes))
        return hba_attributes

    def get_fc_hba_ports(self):
        hba_ports = []

        adapter_count = self.get_fc_hba_count()
        for adapter_index in range(adapter_count):
            adapter_name = self._get_adapter_name(adapter_index)
            with self._get_hba_handle(
                    adapter_name=adapter_name) as hba_handle:
                adapter_attributes = self._get_adapter_attributes(hba_handle)
                port_count = adapter_attributes.NumberOfPorts

                for port_index in range(port_count):
                    port_attributes = self._get_adapter_port_attributes(
                        hba_handle,
                        port_index)
                    wwnn = self._wwn_array_to_hex_str(port_attributes.NodeWWN)
                    wwpn = self._wwn_array_to_hex_str(port_attributes.PortWWN)

                    hba_port_info = dict(node_name=wwnn,
                                         port_name=wwpn)
                    hba_ports.append(hba_port_info)

        return hba_ports

    def _wwn_hex_string_to_array(self, wwn):
        return [int(hex_byte, 16) for hex_byte in textwrap.wrap(wwn, 2)]

    def _wwn_array_to_hex_str(self, wwn):
        return ''.join('{:02X}'.format(b) for b in wwn)

    def get_fc_target_mappings(self, node_wwn):
        mappings = []
        node_wwn = self._wwn_hex_string_to_array(node_wwn)

        with self._get_hba_handle(adapter_wwn=node_wwn) as hba_handle:
            fcp_mappings = self._get_target_mapping(hba_handle)
            for entry in fcp_mappings.Entries:
                wwnn = self._wwn_array_to_hex_str(entry.FcpId.NodeWWN)
                wwpn = self._wwn_array_to_hex_str(entry.FcpId.PortWWN)
                mapping = dict(node_name=wwnn,
                               port_name=wwpn,
                               device_name=entry.ScsiId.OSDeviceName,
                               lun=entry.ScsiId.ScsiOSLun)
                mappings.append(mapping)
        return mappings

    def rescan_disks(self):
        # TODO(lpetrut): find a better way to do this.
        cmd = ("cmd", "/c", "echo", "rescan", "|", "diskpart.exe")
        _utils.execute(*cmd)

    def refresh_hba_configuration(self):
        hbaapi.HBA_RefreshAdapterConfiguration()
