# Copyright 2016 Cloudbase Solutions Srl
#
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
Base WMI utility class.
"""

import sys

if sys.platform == 'win32':
    import wmi


class BaseUtils(object):

    _WMI_CONS = {}

    def _get_wmi_obj(self, moniker, **kwargs):
        return wmi.WMI(moniker=moniker, **kwargs)

    def _get_wmi_conn(self, moniker, **kwargs):
        if sys.platform != 'win32':
            return None
        if kwargs:
            return self._get_wmi_obj(moniker, **kwargs)
        if moniker in self._WMI_CONS:
            return self._WMI_CONS[moniker]

        wmi_conn = self._get_wmi_obj(moniker)
        self._WMI_CONS[moniker] = wmi_conn
        return wmi_conn


class BaseUtilsVirt(BaseUtils):

    _wmi_namespace = '//%s/root/virtualization/v2'

    def __init__(self, host='.'):
        self._vs_man_svc_attr = None
        self._conn = self._get_wmi_conn(self._wmi_namespace % host)

    @property
    def _vs_man_svc(self):
        if not self._vs_man_svc_attr:
            self._vs_man_svc_attr = (
                self._conn.Msvm_VirtualSystemManagementService()[0])
        return self._vs_man_svc_attr
