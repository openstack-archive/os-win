# Copyright 2013 Cloudbase Solutions Srl
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
Utility class for network related operations.
"""

import sys
import uuid

if sys.platform == 'win32':
    import wmi

from oslo_log import log as logging

from os_win._i18n import _, _LE
from os_win import exceptions
from os_win.utils import jobutils

LOG = logging.getLogger(__name__)


class NetworkUtils(object):

    _ETHERNET_SWITCH_PORT = 'Msvm_SwitchPort'
    _SWITCH_LAN_ENDPOINT = 'Msvm_SwitchLanEndpoint'
    _VIRTUAL_SWITCH = 'Msvm_VirtualSwitch'
    _BINDS_TO = 'Msvm_BindsTo'
    _VLAN_ENDPOINT_SET_DATA = 'Msvm_VLANEndpointSettingData'

    def __init__(self):
        self._jobutils = jobutils.JobUtils()
        if sys.platform == 'win32':
            self._conn = wmi.WMI(moniker='//./root/virtualization')

    def get_external_vswitch(self, vswitch_name):
        if vswitch_name:
            vswitches = self._conn.Msvm_VirtualSwitch(ElementName=vswitch_name)
        else:
            # Find the vswitch that is connected to the first physical nic.
            ext_port = self._conn.Msvm_ExternalEthernetPort(IsBound='TRUE')[0]
            port = ext_port.associators(wmi_result_class='Msvm_SwitchPort')[0]
            vswitches = port.associators(wmi_result_class='Msvm_VirtualSwitch')

        if not len(vswitches):
            raise exceptions.HyperVException(_('vswitch "%s" not found')
                                             % vswitch_name)
        return vswitches[0].path_()

    def get_vswitch_id(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        return vswitch.Name

    def _get_vswitch(self, vswitch_name):
        vswitch = self._conn.Msvm_VirtualSwitch(ElementName=vswitch_name)
        if not vswitch:
            raise exceptions.HyperVException(_('VSwitch not found: %s') %
                                             vswitch_name)
        return vswitch[0]

    def _get_vswitch_external_port(self, vswitch_name):
        ext_ports = self._conn.Msvm_ExternalEthernetPort()
        for ext_port in ext_ports:
            lan_endpoint_list = ext_port.associators(
                wmi_result_class='Msvm_SwitchLanEndpoint')
            if lan_endpoint_list:
                vswitch_port_list = lan_endpoint_list[0].associators(
                    wmi_result_class=self._ETHERNET_SWITCH_PORT)
                if vswitch_port_list:
                    vswitch_port = vswitch_port_list[0]
                    vswitch_list = vswitch_port.associators(
                        wmi_result_class='Msvm_VirtualSwitch')
                    if (vswitch_list and
                            vswitch_list[0].ElementName == vswitch_name):
                        return vswitch_port

    def set_switch_external_port_trunk_vlan(self, vswitch_name, vlan_id,
                                            desired_endpoint_mode):
        vswitch_external_port = self._get_vswitch_external_port(vswitch_name)
        if vswitch_external_port:
            vlan_endpoint = vswitch_external_port.associators(
                wmi_association_class=self._BINDS_TO)[0]
            vlan_endpoint_settings = vlan_endpoint.associators(
                wmi_result_class=self._VLAN_ENDPOINT_SET_DATA)[0]
            if vlan_id not in vlan_endpoint_settings.TrunkedVLANList:
                vlan_endpoint_settings.TrunkedVLANList += (vlan_id,)
                vlan_endpoint_settings.put()

            if (desired_endpoint_mode not in
                    vlan_endpoint.SupportedEndpointModes):
                LOG.error(_LE("'Trunk' VLAN endpoint mode is not supported by "
                              "the switch / physycal network adapter. Correct "
                              "this issue or use flat networks instead."))
                return
            if vlan_endpoint.DesiredEndpointMode != desired_endpoint_mode:
                vlan_endpoint.DesiredEndpointMode = desired_endpoint_mode
                vlan_endpoint.put()

    def create_vswitch_port(self, vswitch_path, port_name):
        switch_svc = self._conn.Msvm_VirtualSwitchManagementService()[0]
        # Create a port on the vswitch.
        (new_port, ret_val) = switch_svc.CreateSwitchPort(
            Name=str(uuid.uuid4()),
            FriendlyName=port_name,
            ScopeOfResidence="",
            VirtualSwitch=vswitch_path)
        if ret_val != 0:
            raise exceptions.HyperVException(
                _("Failed to create vswitch port %(port_name)s on switch "
                  "%(vswitch_path)s") % {'port_name': port_name,
                                         'vswitch_path': vswitch_path})
        return new_port

    def vswitch_port_needed(self):
        # NOTE(alexpilotti): In WMI V2 the vswitch_path is set in the VM
        # setting data without the need for a vswitch port.
        return True

    def get_switch_ports(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        vswitch_ports = vswitch.associators(
            wmi_result_class=self._ETHERNET_SWITCH_PORT)
        return set(p.Name for p in vswitch_ports)

    def vnic_port_exists(self, port_id):
        try:
            self._get_vnic_settings(port_id)
        except Exception:
            return False
        return True

    def get_vnic_ids(self):
        return set(
            p.ElementName
            for p in self._conn.Msvm_SyntheticEthernetPortSettingData()
            if p.ElementName is not None)

    def _get_vnic_settings(self, vnic_name):
        vnic_settings = self._conn.Msvm_SyntheticEthernetPortSettingData(
            ElementName=vnic_name)
        if not vnic_settings:
            raise exceptions.HyperVException(
                message=_('Vnic not found: %s') % vnic_name)
        return vnic_settings[0]

    def connect_vnic_to_vswitch(self, vswitch_name, switch_port_name):
        vnic_settings = self._get_vnic_settings(switch_port_name)
        if not vnic_settings.Connection or not vnic_settings.Connection[0]:
            port = self.get_port_by_id(switch_port_name, vswitch_name)
            if port:
                port_path = port.Path_()
            else:
                port_path = self.create_vswitch_port(
                    vswitch_name, switch_port_name)
            vnic_settings.Connection = [port_path]
            self._jobutils.modify_virt_resource(vnic_settings)

    def _get_vm_from_res_setting_data(self, res_setting_data):
        sd = res_setting_data.associators(
            wmi_result_class='Msvm_VirtualSystemSettingData')
        vm = sd[0].associators(
            wmi_result_class='Msvm_ComputerSystem')
        return vm[0]

    def disconnect_switch_port(self, switch_port_name, vnic_deleted,
                               delete_port):
        """Disconnects the switch port."""
        switch_svc = self._conn.Msvm_VirtualSwitchManagementService()[0]
        switch_port_path = self._get_switch_port_path_by_name(
            switch_port_name)
        if not switch_port_path:
            # Port not found. It happens when the VM was already deleted.
            return

        if not vnic_deleted:
            (ret_val, ) = switch_svc.DisconnectSwitchPort(
                SwitchPort=switch_port_path)
            if ret_val != 0:
                data = {'switch_port_name': switch_port_name,
                        'ret_val': ret_val}
                raise exceptions.HyperVException(
                    message=_('Failed to disconnect port %(switch_port_name)s '
                              'with error %(ret_val)s') % data)
        if delete_port:
            (ret_val, ) = switch_svc.DeleteSwitchPort(
                SwitchPort=switch_port_path)
            if ret_val != 0:
                data = {'switch_port_name': switch_port_name,
                        'ret_val': ret_val}
                raise exceptions.HyperVException(
                    message=_('Failed to delete port %(switch_port_name)s '
                              'with error %(ret_val)s') % data)

    def set_vswitch_port_vlan_id(self, vlan_id, switch_port_name):
        vlan_endpoint_settings = self._conn.Msvm_VLANEndpointSettingData(
            ElementName=switch_port_name)[0]
        if vlan_endpoint_settings.AccessVLAN != vlan_id:
            vlan_endpoint_settings.AccessVLAN = vlan_id
            vlan_endpoint_settings.put()

    def _get_switch_port_path_by_name(self, switch_port_name):
        vswitch = self._conn.Msvm_SwitchPort(ElementName=switch_port_name)
        if vswitch:
            return vswitch[0].path_()

    def get_port_by_id(self, port_id, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        switch_ports = vswitch.associators(
            wmi_result_class=self._ETHERNET_SWITCH_PORT)
        for switch_port in switch_ports:
            if (switch_port.ElementName == port_id):
                return switch_port

    def remove_all_security_rules(self, switch_port_name):
        pass

    def enable_port_metrics_collection(self, switch_port_name):
        raise NotImplementedError(_("Metrics collection is not supported on "
                                    "this version of Hyper-V"))

    def enable_control_metrics(self, switch_port_name):
        raise NotImplementedError(_("Metrics collection is not supported on "
                                    "this version of Hyper-V"))
