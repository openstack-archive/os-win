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
Based on the "root/virtualization/v2" namespace available starting with
Hyper-V Server / Windows Server 2012.
"""

from eventlet import greenthread
import sys

if sys.platform == 'win32':
    import wmi

from os_win._i18n import _
from os_win import exceptions
from os_win.utils import jobutils


class NetworkUtils(object):

    _EXTERNAL_PORT = 'Msvm_ExternalEthernetPort'
    _ETHERNET_SWITCH_PORT = 'Msvm_EthernetSwitchPort'
    _PORT_ALLOC_SET_DATA = 'Msvm_EthernetPortAllocationSettingData'
    _PORT_VLAN_SET_DATA = 'Msvm_EthernetSwitchPortVlanSettingData'
    _PORT_SECURITY_SET_DATA = 'Msvm_EthernetSwitchPortSecuritySettingData'
    _PORT_ALLOC_ACL_SET_DATA = 'Msvm_EthernetSwitchPortAclSettingData'
    _PORT_EXT_ACL_SET_DATA = _PORT_ALLOC_ACL_SET_DATA
    _LAN_ENDPOINT = 'Msvm_LANEndpoint'
    _STATE_DISABLED = 3
    _OPERATION_MODE_ACCESS = 1

    _VIRTUAL_SYSTEM_SETTING_DATA = 'Msvm_VirtualSystemSettingData'
    _VM_SUMMARY_ENABLED_STATE = 100
    _HYPERV_VM_STATE_ENABLED = 2

    _ACL_DIR_IN = 1
    _ACL_DIR_OUT = 2

    _ACL_TYPE_IPV4 = 2
    _ACL_TYPE_IPV6 = 3

    _ACL_ACTION_ALLOW = 1
    _ACL_ACTION_DENY = 2
    _ACL_ACTION_METER = 3

    _METRIC_ENABLED = 2
    _NET_IN_METRIC_NAME = 'Filtered Incoming Network Traffic'
    _NET_OUT_METRIC_NAME = 'Filtered Outgoing Network Traffic'

    _ACL_APPLICABILITY_LOCAL = 1
    _ACL_APPLICABILITY_REMOTE = 2

    _ACL_DEFAULT = 'ANY'
    _IPV4_ANY = '0.0.0.0/0'
    _IPV6_ANY = '::/0'
    _TCP_PROTOCOL = 'tcp'
    _UDP_PROTOCOL = 'udp'
    _ICMP_PROTOCOL = '1'
    _ICMPV6_PROTOCOL = '58'
    _MAX_WEIGHT = 65500

    # 2 directions x 2 address types = 4 ACLs
    _REJECT_ACLS_COUNT = 4

    def __init__(self):
        self._jobutils = jobutils.JobUtils()
        if sys.platform == 'win32':
            self._conn = wmi.WMI(moniker='//./root/virtualization/v2')

    def get_external_vswitch(self, vswitch_name):
        if vswitch_name:
            vswitches = self._conn.Msvm_VirtualEthernetSwitch(
                ElementName=vswitch_name)
            if not len(vswitches):
                raise exceptions.HyperVException(_('vswitch "%s" not found')
                                                 % vswitch_name)
        else:
            # Find the vswitch that is connected to the first physical nic.
            ext_port = self._conn.Msvm_ExternalEthernetPort(IsBound='TRUE')[0]
            lep = ext_port.associators(wmi_result_class='Msvm_LANEndpoint')[0]
            lep1 = lep.associators(wmi_result_class='Msvm_LANEndpoint')[0]
            esw = lep1.associators(
                wmi_result_class='Msvm_EthernetSwitchPort')[0]
            vswitches = esw.associators(
                wmi_result_class='Msvm_VirtualEthernetSwitch')

            if not len(vswitches):
                raise exceptions.HyperVException(
                    _('No external vswitch found'))

        return vswitches[0].path_()

    def get_vswitch_id(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        return vswitch.Name

    def _get_vswitch(self, vswitch_name):
        vswitch = self._conn.Msvm_VirtualEthernetSwitch(
            ElementName=vswitch_name)
        if not len(vswitch):
            raise exceptions.HyperVException(_('VSwitch not found: %s') %
                                             vswitch_name)
        return vswitch[0]

    def vswitch_port_needed(self):
        return False

    def get_switch_ports(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        vswitch_ports = vswitch.associators(
            wmi_result_class=self._ETHERNET_SWITCH_PORT)
        return set(p.Name for p in vswitch_ports)

    def get_port_by_id(self, port_id, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        switch_ports = vswitch.associators(
            wmi_result_class=self._ETHERNET_SWITCH_PORT)
        for switch_port in switch_ports:
            if (switch_port.ElementName == port_id):
                return switch_port

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
        port, found = self._get_switch_port_allocation(switch_port_name, True)
        if found and port.HostResource and port.HostResource[0]:
            # vswitch port already exists and is connected to vswitch.
            return

        vswitch = self._get_vswitch(vswitch_name)
        vnic = self._get_vnic_settings(switch_port_name)

        port.HostResource = [vswitch.path_()]
        port.Parent = vnic.path_()
        if not found:
            vm = self._get_vm_from_res_setting_data(vnic)
            self._jobutils.add_virt_resource(port, vm)
        else:
            self._jobutils.modify_virt_resource(port)

    def _get_vm_from_res_setting_data(self, res_setting_data):
        sd = res_setting_data.associators(
            wmi_result_class='Msvm_VirtualSystemSettingData')
        vm = sd[0].associators(
            wmi_result_class='Msvm_ComputerSystem')
        return vm[0]

    def disconnect_switch_port(self, switch_port_name, vnic_deleted,
                               delete_port):
        """Disconnects the switch port."""
        sw_port, found = self._get_switch_port_allocation(switch_port_name)
        if not sw_port:
            # Port not found. It happens when the VM was already deleted.
            return

        if delete_port:
            self._jobutils.remove_virt_resource(sw_port)
        else:
            sw_port.EnabledState = self._STATE_DISABLED
            self._jobutils.modify_virt_resource(sw_port)

    def set_vswitch_port_vlan_id(self, vlan_id, switch_port_name):
        port_alloc, found = self._get_switch_port_allocation(switch_port_name)
        if not found:
            raise exceptions.HyperVException(
                _('Port Allocation not found: %s') % switch_port_name)

        vlan_settings = self._get_vlan_setting_data_from_port_alloc(port_alloc)
        if vlan_settings:
            if (vlan_settings.OperationMode == self._OPERATION_MODE_ACCESS and
                    vlan_settings.AccessVlanId == vlan_id):
                # VLAN already set to corect value, no need to change it.
                return

            # Removing the feature because it cannot be modified
            # due to a wmi exception.
            self._jobutils.remove_virt_feature(vlan_settings)

        (vlan_settings, found) = self._get_vlan_setting_data(switch_port_name)
        vlan_settings.AccessVlanId = vlan_id
        vlan_settings.OperationMode = self._OPERATION_MODE_ACCESS
        self._jobutils.add_virt_feature(vlan_settings, port_alloc)

    def _get_vlan_setting_data_from_port_alloc(self, port_alloc):
        return self._get_first_item(port_alloc.associators(
            wmi_result_class=self._PORT_VLAN_SET_DATA))

    def _get_vlan_setting_data(self, switch_port_name, create=True):
        return self._get_setting_data(
            self._PORT_VLAN_SET_DATA,
            switch_port_name, create)

    def _get_switch_port_allocation(self, switch_port_name, create=False):
        return self._get_setting_data(
            self._PORT_ALLOC_SET_DATA,
            switch_port_name, create)

    def _get_setting_data(self, class_name, element_name, create=True):
        element_name = element_name.replace("'", '"')
        q = self._conn.query("SELECT * FROM %(class_name)s WHERE "
                             "ElementName = '%(element_name)s'" %
                             {"class_name": class_name,
                              "element_name": element_name})
        data = self._get_first_item(q)
        found = data is not None
        if not data and create:
            data = self._get_default_setting_data(class_name)
            data.ElementName = element_name
        return data, found

    def _get_default_setting_data(self, class_name):
        return self._conn.query("SELECT * FROM %s WHERE InstanceID "
                                "LIKE '%%\\Default'" % class_name)[0]

    def _get_first_item(self, obj):
        if obj:
            return obj[0]

    def enable_port_metrics_collection(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return

        # Add the ACLs only if they don't already exist
        acls = port.associators(wmi_result_class=self._PORT_ALLOC_ACL_SET_DATA)
        for acl_type in [self._ACL_TYPE_IPV4, self._ACL_TYPE_IPV6]:
            for acl_dir in [self._ACL_DIR_IN, self._ACL_DIR_OUT]:
                _acls = self._filter_acls(
                    acls, self._ACL_ACTION_METER, acl_dir, acl_type)

                if not _acls:
                    acl = self._create_acl(
                        acl_dir, acl_type, self._ACL_ACTION_METER)
                    self._jobutils.add_virt_feature(acl, port)

    def enable_control_metrics(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return

        metric_svc = self._conn.Msvm_MetricService()[0]
        metric_names = [self._NET_IN_METRIC_NAME, self._NET_OUT_METRIC_NAME]

        for metric_name in metric_names:
            metric_def = self._conn.CIM_BaseMetricDefinition(Name=metric_name)
            if metric_def:
                metric_svc.ControlMetrics(
                    Subject=port.path_(),
                    Definition=metric_def[0].path_(),
                    MetricCollectionEnabled=self._METRIC_ENABLED)

    def can_enable_control_metrics(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return False

        if not self._is_port_vm_started(port):
            return False

        # all 4 meter ACLs must be existent first. (2 x direction)
        acls = port.associators(wmi_result_class=self._PORT_ALLOC_ACL_SET_DATA)
        acls = [a for a in acls if a.Action == self._ACL_ACTION_METER]
        if len(acls) < 2:
            return False
        return True

    def _is_port_vm_started(self, port):
        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        vmsettings = port.associators(
            wmi_result_class=self._VIRTUAL_SYSTEM_SETTING_DATA)
        # See http://msdn.microsoft.com/en-us/library/cc160706%28VS.85%29.aspx
        (ret_val, summary_info) = vs_man_svc.GetSummaryInformation(
            [self._VM_SUMMARY_ENABLED_STATE],
            [v.path_() for v in vmsettings])
        if ret_val or not summary_info:
            raise exceptions.HyperVException(_('Cannot get VM summary data '
                                               'for: %s') % port.ElementName)

        return summary_info[0].EnabledState is self._HYPERV_VM_STATE_ENABLED

    def create_security_rules(self, switch_port_name, sg_rules):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return

        self._bind_security_rules(port, sg_rules)

    def remove_security_rules(self, switch_port_name, sg_rules):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            # Port not found. It happens when the VM was already deleted.
            return

        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)
        remove_acls = []
        for sg_rule in sg_rules:
            filtered_acls = self._filter_security_acls(sg_rule, acls)
            remove_acls.extend(filtered_acls)

        if remove_acls:
            self._jobutils.remove_multiple_virt_features(remove_acls)

    def remove_all_security_rules(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            # Port not found. It happens when the VM was already deleted.
            return

        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)
        filtered_acls = [a for a in acls if
                         a.Action is not self._ACL_ACTION_METER]

        if filtered_acls:
            self._jobutils.remove_multiple_virt_features(filtered_acls)

    def _bind_security_rules(self, port, sg_rules):
        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)

        # Add the ACL only if it don't already exist.
        add_acls = []
        weights = self._get_new_weights(sg_rules, acls)
        index = 0

        for sg_rule in sg_rules:
            filtered_acls = self._filter_security_acls(sg_rule, acls)
            if filtered_acls:
                # ACL already exists.
                continue

            acl = self._create_security_acl(sg_rule, weights[index])
            add_acls.append(acl)
            index += 1

            # append sg_rule the acls list, to make sure that the same rule
            # is not processed twice.
            acls.append(sg_rule)

            # yielding to other threads that must run (like state reporting)
            greenthread.sleep()

        if add_acls:
            self._jobutils.add_multiple_virt_features(add_acls, port)

    def _create_acl(self, direction, acl_type, action):
        acl = self._get_default_setting_data(self._PORT_ALLOC_ACL_SET_DATA)
        acl.set(Direction=direction,
                AclType=acl_type,
                Action=action,
                Applicability=self._ACL_APPLICABILITY_LOCAL)
        return acl

    def _create_security_acl(self, sg_rule, weight):
        acl = self._get_default_setting_data(self._PORT_EXT_ACL_SET_DATA)
        acl.set(**sg_rule.to_dict())
        return acl

    def _filter_acls(self, acls, action, direction, acl_type, remote_addr=""):
        return [v for v in acls
                if v.Action == action and
                v.Direction == direction and
                v.AclType == acl_type and
                v.RemoteAddress == remote_addr]

    def _filter_security_acls(self, sg_rule, acls):
        return [a for a in acls if sg_rule == a]

    def _get_new_weights(self, sg_rules, existent_acls):
        """Computes the weights needed for given sg_rules.

        :param sg_rules: ACLs to be added. They must have the same Action.
        :existent_acls: ACLs already bound to a switch port.
        :return: list of weights which will be used to create ACLs. List will
                 have the recommended order for sg_rules' Action.
        """
        return [0] * len(sg_rules)


class NetworkUtilsR2(NetworkUtils):
    _PORT_EXT_ACL_SET_DATA = 'Msvm_EthernetSwitchPortExtendedAclSettingData'
    _MAX_WEIGHT = 65500

    # 2 directions x 2 address types x 4 protocols = 16 ACLs
    _REJECT_ACLS_COUNT = 16

    def _create_security_acl(self, sg_rule, weight):
        acl = super(NetworkUtilsR2, self)._create_security_acl(sg_rule,
                                                               weight)
        acl.Weight = weight
        return acl

    def _get_new_weights(self, sg_rules, existent_acls):
        sg_rule = sg_rules[0]
        num_rules = len(sg_rules)
        existent_acls = [a for a in existent_acls
                         if a.Action == sg_rule.Action]
        if not existent_acls:
            if sg_rule.Action == self._ACL_ACTION_DENY:
                return range(1, 1 + num_rules)
            else:
                return range(self._MAX_WEIGHT - 1,
                             self._MAX_WEIGHT - 1 - num_rules, - 1)

        # there are existent ACLs.
        weights = [a.Weight for a in existent_acls]
        if sg_rule.Action == self._ACL_ACTION_DENY:
            return [i for i in range(1, self._REJECT_ACLS_COUNT + 1)
                    if i not in weights][:num_rules]

        min_weight = min(weights)
        last_weight = min_weight - num_rules - 1
        if last_weight > self._REJECT_ACLS_COUNT:
            return range(min_weight - 1, last_weight, - 1)

        # not enough weights. Must search for available weights.
        # if it is this case, num_rules is a small number.
        current_weight = self._MAX_WEIGHT - 1
        new_weights = []
        for i in range(num_rules):
            while current_weight in weights:
                current_weight -= 1
            new_weights.append(current_weight)

        return new_weights
