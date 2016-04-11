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
import functools
import re

from eventlet import greenthread
from eventlet import patcher
from eventlet import tpool
import sys

if sys.platform == 'win32':
    import wmi

from os_win._i18n import _
from os_win import exceptions
from os_win.utils import _wqlutils
from os_win.utils import baseutils
from os_win.utils import jobutils


class NetworkUtils(baseutils.BaseUtilsVirt):

    EVENT_TYPE_CREATE = "__InstanceCreationEvent"
    EVENT_TYPE_DELETE = "__InstanceDeletionEvent"

    _VNIC_SET_DATA = 'Msvm_SyntheticEthernetPortSettingData'
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

    _VNIC_LISTENER_TIMEOUT_MS = 2000

    _switches = {}
    _switch_ports = {}
    _vlan_sds = {}
    _vsid_sds = {}
    _sg_acl_sds = {}

    def __init__(self):
        super(NetworkUtils, self).__init__()
        self._jobutils = jobutils.JobUtils()

    def init_caches(self):
        for vswitch in self._conn.Msvm_VirtualEthernetSwitch():
            self._switches[vswitch.ElementName] = vswitch

        # map between switch port ID and switch port WMI object.
        for port in self._conn.Msvm_EthernetPortAllocationSettingData():
            self._switch_ports[port.ElementName] = port

        # VLAN and VSID setting data's InstanceID will contain the switch
        # port's InstanceID.
        switch_port_id_regex = re.compile(
            "Microsoft:[0-9A-F-]*\\\\[0-9A-F-]*\\\\[0-9A-F-]",
            flags=re.IGNORECASE)

        # map between switch port's InstanceID and their VLAN setting data WMI
        # objects.
        for vlan_sd in self._conn.Msvm_EthernetSwitchPortVlanSettingData():
            match = switch_port_id_regex.match(vlan_sd.InstanceID)
            if match:
                self._vlan_sds[match.group()] = vlan_sd

        # map between switch port's InstanceID and their VSID setting data WMI
        # objects.
        for vsid_sd in self._conn.Msvm_EthernetSwitchPortSecuritySettingData():
            match = switch_port_id_regex.match(vsid_sd.InstanceID)
            if match:
                self._vsid_sds[match.group()] = vsid_sd

    def update_cache(self):
        # map between switch port ID and switch port WMI object.
        self._switch_ports = {
            port.ElementName: port for port in
            self._conn.Msvm_EthernetPortAllocationSettingData()}

    def clear_port_sg_acls_cache(self, switch_port_name):
        self._sg_acl_sds.pop(switch_port_name, None)

    def get_vswitch_id(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        return vswitch.Name

    def get_vswitch_external_network_name(self, vswitch_name):
        ext_port = self._get_vswitch_external_port(vswitch_name)
        if ext_port:
            return ext_port.ElementName

    def _get_vswitch(self, vswitch_name):
        if vswitch_name in self._switches:
            return self._switches[vswitch_name]

        vswitch = self._conn.Msvm_VirtualEthernetSwitch(
            ElementName=vswitch_name)
        if not len(vswitch):
            raise exceptions.HyperVException(_('VSwitch not found: %s') %
                                             vswitch_name)

        self._switches[vswitch_name] = vswitch[0]
        return vswitch[0]

    def _get_vswitch_external_port(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        ext_ports = self._conn.Msvm_ExternalEthernetPort()
        for ext_port in ext_ports:
            lan_endpoint_assoc_list = (
                self._conn.Msvm_EthernetDeviceSAPImplementation(
                    Antecedent=ext_port.path_()))
            if lan_endpoint_assoc_list:
                lan_endpoint_assoc_list = self._conn.Msvm_ActiveConnection(
                    Dependent=lan_endpoint_assoc_list[0].Dependent.path_())
                if lan_endpoint_assoc_list:
                    lan_endpoint = lan_endpoint_assoc_list[0].Antecedent
                    if lan_endpoint.SystemName == vswitch.Name:
                        return ext_port

    def vswitch_port_needed(self):
        return False

    def get_switch_ports(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        vswitch_ports = self._conn.Msvm_EthernetSwitchPort(
            SystemName=vswitch.Name)
        return set(p.Name for p in vswitch_ports)

    def get_port_by_id(self, port_id, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        switch_ports = self._conn.Msvm_EthernetSwitchPort(
            SystemName=vswitch.Name)
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

    def get_vnic_mac_address(self, switch_port_name):
        vnic = self._get_vnic_settings(switch_port_name)
        return vnic.Address

    def _get_vnic_settings(self, vnic_name):
        vnic_settings = self._conn.Msvm_SyntheticEthernetPortSettingData(
            ElementName=vnic_name)
        if not vnic_settings:
            raise exceptions.HyperVException(
                message=_('Vnic not found: %s') % vnic_name)
        return vnic_settings[0]

    def get_vnic_event_listener(self, event_type):
        query = self._get_event_wql_query(cls=self._VNIC_SET_DATA,
                                          event_type=event_type,
                                          timeframe=2)
        listener = self._conn.Msvm_SyntheticEthernetPortSettingData.watch_for(
            query)

        def _poll_events(callback):
            if patcher.is_monkey_patched('thread'):
                listen = functools.partial(tpool.execute, listener,
                                           self._VNIC_LISTENER_TIMEOUT_MS)
            else:
                listen = functools.partial(listener,
                                           self._VNIC_LISTENER_TIMEOUT_MS)

            while True:
                # Retrieve one by one all the events that occurred in
                # the checked interval.
                try:
                    event = listen()
                    callback(event.ElementName)
                except wmi.x_wmi_timed_out:
                    # no new event published.
                    pass

        return _poll_events

    def _get_event_wql_query(self, cls, event_type, timeframe=2, **where):
        """Return a WQL query used for polling WMI events.

            :param cls: the Hyper-V class polled for events.
            :param event_type: the type of event expected.
            :param timeframe: check for events that occurred in
                              the specified timeframe.
            :param where: key-value arguments which are to be included in the
                          query. For example: like=dict(foo="bar").
        """
        like = where.pop('like', {})
        like_str = " AND ".join("TargetInstance.%s LIKE '%s%%'" % (k, v)
                                for k, v in like.items())
        like_str = "AND " + like_str if like_str else ""

        query = ("SELECT * FROM %(event_type)s WITHIN %(timeframe)s "
                 "WHERE TargetInstance ISA '%(class)s' %(like)s" % {
                     'class': cls,
                     'event_type': event_type,
                     'like': like_str,
                     'timeframe': timeframe})
        return query

    def connect_vnic_to_vswitch(self, vswitch_name, switch_port_name):
        port, found = self._get_switch_port_allocation(
            switch_port_name, create=True, expected=False)
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
        vmsettings_instance_id = res_setting_data.InstanceID.split('\\')[0]
        sd = self._conn.Msvm_VirtualSystemSettingData(
            InstanceID=vmsettings_instance_id)
        vm = self._conn.Msvm_ComputerSystem(Name=sd[0].ConfigurationID)
        return vm[0]

    def remove_switch_port(self, switch_port_name, vnic_deleted=False):
        """Removes the switch port."""
        sw_port, found = self._get_switch_port_allocation(switch_port_name,
                                                          expected=False)
        if not sw_port:
            # Port not found. It happens when the VM was already deleted.
            return

        if not vnic_deleted:
            try:
                self._jobutils.remove_virt_resource(sw_port)
            except wmi.x_wmi:
                # port may have already been destroyed by Hyper-V
                pass

        self._switch_ports.pop(switch_port_name, None)
        self._vlan_sds.pop(sw_port.InstanceID, None)
        self._vsid_sds.pop(sw_port.InstanceID, None)

    def set_vswitch_port_vlan_id(self, vlan_id, switch_port_name):
        port_alloc = self._get_switch_port_allocation(switch_port_name)[0]

        vlan_settings = self._get_vlan_setting_data_from_port_alloc(port_alloc)
        if vlan_settings:
            if (vlan_settings.OperationMode == self._OPERATION_MODE_ACCESS and
                    vlan_settings.AccessVlanId == vlan_id):
                # VLAN already set to corect value, no need to change it.
                return

            # Removing the feature because it cannot be modified
            # due to a wmi exception.
            self._jobutils.remove_virt_feature(vlan_settings)

            # remove from cache.
            self._vlan_sds.pop(port_alloc.InstanceID, None)

        vlan_settings = self._create_default_setting_data(
            self._PORT_VLAN_SET_DATA)
        vlan_settings.AccessVlanId = vlan_id
        vlan_settings.OperationMode = self._OPERATION_MODE_ACCESS
        self._jobutils.add_virt_feature(vlan_settings, port_alloc)

        # TODO(claudiub): This will help solve the missing VLAN issue, but it
        # comes with a performance cost. The root cause of the problem must
        # be solved.
        vlan_settings = self._get_vlan_setting_data_from_port_alloc(port_alloc)
        if not vlan_settings:
            raise exceptions.HyperVException(
                _('Port VLAN not found: %s') % switch_port_name)

    def set_vswitch_port_vsid(self, vsid, switch_port_name):
        port_alloc = self._get_switch_port_allocation(switch_port_name)[0]

        vsid_settings = self._get_security_setting_data_from_port_alloc(
            port_alloc)

        if vsid_settings:
            if vsid_settings.VirtualSubnetId == vsid:
                # VSID already added, no need to readd it.
                return
            # Removing the feature because it cannot be modified
            # due to a wmi exception.
            self._jobutils.remove_virt_feature(vsid_settings)

            # remove from cache.
            self._vsid_sds.pop(port_alloc.InstanceID, None)

        vsid_settings = self._create_default_setting_data(
            self._PORT_SECURITY_SET_DATA)
        vsid_settings.VirtualSubnetId = vsid
        self._jobutils.add_virt_feature(vsid_settings, port_alloc)

        # TODO(claudiub): This will help solve the missing VSID issue, but it
        # comes with a performance cost. The root cause of the problem must
        # be solved.
        vsid_settings = self._get_security_setting_data_from_port_alloc(
            port_alloc)
        if not vsid_settings:
            raise exceptions.HyperVException(
                _('Port VSID not found: %s') % switch_port_name)

    def _get_vlan_setting_data_from_port_alloc(self, port_alloc):
        return self._get_setting_data_from_port_alloc(
            port_alloc, self._vlan_sds, self._PORT_VLAN_SET_DATA)

    def _get_security_setting_data_from_port_alloc(self, port_alloc):
        return self._get_setting_data_from_port_alloc(
            port_alloc, self._vsid_sds, self._PORT_SECURITY_SET_DATA)

    def _get_setting_data_from_port_alloc(self, port_alloc, cache, data_class):
        if port_alloc.InstanceID in cache:
            return cache[port_alloc.InstanceID]

        setting_data = self._get_first_item(
            _wqlutils.get_element_associated_class(
                self._conn, data_class,
                element_instance_id=port_alloc.InstanceID))
        if setting_data:
            cache[port_alloc.InstanceID] = setting_data
        return setting_data

    def _get_switch_port_allocation(self, switch_port_name, create=False,
                                    expected=True):
        if switch_port_name in self._switch_ports:
            return self._switch_ports[switch_port_name], True

        switch_port, found = self._get_setting_data(
            self._PORT_ALLOC_SET_DATA,
            switch_port_name, create)

        if found:
            # newly created setting data cannot be cached, they do not
            # represent real objects yet.
            # if it was found, it means that it was not created.
            self._switch_ports[switch_port_name] = switch_port
        elif expected:
            raise exceptions.HyperVPortNotFoundException(
                port_name=switch_port_name)
        return switch_port, found

    def _get_setting_data(self, class_name, element_name, create=True):
        element_name = element_name.replace("'", '"')
        q = self._compat_conn.query("SELECT * FROM %(class_name)s WHERE "
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
        return self._compat_conn.query("SELECT * FROM %s WHERE InstanceID "
                                       "LIKE '%%\\Default'" % class_name)[0]

    def _create_default_setting_data(self, class_name):
        return getattr(self._compat_conn, class_name).new()

    def _get_first_item(self, obj):
        if obj:
            return obj[0]

    def add_metrics_collection_acls(self, switch_port_name):
        port = self._get_switch_port_allocation(switch_port_name)[0]

        # Add the ACLs only if they don't already exist
        acls = _wqlutils.get_element_associated_class(
            self._conn, self._PORT_ALLOC_ACL_SET_DATA,
            element_instance_id=port.InstanceID)
        for acl_type in [self._ACL_TYPE_IPV4, self._ACL_TYPE_IPV6]:
            for acl_dir in [self._ACL_DIR_IN, self._ACL_DIR_OUT]:
                _acls = self._filter_acls(
                    acls, self._ACL_ACTION_METER, acl_dir, acl_type)

                if not _acls:
                    acl = self._create_acl(
                        acl_dir, acl_type, self._ACL_ACTION_METER)
                    self._jobutils.add_virt_feature(acl, port)

    def is_metrics_collection_allowed(self, switch_port_name):
        port = self._get_switch_port_allocation(switch_port_name)[0]

        if not self._is_port_vm_started(port):
            return False

        # all 4 meter ACLs must be existent first. (2 x direction)
        acls = _wqlutils.get_element_associated_class(
            self._conn, self._PORT_ALLOC_ACL_SET_DATA,
            element_instance_id=port.InstanceID)
        acls = [a for a in acls if a.Action == self._ACL_ACTION_METER]
        if len(acls) < 2:
            return False
        return True

    def _is_port_vm_started(self, port):
        vmsettings_instance_id = port.InstanceID.split('\\')[0]
        vmsettings = self._conn.Msvm_VirtualSystemSettingData(
            InstanceID=vmsettings_instance_id)
        # See http://msdn.microsoft.com/en-us/library/cc160706%28VS.85%29.aspx
        (ret_val, summary_info) = self._vs_man_svc.GetSummaryInformation(
            [self._VM_SUMMARY_ENABLED_STATE],
            [v.path_() for v in vmsettings])
        if ret_val or not summary_info:
            raise exceptions.HyperVException(_('Cannot get VM summary data '
                                               'for: %s') % port.ElementName)

        return summary_info[0].EnabledState is self._HYPERV_VM_STATE_ENABLED

    def create_security_rules(self, switch_port_name, sg_rules):
        port = self._get_switch_port_allocation(switch_port_name)[0]

        self._bind_security_rules(port, sg_rules)

    def remove_security_rules(self, switch_port_name, sg_rules):
        port = self._get_switch_port_allocation(switch_port_name)[0]

        acls = _wqlutils.get_element_associated_class(
            self._conn, self._PORT_EXT_ACL_SET_DATA,
            element_instance_id=port.InstanceID)
        remove_acls = []
        for sg_rule in sg_rules:
            filtered_acls = self._filter_security_acls(sg_rule, acls)
            remove_acls.extend(filtered_acls)

        if remove_acls:
            self._jobutils.remove_multiple_virt_features(remove_acls)

            # remove the old ACLs from the cache.
            new_acls = [a for a in acls if a not in remove_acls]
            self._sg_acl_sds[port.ElementName] = new_acls

    def remove_all_security_rules(self, switch_port_name):
        port = self._get_switch_port_allocation(switch_port_name)[0]

        acls = _wqlutils.get_element_associated_class(
            self._conn, self._PORT_EXT_ACL_SET_DATA,
            element_instance_id=port.InstanceID)
        filtered_acls = [a for a in acls if
                         a.Action is not self._ACL_ACTION_METER]

        if filtered_acls:
            self._jobutils.remove_multiple_virt_features(filtered_acls)

            # clear the cache.
            self._sg_acl_sds[port.ElementName] = []

    def _bind_security_rules(self, port, sg_rules):
        acls = _wqlutils.get_element_associated_class(
            self._conn, self._PORT_EXT_ACL_SET_DATA,
            element_instance_id=port.InstanceID)

        # Add the ACL only if it don't already exist.
        add_acls = []
        processed_sg_rules = []
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
            processed_sg_rules.append(sg_rule)

            # yielding to other threads that must run (like state reporting)
            greenthread.sleep()

        if add_acls:
            self._jobutils.add_multiple_virt_features(add_acls, port)

            # caching the Security Group Rules that have been processed and
            # added to the port. The list should only be used to check the
            # existence of rules, nothing else.
            acls.extend(processed_sg_rules)

    def _get_port_security_acls(self, port):
        """Returns a mutable list of Security Group Rule objects.

        Returns the list of Security Group Rule objects from the cache,
        otherwise it fetches and caches from the port's associated class.
        """

        if port.ElementName in self._sg_acl_sds:
            return self._sg_acl_sds[port.ElementName]

        acls = _wqlutils.get_element_associated_class(
            self._conn, self._PORT_EXT_ACL_SET_DATA,
            element_instance_id=port.InstanceID)
        self._sg_acl_sds[port.ElementName] = acls

        return acls

    def _create_acl(self, direction, acl_type, action):
        acl = self._create_default_setting_data(self._PORT_ALLOC_ACL_SET_DATA)
        acl.set(Direction=direction,
                AclType=acl_type,
                Action=action,
                Applicability=self._ACL_APPLICABILITY_LOCAL)
        return acl

    def _create_security_acl(self, sg_rule, weight):
        # Acl instance can be created new eachtime, the object should be
        # of type ExtendedEthernetSettingsData.
        acl = self._create_default_setting_data(self._PORT_EXT_ACL_SET_DATA)
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
        sg_rule.Weight = weight
        return acl

    def _get_new_weights(self, sg_rules, existent_acls):
        sg_rule = sg_rules[0]
        num_rules = len(sg_rules)
        existent_acls = [a for a in existent_acls
                         if a.Action == sg_rule.Action]
        if not existent_acls:
            if sg_rule.Action == self._ACL_ACTION_DENY:
                return list(range(1, 1 + num_rules))
            else:
                return list(range(self._MAX_WEIGHT - 1,
                                  self._MAX_WEIGHT - 1 - num_rules, - 1))

        # there are existent ACLs.
        weights = [a.Weight for a in existent_acls]
        if sg_rule.Action == self._ACL_ACTION_DENY:
            return [i for i in list(range(1, self._REJECT_ACLS_COUNT + 1))
                    if i not in weights][:num_rules]

        min_weight = min(weights)
        last_weight = min_weight - num_rules - 1
        if last_weight > self._REJECT_ACLS_COUNT:
            return list(range(min_weight - 1, last_weight, - 1))

        # not enough weights. Must search for available weights.
        # if it is this case, num_rules is a small number.
        current_weight = self._MAX_WEIGHT - 1
        new_weights = []
        for i in list(range(num_rules)):
            while current_weight in weights:
                current_weight -= 1
            new_weights.append(current_weight)

        return new_weights
