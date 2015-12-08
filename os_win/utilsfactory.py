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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from os_win._i18n import _, _LW  # noqa
from os_win import exceptions
from os_win.utils import hostutils
from os_win.utils.io import namedpipe
from os_win.utils.storage.initiator import iscsi_cli_utils

hyper_opts = [
    cfg.BoolOpt('force_volumeutils_v1',
                default=False,
                help='Force V1 volume utility class'),
]

CONF = cfg.CONF
CONF.register_opts(hyper_opts, 'hyperv')

LOG = logging.getLogger(__name__)

utils = hostutils.HostUtils()

utils_map = {
    'hostutils': {
        'HostUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.hostutils.HostUtils'}},
    'iscsi_initiator_utils': {
        'ISCSIInitiatorCLIUtils': {
            'min_version': 6.0,
            'max_version': 6.2,
            'path': 'os_win.utils.storage.initiator.iscsi_cli_utils.'
                    'ISCSIInitiatorCLIUtils'},
        'ISCSIInitiatorWMIUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.storage.initiator.iscsi_wmi_utils.'
                    'ISCSIInitiatorWMIUtils'}},
    'iscsi_target_utils': {
        'ISCSITargetUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.storage.target.iscsi_target_utils.'
                    'ISCSITargetUtils'}},
    'fc_utils': {
        'FCUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.storage.initiator.fc_utils.'
                    'FCUtils'}},
    'livemigrationutils': {
        'LiveMigrationUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.compute.livemigrationutils.'
                    'LiveMigrationUtils'}},
    'networkutils': {
        'NetworkUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.network.networkutils.NetworkUtils'}},
    'pathutils': {
        'PathUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.pathutils.PathUtils'}},
    'rdpconsoleutils': {
        'RDPConsoleUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.compute.rdpconsoleutils.RDPConsoleUtils'}},
    'smbutils': {
        'SMBUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.storage.smbutils.SMBUtils'}},
    'vhdutils': {
        'VHDUtils': {
            'min_version': 6.2,
            'max_version': None,
            'path': 'os_win.utils.storage.virtdisk.vhdutils.VHDUtils'}},
    'vmutils': {
        'VMUtils': {
            'min_version': 6.2,
            'max_version': 10,
            'path': 'os_win.utils.compute.vmutils.VMUtils'},
        'VMUtils10': {
            'min_version': 10,
            'max_version': None,
            'path': 'os_win.utils.compute.vmutils10.VMUtils10'}},
}


def _get_class(class_type):
    if class_type not in utils_map:
        raise exceptions.HyperVException(_('Class type %s does '
                                           'not exist') % class_type)

    windows_version = utils.get_windows_version()
    build = list(map(int, windows_version.split('.')))
    windows_version = float("%i.%i" % (build[0], build[1]))

    existing_classes = utils_map.get(class_type)
    for class_variant in existing_classes.keys():
        utils_class = existing_classes.get(class_variant)
        if (utils_class['min_version'] <= windows_version and
                (utils_class['max_version'] is None or
                 windows_version < utils_class['max_version'])):
            return importutils.import_object(utils_class['path'])

    raise exceptions.HyperVException(_('Could not find any %(class)s class for'
        'this Windows version: %(win_version)s')
        % {'class': class_type, 'win_version': windows_version})


def get_vmutils(host='.'):
    return _get_class(class_type='vmutils')


def get_vhdutils():
    return _get_class(class_type='vhdutils')


def get_networkutils():
    return _get_class(class_type='networkutils')


def get_hostutils():
    return _get_class(class_type='hostutils')


def get_pathutils():
    return _get_class(class_type='pathutils')


def get_iscsi_initiator_utils(use_iscsi_cli=False):
    use_iscsi_cli = use_iscsi_cli or CONF.hyperv.force_volumeutils_v1
    if use_iscsi_cli:
        return iscsi_cli_utils.ISCSIInitiatorCLIUtils()
    return _get_class(class_type='iscsi_initiator_utils')


def get_livemigrationutils():
    return _get_class(class_type='livemigrationutils')


def get_smbutils():
    return _get_class(class_type='smbutils')


def get_rdpconsoleutils():
    return _get_class(class_type='rdpconsoleutils')


def get_iscsi_target_utils():
    return _get_class(class_type='iscsi_target_utils')


def get_named_pipe_handler(*args, **kwargs):
    return namedpipe.NamedPipeHandler(*args, **kwargs)


def get_fc_utils():
    return _get_class(class_type='fc_utils')
