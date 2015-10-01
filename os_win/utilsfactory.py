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

from os_win._i18n import _, _LW  # noqa
from os_win.utils.compute import livemigrationutils
from os_win.utils.compute import rdpconsoleutils
from os_win.utils.compute import vmutils
from os_win.utils import hostutils
from os_win.utils.network import networkutils
from os_win.utils import pathutils
from os_win.utils.storage.initiator import iscsi_cli_utils
from os_win.utils.storage.initiator import iscsi_wmi_utils
from os_win.utils.storage.target import iscsi_target_utils
from os_win.utils.storage.virtdisk import vhdutils

hyper_opts = [
    cfg.BoolOpt('force_volumeutils_v1',
                default=False,
                help='Force V1 volume utility class'),
]

CONF = cfg.CONF
CONF.register_opts(hyper_opts, 'hyperv')

LOG = logging.getLogger(__name__)

utils = hostutils.HostUtils()


def _get_class(v1_class, v2_class, force_v1_flag, *version):
    # V2 classes are supported starting from Hyper-V Server 2012 and
    # Windows Server 2012 (kernel version 6.2)
    if force_v1_flag:
        cls = v1_class
    elif version and not utils.check_min_windows_version(*version):
        cls = v1_class
    else:
        cls = v2_class
    LOG.debug("Loading class: %(module_name)s.%(class_name)s",
              {'module_name': cls.__module__, 'class_name': cls.__name__})
    return cls


def get_vmutils(host='.'):
    return vmutils.VMUtils(host)


def get_vhdutils():
    return vhdutils.VHDUtils()


def get_networkutils():
    return _get_class(networkutils.NetworkUtils, networkutils.NetworkUtilsR2,
                      False, 6, 3)()


def get_hostutils():
    return hostutils.HostUtils()


def get_pathutils():
    return pathutils.PathUtils()


def get_iscsi_initiator_utils(use_iscsi_cli=False):
    use_iscsi_cli = use_iscsi_cli or CONF.hyperv.force_volumeutils_v1
    return _get_class(iscsi_cli_utils.ISCSIInitiatorCLIUtils,
                      iscsi_wmi_utils.ISCSIInitiatorWMIUtils,
                      use_iscsi_cli)()


def get_livemigrationutils():
    return livemigrationutils.LiveMigrationUtils()


def get_rdpconsoleutils():
    return rdpconsoleutils.RDPConsoleUtils()


def get_iscsi_target_utils():
    return iscsi_target_utils.ISCSITargetUtils()
