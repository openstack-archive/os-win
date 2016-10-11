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

import ctypes
import sys

from os_win.utils.io import ioutils

if sys.platform == 'win32':
    iscsidsc = ctypes.windll.iscsidsc

DEFAULT_ISCSI_PORT = 3260
ISCSI_ANY_INITIATOR_PORT = -1
ISCSI_ALL_INITIATOR_PORTS = -1
ISCSI_DEFAULT_SECURITY_FLAGS = 0
MAX_ISCSI_PORTAL_NAME_LEN = 256
MAX_ISCSI_PORTAL_ADDRESS_LEN = 256
MAX_ISCSI_NAME_LEN = 223
MAX_ISCSI_HBANAME_LEN = 256
MAX_PATH = 260
SENSE_BUFF_SIZE = 18

PUCHAR = ctypes.POINTER(ctypes.c_ubyte)

ISCSI_SECURITY_FLAGS = ctypes.c_ulonglong
ISCSI_LOGIN_FLAGS = ctypes.c_uint32
ISCSI_LOGIN_OPTIONS_INFO_SPECIFIED = ctypes.c_uint32
ISCSI_AUTH_TYPES = ctypes.c_int
ISCSI_DIGEST_TYPES = ctypes.c_int

DEVICE_TYPE = ctypes.c_ulong
FILE_DEVICE_DISK = 7

ISCSI_LOGIN_FLAG_MULTIPATH_ENABLED = 2
ISCSI_LOGIN_OPTIONS_USERNAME = 0x00000020
ISCSI_LOGIN_OPTIONS_PASSWORD = 0x00000040
ISCSI_LOGIN_OPTIONS_AUTH_TYPE = 0x00000080

ERROR_INSUFFICIENT_BUFFER = 122


class GUID(ctypes.Structure):
    # This is also used in virdisk_structures.py, we should move
    # common structures to a common module.
    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_byte * 8)]


class ISCSI_TARGET_PORTAL(ctypes.Structure):
    _fields_ = [('SymbolicName', ctypes.c_wchar * MAX_ISCSI_PORTAL_NAME_LEN),
                ('Address', ctypes.c_wchar * MAX_ISCSI_PORTAL_ADDRESS_LEN),
                ('Socket', ctypes.c_ushort)]


class ISCSI_LOGIN_OPTIONS(ctypes.Structure):
    _fields_ = [('Version', ctypes.c_ulong),
                ('InformationSpecified', ISCSI_LOGIN_OPTIONS_INFO_SPECIFIED),
                ('LoginFlags', ISCSI_LOGIN_FLAGS),
                ('AuthType', ISCSI_AUTH_TYPES),
                ('HeaderDigest', ISCSI_DIGEST_TYPES),
                ('DataDigest', ISCSI_DIGEST_TYPES),
                ('MaximumConnections', ctypes.c_ulong),
                ('DefaultTime2Wait', ctypes.c_ulong),
                ('DefaultTime2Retain', ctypes.c_ulong),
                ('UsernameLength', ctypes.c_ulong),
                ('PasswordLength', ctypes.c_ulong),
                ('Username', PUCHAR),
                ('Password', PUCHAR)]

    def __init__(self, Username=None, Password=None, AuthType=None,
                 LoginFlags=0):
        info_bitmap = 0
        if Username:
            username_buff = ioutils.IOUtils.get_buffer(len(Username),
                                                       Username)
            self.Username = ctypes.cast(username_buff, PUCHAR)
            self.UsernameLength = len(Username)
            info_bitmap |= ISCSI_LOGIN_OPTIONS_USERNAME
        if Password:
            pwd_buff = ioutils.IOUtils.get_buffer(len(Password),
                                                  Password)
            self.Password = ctypes.cast(pwd_buff, PUCHAR)
            self.PasswordLength = len(Password)
            info_bitmap |= ISCSI_LOGIN_OPTIONS_PASSWORD
        if AuthType is not None:
            self.AuthType = AuthType
            info_bitmap |= ISCSI_LOGIN_OPTIONS_AUTH_TYPE
        self.InformationSpecified = info_bitmap
        self.LoginFlags = LoginFlags


class SCSI_LUN_LIST(ctypes.Structure):
    _fields_ = [('OSLUN', ctypes.c_ulonglong),
                ('TargetLUN', ctypes.c_ulonglong)]


class ISCSI_UNIQUE_SESSION_ID(ctypes.Structure):
    _fields_ = [('AdapterUnique', ctypes.c_ulonglong),
                ('AdapterSpecific', ctypes.c_ulonglong)]


class ISCSI_UNIQUE_CONNECTION_ID(ISCSI_UNIQUE_SESSION_ID):
    pass


class ISCSI_TARGET_MAPPING(ctypes.Structure):
    _fields_ = [('InitiatorName', ctypes.c_wchar * MAX_ISCSI_HBANAME_LEN),
                ('TargetName', ctypes.c_wchar * (MAX_ISCSI_NAME_LEN + 1)),
                ('OSDeviceName', ctypes.c_wchar * MAX_PATH),
                ('SessionId', ISCSI_UNIQUE_SESSION_ID),
                ('OSBusNumber', ctypes.c_ulong),
                ('OSTargetNumber', ctypes.c_ulong),
                ('LUNCount', ctypes.c_ulong),
                ('LUNList', ctypes.POINTER(SCSI_LUN_LIST))]


PISCSI_TARGET_PORTAL = ctypes.POINTER(ISCSI_TARGET_PORTAL)
PISCSI_TARGET_MAPPING = ctypes.POINTER(ISCSI_TARGET_MAPPING)


class PERSISTENT_ISCSI_LOGIN_INFO(ctypes.Structure):
    _fields_ = [('TargetName', ctypes.c_wchar * (MAX_ISCSI_NAME_LEN + 1)),
                ('IsInformationalSession', ctypes.c_bool),
                ('InitiatorInstance', ctypes.c_wchar * MAX_ISCSI_HBANAME_LEN),
                ('InitiatorPortNumber', ctypes.c_ulong),
                ('TargetPortal', ISCSI_TARGET_PORTAL),
                ('SecurityFlags', ISCSI_SECURITY_FLAGS),
                ('Mappings', PISCSI_TARGET_MAPPING),
                ('LoginOptions', ISCSI_LOGIN_OPTIONS)]


class ISCSI_CONNECTION_INFO(ctypes.Structure):
    _fields_ = [('ConnectionId', ISCSI_UNIQUE_CONNECTION_ID),
                ('InitiatorAddress', ctypes.c_wchar_p),
                ('TargetAddress', ctypes.c_wchar_p),
                ('InitiatorSocket', ctypes.c_ushort),
                ('TargetSocket', ctypes.c_ushort),
                ('CID', ctypes.c_ubyte * 2)]


class ISCSI_SESSION_INFO(ctypes.Structure):
    _fields_ = [('SessionId', ISCSI_UNIQUE_SESSION_ID),
                ('InitiatorName', ctypes.c_wchar_p),
                ('TargetName', ctypes.c_wchar_p),
                ('TargetNodeName', ctypes.c_wchar_p),
                ('ISID', ctypes.c_ubyte * 6),
                ('TSID', ctypes.c_ubyte * 2),
                ('ConnectionCount', ctypes.c_ulong),
                ('Connections', ctypes.POINTER(ISCSI_CONNECTION_INFO))]


class SCSI_ADDRESS(ctypes.Structure):
    _fields_ = [('Length', ctypes.c_ulong),
                ('PortNumber', ctypes.c_ubyte),
                ('PathId', ctypes.c_ubyte),
                ('TargetId', ctypes.c_ubyte),
                ('Lun', ctypes.c_ubyte)]


class STORAGE_DEVICE_NUMBER(ctypes.Structure):
    _fields_ = [('DeviceType', DEVICE_TYPE),
                ('DeviceNumber', ctypes.c_long),
                ('PartitionNumber', ctypes.c_ulong)]


class ISCSI_DEVICE_ON_SESSION(ctypes.Structure):
    _fields_ = [('InitiatorName', ctypes.c_wchar * MAX_ISCSI_HBANAME_LEN),
                ('TargetName', ctypes.c_wchar * (MAX_ISCSI_NAME_LEN + 1)),
                ('ScsiAddress', SCSI_ADDRESS),
                ('DeviceInterfaceType', GUID),
                ('DeviceInterfaceName', ctypes.c_wchar * MAX_PATH),
                ('LegacyName', ctypes.c_wchar * MAX_PATH),
                ('StorageDeviceNumber', STORAGE_DEVICE_NUMBER),
                ('DeviceInstance', ctypes.c_ulong)]
