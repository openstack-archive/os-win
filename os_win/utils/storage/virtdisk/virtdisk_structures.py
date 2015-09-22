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

import ctypes
from ctypes import wintypes

from os_win.utils.storage.virtdisk import (
    virtdisk_constants as vdisk_const)


class Win32_GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", wintypes.BYTE * 8)]


WIN32_VIRTUAL_STORAGE_TYPE_MSFT = Win32_GUID(
    Data1=0xec984aec,
    Data2=0xa0f9,
    Data3=0x47e9,
    Data4=(wintypes.BYTE * 8)(0x90, 0x1f, 0x71, 0x41,
                              0x5a, 0x66, 0x34, 0x5b))


class Win32_VIRTUAL_STORAGE_TYPE(ctypes.Structure):
    _fields_ = [
        ('DeviceId', wintypes.ULONG),
        ('VendorId', Win32_GUID)
    ]

    def __init__(self, *args, **kwargs):
        self.VendorId = WIN32_VIRTUAL_STORAGE_TYPE_MSFT
        super(Win32_VIRTUAL_STORAGE_TYPE, self).__init__(*args, **kwargs)


class Win32_RESIZE_VIRTUAL_DISK_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ('Version', wintypes.DWORD),
        ('NewSize', ctypes.c_ulonglong)
    ]

    def __init__(self, *args, **kwargs):
        self.Version = vdisk_const.RESIZE_VIRTUAL_DISK_VERSION_1
        super(Win32_RESIZE_VIRTUAL_DISK_PARAMETERS, self).__init__(
            *args, **kwargs)


class Win32_OPEN_VIRTUAL_DISK_PARAMETERS_V1(ctypes.Structure):
    _fields_ = [
        ('Version', wintypes.DWORD),
        ('RWDepth', ctypes.c_ulong),
    ]

    def __init__(self, *args, **kwargs):
        self.Version = vdisk_const.OPEN_VIRTUAL_DISK_VERSION_1
        super(Win32_OPEN_VIRTUAL_DISK_PARAMETERS_V1, self).__init__(
            *args, **kwargs)


class Win32_OPEN_VIRTUAL_DISK_PARAMETERS_V2(ctypes.Structure):
    _fields_ = [
        ('Version', wintypes.DWORD),
        ('GetInfoOnly', wintypes.BOOL),
        ('ReadOnly', wintypes.BOOL),
        ('ResiliencyGuid', Win32_GUID)
    ]

    def __init__(self, *args, **kwargs):
        self.Version = vdisk_const.OPEN_VIRTUAL_DISK_VERSION_2
        super(Win32_OPEN_VIRTUAL_DISK_PARAMETERS_V2, self).__init__(
            *args, **kwargs)


class Win32_MERGE_VIRTUAL_DISK_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ('Version', wintypes.DWORD),
        ('MergeDepth', ctypes.c_ulong)
    ]

    def __init__(self, *args, **kwargs):
        self.Version = vdisk_const.MERGE_VIRTUAL_DISK_VERSION_1
        super(Win32_MERGE_VIRTUAL_DISK_PARAMETERS, self).__init__(
            *args, **kwargs)


class Win32_CREATE_VIRTUAL_DISK_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ('Version', wintypes.DWORD),
        ('UniqueId', Win32_GUID),
        ('MaximumSize', ctypes.c_ulonglong),
        ('BlockSizeInBytes', wintypes.ULONG),
        ('SectorSizeInBytes', wintypes.ULONG),
        ('PhysicalSectorSizeInBytes', wintypes.ULONG),
        ('ParentPath', wintypes.LPCWSTR),
        ('SourcePath', wintypes.LPCWSTR),
        ('OpenFlags', wintypes.DWORD),
        ('ParentVirtualStorageType', Win32_VIRTUAL_STORAGE_TYPE),
        ('SourceVirtualStorageType', Win32_VIRTUAL_STORAGE_TYPE),
        ('ResiliencyGuid', Win32_GUID)
    ]

    def __init__(self, *args, **kwargs):
        self.Version = vdisk_const.CREATE_VIRTUAL_DISK_VERSION_2

        # The kwargs can override the defaults specified bellow.
        self.PhysicalSectorSizeInBytes = (
            vdisk_const.VIRTUAL_DISK_DEFAULT_PHYS_SECTOR_SIZE)
        self.BlockSizeInBytes = (
            vdisk_const.CREATE_VHD_PARAMS_DEFAULT_BLOCK_SIZE)
        self.SectorSizeInBytes = (
            vdisk_const.VIRTUAL_DISK_DEFAULT_SECTOR_SIZE)

        super(Win32_CREATE_VIRTUAL_DISK_PARAMETERS, self).__init__(
            *args, **kwargs)


class Win32_SIZE(ctypes.Structure):
    _fields_ = [("VirtualSize", wintypes.ULARGE_INTEGER),
                ("PhysicalSize", wintypes.ULARGE_INTEGER),
                ("BlockSize", wintypes.ULONG),
                ("SectorSize", wintypes.ULONG)]


class Win32_PARENT_LOCATION(ctypes.Structure):
    _fields_ = [('ParentResolved', wintypes.BOOL),
                ('ParentPath', wintypes.WCHAR * 512)]


class Win32_PHYSICAL_DISK(ctypes.Structure):
    _fields_ = [("LogicalSectorSize", wintypes.ULONG),
                ("PhysicalSectorSize", wintypes.ULONG),
                ("IsRemote", wintypes.BOOL)]


class Win32_VHD_INFO(ctypes.Union):
    _fields_ = [("Size", Win32_SIZE),
                ("Identifier", Win32_GUID),
                ("ParentLocation", Win32_PARENT_LOCATION),
                ("ParentIdentifier", Win32_GUID),
                ("ParentTimestamp", wintypes.ULONG),
                ("VirtualStorageType", Win32_VIRTUAL_STORAGE_TYPE),
                ("ProviderSubtype", wintypes.ULONG),
                ("Is4kAligned", wintypes.BOOL),
                ("PhysicalDisk", Win32_PHYSICAL_DISK),
                ("VhdPhysicalSectorSize", wintypes.ULONG),
                ("SmallestSafeVirtualSize",
                    wintypes.ULARGE_INTEGER),
                ("FragmentationPercentage", wintypes.ULONG)]


class Win32_GET_VIRTUAL_DISK_INFO_PARAMETERS(ctypes.Structure):
    _fields_ = [("VERSION", wintypes.UINT),
                ("VhdInfo", Win32_VHD_INFO)]


class Win32_SET_VIRTUAL_DISK_INFO_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ('Version', wintypes.DWORD),
        ('ParentFilePath', wintypes.LPCWSTR)
    ]

    def __init__(self, *args, **kwargs):
        self.Version = vdisk_const.SET_VIRTUAL_DISK_INFO_PARENT_PATH
        super(Win32_SET_VIRTUAL_DISK_INFO_PARAMETERS, self).__init__(
            *args, **kwargs)
