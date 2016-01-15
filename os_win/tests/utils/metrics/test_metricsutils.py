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

import mock
from oslotest import base

from os_win import exceptions
from os_win.utils.metrics import metricsutils


class MetricsUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V MetricsUtils class."""

    _FAKE_RET_VAL = 0
    _FAKE_PORT = "fake's port name"

    @mock.patch.object(metricsutils.MetricsUtils, '_cache_metrics_defs')
    def setUp(self, mock_cache_metrics_defs):
        super(MetricsUtilsTestCase, self).setUp()
        self.utils = metricsutils.MetricsUtils()
        self.utils._conn = mock.MagicMock()

    def test_cache_metrics_defs_no_conn(self):
        self.utils._conn = None
        self.utils._cache_metrics_defs()
        self.assertEqual({}, self.utils._metrics_defs)

    @mock.patch.object(metricsutils.MetricsUtils, '_enable_metrics')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm_resources')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm')
    def test_enable_vm_metrics_collection(
            self, mock_get_vm, mock_get_vm_resources, mock_enable_metrics):
        mock_vm = mock_get_vm.return_value
        mock_disk = mock.MagicMock()
        mock_dvd = mock.MagicMock(
            ResourceSubType=self.utils._DVD_DISK_RES_SUB_TYPE)
        mock_get_vm_resources.return_value = [mock_disk, mock_dvd]

        self.utils.enable_vm_metrics_collection(mock.sentinel.vm_name)

        metrics_names = [self.utils._CPU_METRICS,
                         self.utils._MEMORY_METRICS]
        mock_enable_metrics.assert_has_calls(
            [mock.call(mock_disk), mock.call(mock_vm, metrics_names)])

    @mock.patch.object(metricsutils.MetricsUtils, '_enable_metrics')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_switch_port')
    def test_enable_switch_port_metrics_collection(self, mock_get_port,
                                                   mock_enable_metrics):
        self.utils.enable_port_metrics_collection(mock.sentinel.port_name)

        mock_get_port.assert_called_once_with(mock.sentinel.port_name)
        metrics = [self.utils._NET_IN_METRICS,
                   self.utils._NET_OUT_METRICS]
        mock_enable_metrics.assert_called_once_with(
            mock_get_port.return_value, metrics)

    def _check_enable_metrics(self, metrics=None, definition=None):
        mock_element = mock.MagicMock()

        self.utils._enable_metrics(mock_element, metrics)

        self.utils._metrics_svc.ControlMetrics.assert_called_once_with(
            Subject=mock_element.path_.return_value,
            Definition=definition,
            MetricCollectionEnabled=self.utils._METRICS_ENABLED)

    def test_enable_metrics_no_metrics(self):
        self._check_enable_metrics()

    def test_enable_metrics(self):
        metrics_name = self.utils._CPU_METRICS
        metrics_def = mock.MagicMock()
        self.utils._metrics_defs = {metrics_name: metrics_def}
        self._check_enable_metrics([metrics_name, mock.sentinel.metrics_name],
                                   metrics_def.path_.return_value)

    @mock.patch.object(metricsutils.MetricsUtils, '_get_metrics')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm_resources')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm')
    def test_get_cpu_metrics(self, mock_get_vm, mock_get_vm_resources,
                             mock_get_metrics):
        fake_cpu_count = 2
        fake_uptime = 1000
        fake_cpu_metrics_val = 2000

        self.utils._metrics_defs = {
            self.utils._CPU_METRICS: mock.sentinel.metrics}

        mock_vm = mock_get_vm.return_value
        mock_vm.OnTimeInMilliseconds = fake_uptime
        mock_cpu = mock.MagicMock(VirtualQuantity=fake_cpu_count)
        mock_get_vm_resources.return_value = [mock_cpu]

        mock_metric = mock.MagicMock(MetricValue=fake_cpu_metrics_val)
        mock_get_metrics.return_value = [mock_metric]

        cpu_metrics = self.utils.get_cpu_metrics(mock.sentinel.vm_name)

        self.assertEqual(3, len(cpu_metrics))
        self.assertEqual(fake_cpu_metrics_val, cpu_metrics[0])
        self.assertEqual(fake_cpu_count, cpu_metrics[1])
        self.assertEqual(fake_uptime, cpu_metrics[2])

        mock_get_vm.assert_called_once_with(mock.sentinel.vm_name)
        mock_get_vm_resources.assert_called_once_with(
            mock.sentinel.vm_name, self.utils._PROCESSOR_SETTING_DATA_CLASS)
        mock_get_metrics.assert_called_once_with(mock_vm,
                                                 mock.sentinel.metrics)

    @mock.patch.object(metricsutils.MetricsUtils, '_get_metrics')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm')
    def test_get_memory_metrics(self, mock_get_vm, mock_get_metrics):
        mock_vm = mock_get_vm.return_value
        self.utils._metrics_defs = {
            self.utils._MEMORY_METRICS: mock.sentinel.metrics}

        metrics_memory = mock.MagicMock()
        metrics_memory.MetricValue = 3
        mock_get_metrics.return_value = [metrics_memory]

        response = self.utils.get_memory_metrics(mock.sentinel.vm_name)

        self.assertEqual(3, response)
        mock_get_vm.assert_called_once_with(mock.sentinel.vm_name)
        mock_get_metrics.assert_called_once_with(mock_vm,
                                                 mock.sentinel.metrics)

    @mock.patch.object(metricsutils.MetricsUtils,
                       '_sum_metrics_values_by_defs')
    @mock.patch.object(metricsutils.MetricsUtils,
                       '_get_metrics_value_instances')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm_resources')
    def test_get_vnic_metrics(self, mock_get_vm_resources,
                              mock_get_value_instances, mock_sum_by_defs):
        fake_rx_mb = 1000
        fake_tx_mb = 2000

        self.utils._metrics_defs = {
            self.utils._NET_IN_METRICS: mock.sentinel.net_in_metrics,
            self.utils._NET_OUT_METRICS: mock.sentinel.net_out_metrics}

        mock_port = mock.MagicMock(Parent=mock.sentinel.vnic_path)
        mock_vnic = mock.MagicMock(ElementName=mock.sentinel.element_name,
                                   Address=mock.sentinel.address)
        mock_vnic.path_.return_value = mock.sentinel.vnic_path
        mock_get_vm_resources.side_effect = [[mock_port], [mock_vnic]]
        mock_sum_by_defs.return_value = [fake_rx_mb, fake_tx_mb]

        vnic_metrics = list(
            self.utils.get_vnic_metrics(mock.sentinel.vm_name))

        self.assertEqual(1, len(vnic_metrics))
        self.assertEqual(fake_rx_mb, vnic_metrics[0]['rx_mb'])
        self.assertEqual(fake_tx_mb, vnic_metrics[0]['tx_mb'])
        self.assertEqual(mock.sentinel.element_name,
                         vnic_metrics[0]['element_name'])
        self.assertEqual(mock.sentinel.address, vnic_metrics[0]['address'])

        mock_get_vm_resources.assert_has_calls([
            mock.call(mock.sentinel.vm_name, self.utils._PORT_ALLOC_SET_DATA),
            mock.call(mock.sentinel.vm_name,
                      self.utils._SYNTH_ETH_PORT_SET_DATA)])
        mock_get_value_instances.assert_called_once_with(
            mock_port.associators.return_value, self.utils._BASE_METRICS_VALUE)
        mock_sum_by_defs.assert_called_once_with(
            mock_get_value_instances.return_value,
            [mock.sentinel.net_in_metrics, mock.sentinel.net_out_metrics])

    @mock.patch.object(metricsutils.MetricsUtils, '_get_metrics_values')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm_resources')
    def test_get_disk_metrics(self, mock_get_vm_resources,
                              mock_get_metrics_values):
        fake_read_mb = 1000
        fake_write_mb = 2000

        self.utils._metrics_defs = {
            self.utils._DISK_RD_METRICS: mock.sentinel.disk_rd_metrics,
            self.utils._DISK_WR_METRICS: mock.sentinel.disk_wr_metrics}

        mock_disk = mock.MagicMock(HostResource=[mock.sentinel.host_resource],
                                   InstanceID=mock.sentinel.instance_id)
        mock_get_vm_resources.return_value = [mock_disk]
        mock_get_metrics_values.return_value = [fake_read_mb, fake_write_mb]

        disk_metrics = list(
            self.utils.get_disk_metrics(mock.sentinel.vm_name))

        self.assertEqual(1, len(disk_metrics))
        self.assertEqual(fake_read_mb, disk_metrics[0]['read_mb'])
        self.assertEqual(fake_write_mb, disk_metrics[0]['write_mb'])
        self.assertEqual(mock.sentinel.instance_id,
                         disk_metrics[0]['instance_id'])
        self.assertEqual(mock.sentinel.host_resource,
                         disk_metrics[0]['host_resource'])

        mock_get_vm_resources.assert_called_once_with(
            mock.sentinel.vm_name,
            self.utils._STORAGE_ALLOC_SETTING_DATA_CLASS)
        metrics = [mock.sentinel.disk_rd_metrics,
                   mock.sentinel.disk_wr_metrics]
        mock_get_metrics_values.assert_called_once_with(mock_disk, metrics)

    @mock.patch.object(metricsutils.MetricsUtils, '_get_metrics_values')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm_resources')
    def test_get_disk_latency_metrics(self, mock_get_vm_resources,
                                      mock_get_metrics_values):
        self.utils._metrics_defs = {
            self.utils._DISK_LATENCY_METRICS: mock.sentinel.metrics}

        mock_disk = mock.MagicMock(HostResource=[mock.sentinel.host_resource],
                                   InstanceID=mock.sentinel.instance_id)
        mock_get_vm_resources.return_value = [mock_disk]
        mock_get_metrics_values.return_value = [mock.sentinel.latency]

        disk_metrics = list(
            self.utils.get_disk_latency_metrics(mock.sentinel.vm_name))

        self.assertEqual(1, len(disk_metrics))
        self.assertEqual(mock.sentinel.latency,
                         disk_metrics[0]['disk_latency'])
        self.assertEqual(mock.sentinel.instance_id,
                         disk_metrics[0]['instance_id'])
        mock_get_vm_resources.assert_called_once_with(
            mock.sentinel.vm_name,
            self.utils._STORAGE_ALLOC_SETTING_DATA_CLASS)
        mock_get_metrics_values.assert_called_once_with(
            mock_disk, [mock.sentinel.metrics])

    @mock.patch.object(metricsutils.MetricsUtils, '_get_metrics_values')
    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm_resources')
    def test_get_disk_iops_metrics(self, mock_get_vm_resources,
                                   mock_get_metrics_values):
        self.utils._metrics_defs = {
            self.utils._DISK_IOPS_METRICS: mock.sentinel.metrics}
        mock_disk = mock.MagicMock(HostResource=[mock.sentinel.host_resource],
                                   InstanceID=mock.sentinel.instance_id)
        mock_get_vm_resources.return_value = [mock_disk]
        mock_get_metrics_values.return_value = [mock.sentinel.iops]

        disk_metrics = list(
            self.utils.get_disk_iops_count(mock.sentinel.vm_name))

        self.assertEqual(1, len(disk_metrics))
        self.assertEqual(mock.sentinel.iops,
                         disk_metrics[0]['iops_count'])
        self.assertEqual(mock.sentinel.instance_id,
                         disk_metrics[0]['instance_id'])
        mock_get_vm_resources.assert_called_once_with(
            mock.sentinel.vm_name,
            self.utils._STORAGE_ALLOC_SETTING_DATA_CLASS)
        mock_get_metrics_values.assert_called_once_with(
            mock_disk, [mock.sentinel.metrics])

    def test_sum_metrics_values(self):
        mock_metric = mock.MagicMock(MetricValue='100')
        result = self.utils._sum_metrics_values([mock_metric] * 2)
        self.assertEqual(200, result)

    def test_sum_metrics_values_by_defs(self):
        mock_metric = mock.MagicMock(MetricDefinitionId=mock.sentinel.def_id,
                                     MetricValue='100')
        mock_metric_useless = mock.MagicMock(MetricValue='200')
        mock_metric_def = mock.MagicMock(Id=mock.sentinel.def_id)

        result = self.utils._sum_metrics_values_by_defs(
            [mock_metric, mock_metric_useless], [None, mock_metric_def])

        self.assertEqual([0, 100], result)

    def test_get_metrics_value_instances(self):
        mock_element = mock.MagicMock()
        mock_associator = mock.MagicMock()
        mock_element.associators.return_value = [mock_associator]

        mock_element2 = mock.MagicMock()
        mock_element2.associators.return_value = []

        returned = self.utils._get_metrics_value_instances(
            [mock_element, mock_element2], mock.sentinel.result_class)

        self.assertEqual([mock_associator], returned)

    @mock.patch.object(metricsutils.MetricsUtils, '_filter_metrics')
    def test_get_metrics(self, mock_filter_metrics):
        mock_metric = mock.MagicMock()
        mock_element = mock.MagicMock()
        mock_element.associators.return_value = [mock_metric]

        result = self.utils._get_metrics(mock_element,
                                         mock.sentinel.metrics_def)

        self.assertEqual(mock_filter_metrics.return_value, result)
        mock_filter_metrics.assert_called_once_with([mock_metric],
                                                    mock.sentinel.metrics_def)

    def test_filter_metrics(self):
        mock_metric = mock.MagicMock(MetricDefinitionId=mock.sentinel.def_id)
        mock_bad_metric = mock.MagicMock()
        mock_metric_def = mock.MagicMock(Id=mock.sentinel.def_id)

        result = self.utils._filter_metrics([mock_bad_metric, mock_metric],
                                            mock_metric_def)

        self.assertEqual([mock_metric], result)

    @mock.patch.object(metricsutils.MetricsUtils, '_get_vm_setting_data')
    def test_get_vm_resources(self, mock_get_vm_setting_data):
        result = self.utils._get_vm_resources(mock.sentinel.vm_name,
                                              mock.sentinel.resource_class)

        associators = mock_get_vm_setting_data.return_value.associators
        mock_get_vm_setting_data.assert_called_once_with(mock.sentinel.vm_name)
        associators.assert_called_once_with(
            wmi_result_class=mock.sentinel.resource_class)
        self.assertEqual(associators.return_value, result)

    @mock.patch.object(metricsutils.MetricsUtils, '_unique_result')
    def test_get_vm(self, mock_unique_result):
        result = self.utils._get_vm(mock.sentinel.vm_name)

        self.assertEqual(mock_unique_result.return_value, result)
        conn_class = self.utils._conn.Msvm_ComputerSystem
        conn_class.assert_called_once_with(ElementName=mock.sentinel.vm_name)
        mock_unique_result.assert_called_once_with(conn_class.return_value,
                                                   mock.sentinel.vm_name)

    @mock.patch.object(metricsutils.MetricsUtils, '_unique_result')
    def test_get_switch_port(self, mock_unique_result):
        result = self.utils._get_switch_port(mock.sentinel.port_name)

        self.assertEqual(mock_unique_result.return_value, result)
        conn_class = self.utils._conn.Msvm_SyntheticEthernetPortSettingData
        conn_class.assert_called_once_with(ElementName=mock.sentinel.port_name)
        mock_unique_result.assert_called_once_with(conn_class.return_value,
                                                   mock.sentinel.port_name)

    @mock.patch.object(metricsutils.MetricsUtils, '_unique_result')
    def test_get_vm_setting_data(self, mock_unique_result):
        result = self.utils._get_vm_setting_data(mock.sentinel.vm_name)

        self.assertEqual(mock_unique_result.return_value, result)
        conn_class = self.utils._conn.Msvm_VirtualSystemSettingData
        conn_class.assert_called_once_with(
            ElementName=mock.sentinel.vm_name,
            VirtualSystemType=self.utils._VIRTUAL_SYSTEM_TYPE_REALIZED)
        mock_unique_result.assert_called_once_with(conn_class.return_value,
                                                   mock.sentinel.vm_name)

    def test_unique_result_not_found(self):
        self.assertRaises(exceptions.NotFound,
                          self.utils._unique_result,
                          [], mock.sentinel.resource_name)

    def test_unique_result_duplicate(self):
        self.assertRaises(exceptions.OSWinException,
                          self.utils._unique_result,
                          [mock.ANY, mock.ANY], mock.sentinel.resource_name)

    def test_unique_result(self):
        result = self.utils._unique_result([mock.sentinel.obj],
                                           mock.sentinel.resource_name)
        self.assertEqual(mock.sentinel.obj, result)
