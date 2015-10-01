#  Copyright 2015 Cloudbase Solutions Srl
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
from os_win.utils import constants
from os_win.utils import jobutils


class JobUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V JobUtils class."""

    _FAKE_RET_VAL = 0

    _FAKE_JOB_STATUS_BAD = -1
    _FAKE_JOB_DESCRIPTION = "fake_job_description"
    _FAKE_JOB_PATH = 'fake_job_path'
    _FAKE_ERROR = "fake_error"
    _FAKE_ELAPSED_TIME = 0
    _CONCRETE_JOB = "Msvm_ConcreteJob"

    def setUp(self):
        super(JobUtilsTestCase, self).setUp()
        self.jobutils = jobutils.JobUtils()
        self.jobutils._conn = mock.MagicMock()

    @mock.patch.object(jobutils.JobUtils, '_wait_for_job')
    def test_check_ret_val_started(self, mock_wait_for_job):
        self.jobutils.check_ret_val(constants.WMI_JOB_STATUS_STARTED,
                                    mock.sentinel.job_path)
        mock_wait_for_job.assert_called_once_with(mock.sentinel.job_path)

    @mock.patch.object(jobutils.JobUtils, '_wait_for_job')
    def test_check_ret_val_ok(self, mock_wait_for_job):
        self.jobutils.check_ret_val(self._FAKE_RET_VAL,
                                    mock.sentinel.job_path)
        self.assertFalse(mock_wait_for_job.called)

    def test_check_ret_val_exception(self):
        self.assertRaises(exceptions.HyperVException,
                          self.jobutils.check_ret_val,
                          mock.sentinel.ret_val_bad,
                          mock.sentinel.job_path)

    def test_wait_for_job_exception_concrete_job(self):
        mock_job = self._prepare_wait_for_job()
        mock_job.path.return_value.Class = self._CONCRETE_JOB
        self.assertRaises(exceptions.HyperVException,
                          self.jobutils._wait_for_job,
                          self._FAKE_JOB_PATH)

    def test_wait_for_job_exception_with_error(self):
        mock_job = self._prepare_wait_for_job()
        mock_job.GetError.return_value = (self._FAKE_ERROR, self._FAKE_RET_VAL)
        self.assertRaises(exceptions.HyperVException,
                          self.jobutils._wait_for_job,
                          self._FAKE_JOB_PATH)
        mock_job.GetError.assert_called_once_with()

    def test_wait_for_job_exception_no_error_details(self):
        mock_job = self._prepare_wait_for_job()
        mock_job.GetError.return_value = (None, None)
        self.assertRaises(exceptions.HyperVException,
                          self.jobutils._wait_for_job,
                          self._FAKE_JOB_PATH)

    def test_wait_for_job_killed(self):
        mockjob = self._prepare_wait_for_job(constants.JOB_STATE_KILLED)
        job = self.jobutils._wait_for_job(self._FAKE_JOB_PATH)
        self.assertEqual(mockjob, job)

    def test_wait_for_job_ok(self):
        mock_job = self._prepare_wait_for_job(
            constants.WMI_JOB_STATE_COMPLETED)
        job = self.jobutils._wait_for_job(self._FAKE_JOB_PATH)
        self.assertEqual(mock_job, job)

    def test_stop_jobs(self):
        mock_job1 = mock.MagicMock(Cancellable=True)
        mock_job2 = mock.MagicMock(Cancellable=True)
        mock_job3 = mock.MagicMock(Cancellable=True)
        mock_job1.JobState = 2
        mock_job2.JobState = 3
        mock_job3.JobState = constants.JOB_STATE_KILLED

        mock_vm = mock.MagicMock()
        mock_vm_jobs = [mock_job1, mock_job2, mock_job3]
        mock_vm.associators.return_value = mock_vm_jobs

        self.jobutils.stop_jobs(mock_vm)

        mock_job1.RequestStateChange.assert_called_once_with(
            self.jobutils._KILL_JOB_STATE_CHANGE_REQUEST)
        mock_job2.RequestStateChange.assert_called_once_with(
            self.jobutils._KILL_JOB_STATE_CHANGE_REQUEST)
        self.assertFalse(mock_job3.RequestStateChange.called)

    def test_is_job_completed_true(self):
        job = mock.MagicMock(JobState=constants.JOB_STATE_COMPLETED)

        self.assertTrue(self.jobutils._is_job_completed(job))

    def test_is_job_completed_false(self):
        job = mock.MagicMock(JobState=constants.WMI_JOB_STATE_RUNNING)

        self.assertFalse(self.jobutils._is_job_completed(job))

    def _prepare_wait_for_job(self, state=_FAKE_JOB_STATUS_BAD):
        mock_job = mock.MagicMock()
        mock_job.JobState = state
        mock_job.Description = self._FAKE_JOB_DESCRIPTION
        mock_job.ElapsedTime = self._FAKE_ELAPSED_TIME

        wmi_patcher = mock.patch.object(jobutils, 'wmi', create=True)
        mock_wmi = wmi_patcher.start()
        self.addCleanup(wmi_patcher.stop)
        mock_wmi.WMI.return_value = mock_job
        return mock_job

    def test_modify_virt_resource(self):
        side_effect = [
            (self._FAKE_JOB_PATH, mock.MagicMock(), self._FAKE_RET_VAL)]
        self._check_modify_virt_resource_max_retries(side_effect=side_effect)

    def test_modify_virt_resource_max_retries_exception(self):
        side_effect = exceptions.HyperVException('expected failure.')
        self._check_modify_virt_resource_max_retries(
            side_effect=side_effect, num_calls=6, expected_fail=True)

    def test_modify_virt_resource_max_retries(self):
        side_effect = [exceptions.HyperVException('expected failure.')] * 5 + [
            (self._FAKE_JOB_PATH, mock.MagicMock(), self._FAKE_RET_VAL)]
        self._check_modify_virt_resource_max_retries(side_effect=side_effect,
                                                     num_calls=5)

    @mock.patch('eventlet.greenthread.sleep')
    def _check_modify_virt_resource_max_retries(
            self, mock_sleep, side_effect, num_calls=1, expected_fail=False):
        mock_svc = self.jobutils._conn.Msvm_VirtualSystemManagementService()[0]
        mock_svc.ModifyResourceSettings.side_effect = side_effect
        mock_res_setting_data = mock.MagicMock()
        mock_res_setting_data.GetText_.return_value = mock.sentinel.res_data

        if expected_fail:
            self.assertRaises(exceptions.HyperVException,
                              self.jobutils.modify_virt_resource,
                              mock_res_setting_data, mock.sentinel.fake_path)
        else:
            self.jobutils.modify_virt_resource(mock_res_setting_data,
                                               mock.sentinel.fake_path)

        mock_calls = [
            mock.call(ResourceSettings=[mock.sentinel.res_data])] * num_calls
        mock_svc.ModifyResourceSettings.has_calls(mock_calls)
        mock_sleep.has_calls(mock.call(1) * num_calls)

    def test_add_virt_resource(self):
        self._test_virt_method('AddResourceSettings', 3, 'add_virt_resource',
                               True, mock.sentinel.vm_path,
                               [mock.sentinel.res_data])

    def test_remove_virt_resource(self):
        self._test_virt_method('RemoveResourceSettings', 2,
                               'remove_virt_resource', True,
                               ResourceSettings=[mock.sentinel.res_path])

    def test_add_virt_feature(self):
        self._test_virt_method('AddFeatureSettings', 3, 'add_virt_feature',
                               True, mock.sentinel.vm_path,
                               [mock.sentinel.res_data])

    def test_remove_virt_feature(self):
        self._test_virt_method('RemoveFeatureSettings', 2,
                               'remove_virt_feature', False,
                               FeatureSettings=[mock.sentinel.res_path])

    def _test_virt_method(self, vsms_method_name, return_count,
                          utils_method_name, with_mock_vm, *args, **kwargs):
        mock_svc = self.jobutils._conn.Msvm_VirtualSystemManagementService()[0]
        vsms_method = getattr(mock_svc, vsms_method_name)
        mock_rsd = self._mock_vsms_method(vsms_method, return_count)
        if with_mock_vm:
            mock_vm = mock.MagicMock()
            mock_vm.path_.return_value = mock.sentinel.vm_path
            getattr(self.jobutils, utils_method_name)(mock_rsd, mock_vm)
        else:
            getattr(self.jobutils, utils_method_name)(mock_rsd)

        if args:
            vsms_method.assert_called_once_with(*args)
        else:
            vsms_method.assert_called_once_with(**kwargs)

    def _mock_vsms_method(self, vsms_method, return_count):
        args = None
        if return_count == 3:
            args = (
                mock.sentinel.job_path, mock.MagicMock(), self._FAKE_RET_VAL)
        else:
            args = (mock.sentinel.job_path, self._FAKE_RET_VAL)

        vsms_method.return_value = args
        mock_res_setting_data = mock.MagicMock()
        mock_res_setting_data.GetText_.return_value = mock.sentinel.res_data
        mock_res_setting_data.path_.return_value = mock.sentinel.res_path

        self.jobutils.check_ret_val = mock.MagicMock()

        return mock_res_setting_data
