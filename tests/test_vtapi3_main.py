"""
   vtapi3.__main__.py testing module.

   Author: Evgeny Drobotun (c) 2020
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

"""
import os
import errno
import unittest
from unittest import mock

import requests
import vtapi3
from vtapi3.__main__ import (get_environment_api_key, get_file_id_to_analyse, get_file_scan_report,
                    get_file_analyse_report, get_hash_report, get_url_id_to_analyse,
                    get_url_scan_report, get_url_analyse_report, get_ip_report,
                    get_domain_report, create_cmd_parser, main)

def raise_file_not_found(file_path, type_access):
    """Mock function for implementing the FileNotFoundError exception."""
    raise FileNotFoundError

def raise_permission_error(file_path, type_access):
    """Mock function for implementing the PermissionError exception."""
    raise PermissionError

def raise_os_error(file_path, type_access):
    """Mock function for implementing the OSError exception."""
    raise OSError

def post_mock_response_file(status_code):
    """Mock function for implementing test responses from the server for POST request."""
    TEST_JSON = b'{\n    "data": {\n        "id": "test_JSON",\n        "type": "analysis"\n    }\n}'
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = TEST_JSON

    def mock_response(api_url, headers, files, timeout, proxies):
        return test_mock

    return mock_response

def post_mock_response_url(status_code):
    """Mock function for implementing test responses from the server for POST request."""
    TEST_JSON = b'{\n    "data": {\n        "id": "test_JSON",\n        "type": "analysis"\n    }\n}'
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = TEST_JSON

    def mock_response(api_url, headers, data, timeout, proxies):
        return test_mock

    return mock_response

def get_mock_response(status_code):
    """Mock function for implementing test responses from the server for GET request."""
    TEST_JSON = b'{\n    "data": {\n        "id": "test_JSON",\n        "type": "analysis"\n    }\n}'
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = TEST_JSON

    def mock_response(api_url, headers, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error_file(api_url, headers, files, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for files."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_file(api_url, headers, files, timeout, proxies):
    """Mock function for implementing the Timeout exception for files."""
    raise requests.exceptions.Timeout

def raise_connection_error_url(api_url, headers, data, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for URLs."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_url(api_url, headers, data, timeout, proxies):
    """Mock function for implementing the Timeout exception for URLs."""
    raise requests.exceptions.Timeout

def raise_connection_error(api_url, headers, timeout, proxies):
    """Mock function for implementing the ConnectionError exception."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error(api_url, headers, timeout, proxies):
    """Mock function for implementing the Timeout exception."""
    raise requests.exceptions.Timeout

class TestMain(unittest.TestCase):

    def test_get_environment_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        test_api_key = get_environment_api_key()
        self.assertEqual(test_api_key, 'test_api_key')

    def test_get_environment_wrong_api_key(self):
        if 'VT_API_KEY' in os.environ:
            os.environ.pop('VT_API_KEY')
        try:
            get_environment_api_key()
        except vtapi3.VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.EINVAL)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['ok']))
    def test_get_file_id_to_analyse(self):
        result = get_file_id_to_analyse('', 'test_api_key')
        self.assertRegex(result, 'File ID:')

    @mock.patch('builtins.open', raise_file_not_found)
    def test_get_file_id_to_analyse_error_file(self):
        result = get_file_id_to_analyse('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.ENOENT)

    @mock.patch('builtins.open', raise_permission_error)
    def test_get_file_id_to_analyse_permisison_error(self):
        result = get_file_id_to_analyse('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.EPERM)

    @mock.patch('builtins.open', raise_os_error)
    def test_get_file_id_to_analyse_os_error(self):
        result = get_file_id_to_analyse('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.EIO)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['unauthorized']))
    def test_get_file_id_to_analyse_wrong_api_key(self):
        result = get_file_id_to_analyse('', 'test_api_key')
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', raise_timeout_error_file)
    def test_get_file_id_to_analyse_timeout_error(self):
        result = get_file_id_to_analyse('', 'test_api_key')
        self.assertEqual(result.err_code, errno.ETIMEDOUT)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', raise_connection_error_file)
    def test_get_file_id_to_analyse_connection_error(self):
        result = get_file_id_to_analyse('', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_file_scan_report(self):
        result = get_file_scan_report('', 'test_api_key')
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['not_found']))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_file_scan_report_upload_error(self):
        result = get_file_scan_report('', 'test_api_key')
        self.assertRegex(result, 'HTTP error 404')

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['not_found']))
    def test_get_file_scan_report_analyse_error(self):
        result = get_file_scan_report('', 'test_api_key')
        self.assertRegex(result, 'HTTP error 404')

    @mock.patch('builtins.open', raise_file_not_found)
    def test_get_file_scan_report_file_error(self):
        result = get_file_scan_report('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.ENOENT)

    @mock.patch('builtins.open', raise_permission_error)
    def test_get_file_scan_report_permission_error(self):
        result = get_file_scan_report('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.EPERM)

    @mock.patch('builtins.open', raise_os_error)
    def test_get_file_scan_report_os_error(self):
        result = get_file_scan_report('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.EIO)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', raise_connection_error_file)
    def test_get_file_scan_report_connection_error(self):
        result = get_file_scan_report('', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_file_analyse_report(self):
        result = get_file_analyse_report('', 'test_api_key')
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('builtins.open', raise_file_not_found)
    def test_get_file_analyse_report_file_error(self):
        result = get_file_analyse_report('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.ENOENT)

    @mock.patch('builtins.open', raise_permission_error)
    def test_get_file_analyse_report_permission_error(self):
        result = get_file_analyse_report('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.EPERM)

    @mock.patch('builtins.open', raise_os_error)
    def test_get_file_analyse_report_os_error(self):
        result = get_file_analyse_report('test_file', 'test_api_key')
        self.assertEqual(result.err_code, errno.EIO)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_get_file_analyse_report_wrong_api_key(self):
        result = get_file_analyse_report('test_file', 'test_api_key')
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_hash_report(self):
        result = get_hash_report('test_sha256', 'test_api_key')
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_get_hash_report_wrong_api_key(self):
        result = get_hash_report('test_sha256', 'test_api_key')
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', raise_connection_error)
    def test_get_hash_report_connection_error(self):
        result = get_hash_report('test_sha256', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_hash_report_timeout_error(self):
        result = get_hash_report('test_sha256', 'test_api_key')
        self.assertEqual(result.err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', post_mock_response_url(requests.codes['ok']))
    def test_get_url_id_to_analyse(self):
        result = get_url_id_to_analyse('test_url', 'test_api_key')
        self.assertRegex(result, 'URL ID:')

    @mock.patch('requests.post', post_mock_response_url(requests.codes['unauthorized']))
    def test_get_url_id_to_analyse_wrong_api_key(self):
        result = get_url_id_to_analyse('test_url', 'test_api_key')
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.post', raise_timeout_error_url)
    def test_get_url_id_to_analyse_timeout_error(self):
        result = get_url_id_to_analyse('test_url', 'test_api_key')
        self.assertEqual(result.err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_url)
    def test_get_url_id_to_analyse_connection_error(self):
        result = get_url_id_to_analyse('test_url', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_url(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_url_scan_report(self):
        result = get_url_scan_report('test_url', 'test_api_key')
        self.assertRegex(result, 'Analysis report:')
    
    @mock.patch('requests.post', post_mock_response_url(requests.codes['not_found']))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_url_scan_report_upload_error(self):
        result = get_url_scan_report('test_url', 'test_api_key')
        self.assertEqual(result, 'HTTP error 404')

    @mock.patch('requests.post', post_mock_response_url(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['not_found']))
    def test_get_url_scan_report_analyse_error(self):
        result = get_url_scan_report('test_url', 'test_api_key')
        self.assertEqual(result, 'HTTP error 404')

    @mock.patch('requests.post', raise_timeout_error_url)
    def test_get_url_scan_report_timeout_error(self):
        result = get_url_scan_report('test_url', 'test_api_key')
        self.assertEqual(result.err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_url)
    def test_get_url_scan_report_connection_error(self):
        result = get_url_scan_report('test_url', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_url_analyse_report(self):
        result = get_url_analyse_report('test_url', 'test_api_key')
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_get_url_analyse_report_wrong_api_key(self):
        result = get_url_analyse_report('test_url', 'test_api_key')
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_url_analyse_timeout_error(self):
        result = get_url_analyse_report('test_url', 'test_api_key')
        self.assertEqual(result.err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_url_analyse_connection_error(self):
        result = get_url_analyse_report('test_url', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_ip_report(self):
        result = get_ip_report('test_ip', 'test_api_key')
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_get_ip_report_wrong_api_key(self):
        result = get_ip_report('test_ip', 'test_api_key')
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_ip_report_timeout_error(self):
        result = get_ip_report('test_ip', 'test_api_key')
        self.assertEqual(result.err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_ip_report_connectiont_error(self):
        result = get_ip_report('test_ip', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_get_domain_report(self):
        result = get_domain_report('test_domain', 'test_api_key')
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_get_domain_report_wrong_api_key(self):
        result = get_domain_report('test_domain', 'test_api_key')
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_domain_report_timeout_error(self):
        result = get_domain_report('test_domain', 'test_api_key')
        self.assertEqual(result.err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_domain_report_connection_error(self):
        result = get_domain_report('test_domain', 'test_api_key')
        self.assertEqual(result.err_code, errno.ECONNABORTED)

    def test_main_no_environment_api_key(self):
        if 'VT_API_KEY' in os.environ:
            os.environ.pop('VT_API_KEY')
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', 'test_file'])
        result = main(options)
        self.assertEqual(result.err_code, errno.EINVAL)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['ok']))
    def test_main_fid(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', ''])
        result = main(options)
        self.assertRegex(result, 'File ID:')

    @mock.patch('builtins.open', raise_file_not_found)
    def test_main_fid_error_file(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', ''])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['unauthorized']))
    def test_main_fid_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', ''])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_fsr(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-fsr', ''])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('builtins.open', raise_file_not_found)
    def test_main_fsr_error_file(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-fsr', ''])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_file(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_fsr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-fsr', ''])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_far(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-far', ''])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('builtins.open', raise_file_not_found)
    def test_main_far_error_file(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-far', 'trst_file'])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_far_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-far', 'test_file'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_hr(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-hr', 'test_file_sha256'])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_hr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-hr', 'test_file_sha256'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.post', post_mock_response_url(requests.codes['ok']))
    def test_main_uid(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-uid', 'test_url'])
        result = main(options)
        self.assertRegex(result, 'URL ID:')

    @mock.patch('requests.post', post_mock_response_url(requests.codes['unauthorized']))
    def test_main_uid_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-uid', 'test_url'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.post', post_mock_response_url(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_usr(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-usr', 'test_url'])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.post', post_mock_response_url(requests.codes['unauthorized']))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_usr_wrong_api_key_post(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-usr', 'test_url'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.post', post_mock_response_url(requests.codes['ok']))
    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_usr_wrong_api_key_get(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-usr', 'test_url'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_uar(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-uar', 'test_url'])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_uar_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-uar', 'test_url'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_ipr(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-ipr', 'test_ip'])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_ipr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-ipr', 'test_ip'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_dr(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-dr', 'test_domain'])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_dr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['-dr', 'test_domain'])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.get', get_mock_response(requests.codes['ok']))
    def test_main_default(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args([''])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    @mock.patch('builtins.open', raise_file_not_found)
    def test_main_default_error_file(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args(['test_file'])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized']))
    def test_main_default_wrong_api_key(self):
        os.environ['VT_API_KEY'] = 'test_api_key'
        parser = create_cmd_parser()
        options = parser.parse_args([''])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

if __name__ == '__main__':
    unittest.main()
