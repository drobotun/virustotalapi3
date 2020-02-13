"""
   VirusTotalAPIFiles class testing module.

   Author: Evgeny Drobotun (c) 2020
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

"""
import unittest
import errno
from unittest import mock

import requests
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError

def raise_file_not_found(file_path, type_access):
    """Mock function for implementing the FileNotFoundError exception."""
    raise FileNotFoundError

def raise_permission_error(file_path, type_access):
    """Mock function for implementing the PermissionError exception."""
    raise PermissionError

def raise_os_error(file_path, type_access):
    """Mock function for implementing the OSError exception."""
    raise OSError

def post_mock_response_upload(status_code, content):
    """Mock function for implementing test responses from the server for upload() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, files, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error_upload(api_url, headers, files, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for upload() function."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_upload(api_url, headers, files, timeout, proxies):
    """Mock function for implementing the Timeout exception for upload() function."""
    raise requests.exceptions.Timeout

def get_mock_response(status_code, content):
    """Mock function for implementing test responses from the server."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, timeout, proxies):
        return test_mock

    return mock_response

def post_mock_response(status_code, content):
    """Mock function for implementing test responses from the server for analyse() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error(api_url, headers, timeout, proxies):
    """Mock function for implementing the ConnectionError exception."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error(api_url, headers, timeout, proxies):
    """Mock function for implementing the Timeout exception."""
    raise requests.exceptions.Timeout

def get_mock_response_comments(status_code, content):
    """Mock function for implementing test responses from the server for get_comments() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, params, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error_get_comments(api_url, headers, params, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for get_comments() function."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_get_comments(api_url, headers, params, timeout, proxies):
    """Mock function for implementing the Timeout exception for for get_comments() function."""
    raise requests.exceptions.Timeout

def post_mock_response_comments(status_code, content):
    """Mock function for implementing test responses from the server for put_comments() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, json, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error_put_comments(api_url, headers, json, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for put_comments() function."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_put_comments(api_url, headers, json, timeout, proxies):
    """Mock function for implementing the Timeout exception for for put_comments() function."""
    raise requests.exceptions.Timeout

def get_mock_response_votes(status_code, content):
    """Mock function for implementing test responses from the server for get_votes() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, params, timeout, proxies):
        return test_mock

    return mock_response

def post_mock_response_votes(status_code, content):
    """Mock function for implementing test responses from the server for put_votes() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, json, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error_get_votes(api_url, headers, params, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for get_votes() function."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_get_votes(api_url, headers, params, timeout, proxies):
    """Mock function for implementing the Timeout exception for for get_votes() function."""
    raise requests.exceptions.Timeout

def raise_connection_error_put_votes(api_url, headers, json, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for put_votes() function."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_put_votes(api_url, headers, json, timeout, proxies):
    """Mock function for implementing the Timeout exception for for put_votes() function."""
    raise requests.exceptions.Timeout

def get_mock_response_relationship(status_code, content):
    """Mock function for implementing test responses from the server for get_relationship() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, params, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error_get_relationship(api_url, headers, params, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for get_relationship() function."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_get_relationship(api_url, headers, params, timeout, proxies):
    """Mock function for implementing the Timeout exception for for get_relationship() function."""
    raise requests.exceptions.Timeout

class TestFile(unittest.TestCase):
    """The class that implements the VirusTotalAPIFiles class testing functions."""

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    def test_get_file_id_sha256(self):
        TEST_SHA256 = '9b54bb6ed1c5574aeb5343b0c5e9686ab4b68c65bc2b5d408b7ed16499878ad8'
        file_id = VirusTotalAPIFiles.get_file_id('')
        self.assertEqual(file_id, TEST_SHA256)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    def test_get_file_id_sha1(self):
        TEST_SHA1 = '668a6444cd1e22c70919dd8ff8d871be86944d68'
        file_id = VirusTotalAPIFiles.get_file_id('', 'sha1')
        self.assertEqual(file_id, TEST_SHA1)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    def test_get_file_id_md5(self):
        TEST_MD5 = 'e4b681fbffdde3e3f289d39916af6042'
        file_id = VirusTotalAPIFiles.get_file_id('', 'md5')
        self.assertEqual(file_id, TEST_MD5)

    @mock.patch('builtins.open', raise_file_not_found)
    def test_get_file_id_file_error(self):
        err_code = 0
        try:
            VirusTotalAPIFiles.get_file_id('test_file')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ENOENT)

    @mock.patch('builtins.open', raise_permission_error)
    def test_get_file_id_permission_error(self):
        err_code = 0
        try:
            VirusTotalAPIFiles.get_file_id('test_file')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.EPERM)

    @mock.patch('builtins.open', raise_os_error)
    def test_get_file_id_io_error(self):
        err_code = 0
        try:
            VirusTotalAPIFiles.get_file_id('test_file')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.EIO)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_upload(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_upload(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.upload('')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('builtins.open', raise_file_not_found)
    def test_upload_file_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.upload('test_file')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ENOENT)

    @mock.patch('builtins.open', raise_permission_error)
    def test_upload_permission_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.upload('test_file')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.EPERM)

    @mock.patch('builtins.open', raise_os_error)
    def test_upload_io_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.upload('test_file')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.EIO)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', raise_timeout_error_upload)
    def test_upload_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.upload('')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', raise_connection_error_upload)
    def test_upload_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.upload('')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'This is a test file for VirusTotal API validation'))
    @mock.patch('requests.post', post_mock_response_upload(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_upload_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.upload('')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_upload_url(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_upload_url()
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_upload_url_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_upload_url()
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_upload_url_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_upload_url()
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_upload_url_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_upload_url()
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_report_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_report('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_report('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_report_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_report('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_report_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_report('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_report('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_analyse(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.analyse('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.post', post_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_analyse_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.analyse('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.post', raise_timeout_error)
    def test_analyse_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.analyse('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error)
    def test_analyse_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.analyse('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_analyse_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.analyse('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_comments(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_comments('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_comments_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_comments('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_comments)
    def test_get_comments_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_comments('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_comments)
    def test_get_comments_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_comments('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_comments_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_comments('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response_comments(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_comments(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.put_comments('test_id', 'test_comments')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.post', raise_timeout_error_put_comments)
    def test_put_comments_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.put_comments('test_id', 'test_comments')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_put_comments)
    def test_put_comments_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.put_comments('test_id', 'test_comments')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_comments(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_put_comments_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.put_comments('test_id', 'test_comments')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_votes(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_votes('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_votes_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_votes('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_votes)
    def test_get_votes_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_votes('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_votes)
    def test_get_votes_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_votes('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_votes_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_votes('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_votes_harmless(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.put_votes('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_votes_malicious(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.put_votes('test_id', True)
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.post', raise_timeout_error_put_votes)
    def test_put_votes_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.put_votes('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_put_votes)
    def test_put_votes_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.put_votes('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_put_votes_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.put_votes('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_relationship(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_relationship('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_relationship_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_relationship('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_relationship)
    def test_get_relationship_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_relationship('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_relationship)
    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_relationship('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_relationship_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_relationship('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_behaviours(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_behaviours('test_sandbox_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_behaviours_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_behaviours('test_sandbox_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_behaviours_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_behaviours('test_sandbox_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_behaviours_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_behaviours('test_sandbox_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_behaviours_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_behaviours('test_sandbox_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_download_url(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_download_url('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_download_url_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_download_url('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_download_url_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_download_url('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_download_url_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_download_url('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_download_url_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_download_url('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_download(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_download('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_download_wrong_id(self):
        vt_files = VirusTotalAPIFiles('test_api_key')
        vt_files.get_download('test_id')
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_download_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_download('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_download_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles('test_api_key')
        try:
            vt_files.get_download('test_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_download_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('test_api_key')
        vt_files_wrong_api_key.get_download('test_id')
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
