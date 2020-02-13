"""
   VirusTotalAPIAnalyses class testing module.

   Author: Evgeny Drobotun (c) 2020
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

"""
import unittest
import errno
from unittest import mock

import requests
from vtapi3 import VirusTotalAPIAnalyses, VirusTotalAPIError

def get_mock_response(status_code, content):
    """Mock function for implementing test responses from the server."""
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

class TestAnalyses(unittest.TestCase):
    """The class that implements the VirusTotalAPIAnalyses class testing functions."""

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_report_file_id(self):
        """Checking the get_report function when the server responds with the HTTP code 200."""
        vt_analyses = VirusTotalAPIAnalyses('test_api_key')
        vt_analyses.get_report('test_object_id')
        http_err = vt_analyses.get_last_http_error()
        self.assertEqual(http_err, vt_analyses.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_object_id(self):
        """Checking the get_report function when the server responds with the HTTP code 404."""
        vt_analyses = VirusTotalAPIAnalyses('test_api_key')
        vt_analyses.get_report('test_object_id')
        http_err = vt_analyses.get_last_http_error()
        self.assertEqual(http_err, vt_analyses.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_report_timeout_error(self):
        """Checking the get_report function when a Timeout exception occurs."""
        err_code = 0
        vt_analyses = VirusTotalAPIAnalyses('test_api_key')
        try:
            vt_analyses.get_report('test_object_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_report_connection_error(self):
        """Checking the get_report function when a ConnectionError exception occurs."""
        err_code = 0
        vt_analyses = VirusTotalAPIAnalyses('test_api_key')
        try:
            vt_analyses.get_report('test_object_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_api_key(self):
        """Checking the get_report function when the server responds with the HTTP code 401."""
        vt_analyses_wrong_api_key = VirusTotalAPIAnalyses('test_api_key')
        vt_analyses_wrong_api_key.get_report('test_object_id')
        http_err = vt_analyses_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_analyses_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
