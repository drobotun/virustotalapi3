"""
   VirusTotalAPIDomains class testing module.

   Author: Evgeny Drobotun (c) 2020
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

"""
import unittest
import errno
from unittest import mock

import requests
from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError

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

class TestDomain(unittest.TestCase):

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_report_id(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_report('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_id(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_report('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_report_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_report('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_report_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_report('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('test_api_key')
        vt_domains_wrong_api_key.get_report('test_domain')
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_comments(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_comments('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_comments_wrong_id(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_comments('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_comments)
    def test_get_comments_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_comments('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_comments)
    def test_get_comments_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_comments('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_comments_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('test_api_key')
        vt_domains_wrong_api_key.get_comments('test_domain')
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response_comments(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_comments(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.put_comments('test_domain', 'test_comments')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @mock.patch('requests.post', raise_timeout_error_put_comments)
    def test_put_comments_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.put_comments('test_domain', 'test_comments')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_put_comments)
    def test_put_comments_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.put_comments('test_domain', 'test_comments')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_comments(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_put_comments_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('test_api_key')
        vt_domains_wrong_api_key.put_comments('test_domain', 'test_comments')
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_votes(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_votes('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_votes_wrong_id(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_votes('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_votes)
    def test_get_votes_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_votes('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_votes)
    def test_get_votes_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_votes('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_votes_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('test_api_key')
        vt_domains_wrong_api_key.get_votes('test_domain')
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_votes_harmless(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.put_votes('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_votes_malicious(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.put_votes('test_domain', True)
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @mock.patch('requests.post', raise_timeout_error_put_votes)
    def test_put_votes_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.put_votes('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_put_votes)
    def test_put_votes_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.put_votes('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_put_votes_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('test_api_key')
        vt_domains_wrong_api_key.put_votes('test_domain')
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_relationship(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_relationship('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_relationship_wrong_id(self):
        vt_domains = VirusTotalAPIDomains('test_api_key')
        vt_domains.get_relationship('test_domain')
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_relationship)
    def test_get_relationship_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_relationship('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_relationship)
    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains('test_api_key')
        try:
            vt_domains.get_relationship('test_domain')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_relationship_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('test_api_key')
        vt_domains_wrong_api_key.get_relationship('test_domain')
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
