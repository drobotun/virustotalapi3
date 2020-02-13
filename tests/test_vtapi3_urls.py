"""
   VirusTotalAPIUrls class testing module.

   Author: Evgeny Drobotun (c) 2020
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

"""
import unittest
import errno
from unittest import mock

import requests
from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError

def post_mock_response_upload(status_code, content):
    """Mock function for implementing test responses from the server for upload() function."""
    test_mock = mock.Mock()
    test_mock.status_code = status_code
    test_mock.content = content

    def mock_response(api_url, headers, data, timeout, proxies):
        return test_mock

    return mock_response

def raise_connection_error_upload(api_url, headers, data, timeout, proxies):
    """Mock function for implementing the ConnectionError exception for upload() function."""
    raise requests.exceptions.ConnectionError

def raise_timeout_error_upload(api_url, headers, data, timeout, proxies):
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

class TestUrls(unittest.TestCase):

    def test_get_url_id_base64(self):
        TEST_URL = 'https://xakep.ru/author/drobotun/'
        TEST_URL_ID_BASE64 = 'aHR0cHM6Ly94YWtlcC5ydS9hdXRob3IvZHJvYm90dW4v'
        url_id = VirusTotalAPIUrls.get_url_id_base64(TEST_URL)
        self.assertEqual(url_id, TEST_URL_ID_BASE64)

    def test_get_url_id_sha256(self):
        TEST_URL = 'https://xakep.ru/author/drobotun/'
        TEST_URL_ID_SHA256 = '1a565d28f8412c3e4b65ec8267ff8e77eb00a2c76367e653be774169ca9d09a6'
        url_id = VirusTotalAPIUrls.get_url_id_sha256(TEST_URL)
        self.assertEqual(url_id, TEST_URL_ID_SHA256)

    @mock.patch('requests.post', post_mock_response_upload(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_upload(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.upload('test_url')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.post', post_mock_response_upload(requests.codes['bad_request'],
                'Test VirusTotal contetnt'))
    def test_upload_wrong_url(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.upload('test_url')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_BAD_REQUEST_ERROR)

    @mock.patch('requests.post', raise_timeout_error_upload)
    def test_upload_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.upload('test_url')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_upload)
    def test_upload_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.upload('test_url')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_upload(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_upload_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        vt_urls_wrong_api_key.upload('test_url')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_report_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_report('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_report('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_report_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_report('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_report_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_report('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)


    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_report_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('test_api_key')
        vt_urls_wrong_api_key.get_report('test_url_id')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_analyse_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.analyse('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.post', post_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_analyse_wrong_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.analyse('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.post', raise_timeout_error)
    def test_analyse_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.analyse('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error)
    def test_analyse_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.analyse('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_analyse_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        vt_urls_wrong_api_key.analyse('test_url_id')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_comments(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_comments('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_comments_wrong_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_comments('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_comments)
    def test_get_comments_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_comments('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_comments)
    def test_get_comments_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_comments('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_comments(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_comments_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('test_api_key')
        vt_urls_wrong_api_key.get_comments('test_url_id')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response_comments(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_comments(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.put_comments('test_url_id', 'test_comment')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.post', raise_timeout_error_put_comments)
    def test_put_comments_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.put_comments('test_url_id', 'test_comment')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_put_comments)
    def test_put_comments_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.put_comments('test_url_id', 'test_comment')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_comments(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_put_comments_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('test_api_key')
        vt_urls_wrong_api_key.put_comments('test_url_id', 'test_comment')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_votes(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_votes('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_votes_wrong_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_votes('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_votes)
    def test_get_votes_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_votes('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_votes)
    def test_get_votes_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_votes('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_votes(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_votes_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        vt_urls_wrong_api_key.get_votes('test_url_id')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_votes_harmless(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.put_votes('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_put_votes_malicious(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.put_votes('test_url_id', True)
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.post', raise_timeout_error_put_votes)
    def test_put_votes_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.put_votes('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.post', raise_connection_error_put_votes)
    def test_put_votes_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.put_votes('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.post', post_mock_response_votes(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_put_votes_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('test_api_key')
        vt_urls_wrong_api_key.put_votes('test_url_id')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_network_location(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_network_location('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.get', get_mock_response(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_network_location_wrong_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_network_location('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error)
    def test_get_network_location_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_network_location('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error)
    def test_get_network_location_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_network_location('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_network_location_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('test_api_key')
        vt_urls_wrong_api_key.get_network_location('test_url_id')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['ok'],
                'Test VirusTotal contetnt'))
    def test_get_relationship(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_relationship('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['not_found'],
                'Test VirusTotal contetnt'))
    def test_get_relationship_wrong_id(self):
        vt_urls = VirusTotalAPIUrls('test_api_key')
        vt_urls.get_relationship('test_url_id')
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    @mock.patch('requests.get', raise_timeout_error_get_relationship)
    def test_get_relationship_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_relationship('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @mock.patch('requests.get', raise_connection_error_get_relationship)
    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls('test_api_key')
        try:
            vt_urls.get_relationship('test_url_id')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    @mock.patch('requests.get', get_mock_response_relationship(requests.codes['unauthorized'],
                'Test VirusTotal contetnt'))
    def test_get_relationship_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('test_api_key')
        vt_urls_wrong_api_key.get_relationship('test_url_id')
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
