import unittest
import json
import errno

from vtapi3 import VirusTotalAPI, VirusTotalAPIIPAddresses, VirusTotalAPIError

from tests.test_vtapi3_const import (API_KEY, TEST_COMMENTS, TEST_IP,
                                     TEST_TIMEOUT, PRINT_RESULT)

class TestIPAddresses(unittest.TestCase):

    @unittest.skip('The test requires a valid api key')
    def test_get_report(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_report(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_OK)

    
    @unittest.skip('The test requires a valid api key')
    def test_get_report_wrong_id(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_report('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_NOT_FOUND_ERROR)

    def test_get_report_timeout_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_ip.get_report(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_report_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.get_report(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_ip_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_comments(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments_wrong_id(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_comments('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_NOT_FOUND_ERROR)

    def test_get_comments_timeout_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_ip.get_comments(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_comments_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.get_comments(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_ip_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_comments_timeout_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_ip.put_comments(TEST_IP, TEST_COMMENTS)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_comments_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.put_comments(TEST_IP, TEST_COMMENTS)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_ip_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_votes(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes_wrong_id(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_votes('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_NOT_FOUND_ERROR)

    def test_get_votes_timeout_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_ip.get_votes(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_votes_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.get_votes(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_ip_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_votes_timeout_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_ip.put_votes(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_votes_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.put_votes(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_ip_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_relationship(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship_wrong_id(self):
        vt_ip = VirusTotalAPIIPAddresses(API_KEY)
        result = vt_ip.get_relationship('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_ip.get_last_http_error()
        self.assertEqual(http_err, vt_ip.HTTP_NOT_FOUND_ERROR)

    def test_get_relationship_timeout_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_ip.get_relationship(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_relationship_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.get_relationship(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_ip_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
