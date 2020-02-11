import unittest
import json
import errno

from vtapi3 import VirusTotalAPI, VirusTotalAPIDomains, VirusTotalAPIError

from tests.test_vtapi3_const import (API_KEY, TEST_COMMENTS, TEST_DOMAIN,
                                     TEST_TIMEOUT, PRINT_RESULT)

class TestDomain(unittest.TestCase):

    @unittest.skip('The test requires a valid api key')
    def test_get_report(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_report(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_wrong_id(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_report('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    def test_get_report_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_domains.get_report(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_report_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.get_report(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_comments(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments_wrong_id(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_comments('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    def test_get_comments_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_domains.get_comments(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_comments_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.get_comments(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_comments_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_domains.put_comments(TEST_DOMAIN, TEST_COMMENTS)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_comments_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.put_comments(TEST_DOMAIN, TEST_COMMENTS)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_votes(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes_wrong_id(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_votes('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    def test_get_votes_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_domains.get_votes(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_votes_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.get_votes(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_votes_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_domains.put_votes(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_votes_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.put_votes(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_relationship(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship_wrong_id(self):
        vt_domains = VirusTotalAPIDomains(API_KEY)
        result = vt_domains.get_relationship('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_domains.get_last_http_error()
        self.assertEqual(http_err, vt_domains.HTTP_NOT_FOUND_ERROR)

    def test_get_relationship_timeout_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_domains.get_relationship(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_relationship_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.get_relationship(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
