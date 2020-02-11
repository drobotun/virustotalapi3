import unittest
import json
import errno

from vtapi3 import VirusTotalAPI, VirusTotalAPIUrls, VirusTotalAPIError

API_KEY = '<Insert VirusTotal API key>'
TEST_COMMENTS = 'test_comments'
TEST_URL = 'https://xakep.ru/author/drobotun/'
TEST_URL_ID_BASE64 = 'aHR0cHM6Ly94YWtlcC5ydS9hdXRob3IvZHJvYm90dW4v'
TEST_URL_ID_SHA256 = '1a565d28f8412c3e4b65ec8267ff8e77eb00a2c76367e653be774169ca9d09a6'
TEST_URL_ID = 'u-dce9e8fbe86b145e18f9dcd4aba6bba9959fdff55447a8f9914eb9c4fc1931f9-1576610003'
TEST_TIMEOUT = 0.01
PRINT_RESULT = False
TEST_BASE_URL = 'https://www.fgykhjfhgyf.try'

class TestUrls(unittest.TestCase):

    def test_get_url_id_base64(self):
        url_id = VirusTotalAPIUrls.get_url_id_base64(TEST_URL)
        if PRINT_RESULT:
            print('\nURL identifier: ', url_id)
        self.assertEqual(url_id, TEST_URL_ID_BASE64)

    def test_get_url_id_sha256(self):
        url_id = VirusTotalAPIUrls.get_url_id_sha256(TEST_URL)
        if PRINT_RESULT:
            print('\nURL identifier: ', url_id)
        self.assertEqual(url_id, TEST_URL_ID_SHA256)

    @unittest.skip('The test requires a valid api key')
    def test_upload(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.upload(TEST_URL)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_upload_wrong_url(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.upload('')
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_BAD_REQUEST_ERROR)

    def test_upload_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.upload(TEST_URL)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_upload_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.upload(TEST_URL)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_upload_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.upload(TEST_URL)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_id_base64(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_report(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_id_sha256(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_report(TEST_URL_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_wrong_id(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_report('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    def test_get_report_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.get_report(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_report_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.get_report(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)


    def test_get_report_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.get_report(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_analyse_id_base64(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.analyse(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_analyse_id_sha256(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.analyse(TEST_URL_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_analyse_wrong_id(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.analyse('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    def test_analyse_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.analyse(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_analyse_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.analyse(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_analyse_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.analyse(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_comments(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments_wrong_id(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_comments('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    def test_get_comments_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.get_comments(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_comments_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.get_comments(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_comments_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.get_comments(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_comments_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.put_comments(TEST_URL_ID_BASE64, TEST_COMMENTS)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_comments_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.put_comments(TEST_URL_ID_BASE64, TEST_COMMENTS)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_put_comments_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.put_comments(TEST_URL_ID_BASE64, TEST_COMMENTS)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_votes(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes_wrong_id(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_votes('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    def test_get_votes_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.get_votes(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_votes_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.get_votes(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_votes_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.get_votes(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_votes_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.put_votes(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_votes_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.put_votes(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_put_votes_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.put_votes(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_network_location(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_network_location(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_network_location_wrong_id(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_network_location('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    def test_get_network_location_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.get_network_location(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_network_location_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.get_network_location(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_network_location_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.get_network_location(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_relationship(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship_wrong_id(self):
        vt_urls = VirusTotalAPIUrls(API_KEY)
        result = vt_urls.get_relationship('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_urls.get_last_http_error()
        self.assertEqual(http_err, vt_urls.HTTP_NOT_FOUND_ERROR)

    def test_get_relationship_timeout_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_urls.get_relationship(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY)
        vt_urls.base_url = TEST_BASE_URL
        try:
            result = vt_urls.get_relationship(TEST_URL_ID_BASE64)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_relationship_wrong_api_key(self):
        vt_urls_wrong_api_key = VirusTotalAPIUrls('')
        result = vt_urls_wrong_api_key.get_relationship(TEST_URL_ID_BASE64)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_urls_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_urls_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
