import unittest
import json
import errno

from vtapi3.vtapi3 import (VirusTotalAPIFiles, VirusTotalAPIUrls, VirusTotalAPIDomains,
                    VirusTotalAPIIPAddresses, VirusTotalAPIAnalyses, VirusTotalAPIError)

API_KEY = '<Insert VirusTotal API key>'

TEST_FILE = 'test_file.txt'

TEST_FILE_ID_EICAR = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

TEST_FILE_ID_SHA256 = '9b54bb6ed1c5574aeb5343b0c5e9686ab4b68c65bc2b5d408b7ed16499878ad8'
TEST_FILE_ID_SHA1 = '668a6444cd1e22c70919dd8ff8d871be86944d68'
TEST_FILE_ID_MD5 = 'e4b681fbffdde3e3f289d39916af6042'

TEST_URL = 'https://xakep.ru/author/drobotun/'
TEST_URL_ID_BASE64 = 'aHR0cHM6Ly94YWtlcC5ydS9hdXRob3IvZHJvYm90dW4v'
TEST_URL_ID_SHA256 = '1a565d28f8412c3e4b65ec8267ff8e77eb00a2c76367e653be774169ca9d09a6'

TEST_DOMAIN ='www.virustotal.com'

TEST_IP = '216.239.38.21'

TEST_SANDBOX_ID = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f_OS X Sandbox'

TEST_FILE_ID = 'ZTRiNjgxZmJmZmRkZTNlM2YyODlkMzk5MTZhZjYwNDI6MTU3NjYwMTE1Ng=='
TEST_URL_ID = 'u-dce9e8fbe86b145e18f9dcd4aba6bba9959fdff55447a8f9914eb9c4fc1931f9-1576610003'

TEST_TIMEOUT = 0.01

TEST_PROXI = {'http': '10.10.1.10:3128',
              'https': '10.10.1.10:1080',
              'ftp': '10.10.1.10:3128'}

PRINT_RESULT = False


class TestFile(unittest.TestCase):

    def test_get_file_id_sha256(self):
        file_id = VirusTotalAPIFiles.get_file_id(TEST_FILE)
        if PRINT_RESULT:
            print('\nFile identifier: ', file_id)
        self.assertEqual(file_id, TEST_FILE_ID_SHA256)

    def test_get_file_id_sha1(self):
        file_id = VirusTotalAPIFiles.get_file_id(TEST_FILE, 'sha1')
        if PRINT_RESULT:
            print('\nFile identifier: ', file_id)
        self.assertEqual(file_id, TEST_FILE_ID_SHA1)

    def test_get_file_id_md5(self):
        file_id = VirusTotalAPIFiles.get_file_id(TEST_FILE, 'md5')
        if PRINT_RESULT:
            print('\nFile identifier: ', file_id)
        self.assertEqual(file_id, TEST_FILE_ID_MD5)

    def test_get_file_id_error_file(self):
        err_code = 0
        try:
            file_id_sha256 = VirusTotalAPIFiles.get_file_id('')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ENOENT)

    @unittest.skip('The test requires a valid api key')
    def test_upload(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.upload(TEST_FILE)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    def test_upload_file_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY)
        try:
            result = vt_files.upload('')
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ENOENT)

    def test_upload_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.upload(TEST_FILE)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_upload_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.upload(TEST_FILE)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_upload_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.upload(TEST_FILE)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_upload_url(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_upload_url()
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    def test_get_upload_url_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.get_upload_url()
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_get_upload_url_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.get_upload_url()
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_upload_url_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_upload_url()
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_id(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_report(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_wrong_id(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_report('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    def test_get_report_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.get_report(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_get_report_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.get_report(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_report_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_report(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_analyse(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.analyse(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_analyse_wrong_id(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.analyse('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    def test_analyse_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.analyse(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_analyse_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.analyse(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_analyse_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.analyse(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_comments(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_comments_wrong_id(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_comments('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    def test_get_comments_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.get_comments(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_get_comments_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.get_comments(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_comments_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_comments(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_votes(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_votes_wrong_id(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_votes('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    def test_get_votes_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.get_votes(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_get_votes_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.get_votes(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_votes_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_votes(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_relationship(TEST_FILE_ID_EICAR)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_relationship_wrong_id(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_relationship('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    def test_get_relationship_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.get_relationship(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.get_relationship(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_relationship_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_relationship(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_behaviours(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_behaviours(TEST_SANDBOX_ID)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_FORBIDDEN_ERROR)

    @unittest.skip('The test requires a valid api key')
    def test_get_behaviours_wrong_id(self):
        vt_files = VirusTotalAPIFiles(API_KEY)
        result = vt_files.get_behaviours('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_files.get_last_http_error()
        self.assertEqual(http_err, vt_files.HTTP_NOT_FOUND_ERROR)

    def test_get_behaviours_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.get_behaviours(TEST_SANDBOX_ID)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_get_behaviours_connection_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, None, TEST_PROXI)
        try:
            result = vt_files.get_behaviours(TEST_SANDBOX_ID)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_behaviours_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_behaviours(TEST_SANDBOX_ID)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)


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

    @unittest.skip('The test takes a long time')
    def test_upload_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, None, TEST_PROXI)
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

    @unittest.skip('The test takes a long time')
    def test_get_report_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, None, TEST_PROXI)
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

    @unittest.skip('The test takes a long time')
    def test_analyse_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, None, TEST_PROXI)
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

    @unittest.skip('The test takes a long time')
    def test_get_comments_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, None, TEST_PROXI)
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

    @unittest.skip('The test takes a long time')
    def test_get_votes_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, None, TEST_PROXI)
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

    @unittest.skip('The test takes a long time')
    def test_get_network_location_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, None, TEST_PROXI)
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

    @unittest.skip('The test takes a long time')
    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_urls = VirusTotalAPIUrls(API_KEY, None, TEST_PROXI)
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

    @unittest.skip('The test takes a long time')
    def test_get_report_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, None, TEST_PROXI)
        try:
            result = vt_domains.get_report(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

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

    @unittest.skip('The test takes a long time')
    def test_get_comments_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, None, TEST_PROXI)
        try:
            result = vt_domains.get_comments(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_comments_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.get_comments(TEST_DOMAIN)
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

    @unittest.skip('The test takes a long time')
    def test_get_votes_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, None, TEST_PROXI)
        try:
            result = vt_domains.get_votes(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_votes_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.get_votes(TEST_DOMAIN)
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

    @unittest.skip('The test takes a long time')
    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_domains = VirusTotalAPIDomains(API_KEY, None, TEST_PROXI)
        try:
            result = vt_domains.get_relationship(TEST_DOMAIN)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_relationship_wrong_api_key(self):
        vt_domains_wrong_api_key = VirusTotalAPIDomains('')
        result = vt_domains_wrong_api_key.get_relationship(TEST_DOMAIN)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_domains_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_domains_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)


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

    @unittest.skip('The test takes a long time')
    def test_get_report_connection_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, None, TEST_PROXI)
        try:
            result = vt_ip.get_report(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

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

    @unittest.skip('The test takes a long time')
    def test_get_comments_connection_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, None, TEST_PROXI)
        try:
            result = vt_ip.get_comments(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_comments_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.get_comments(TEST_IP)
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

    @unittest.skip('The test takes a long time')
    def test_get_votes_connection_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, None, TEST_PROXI)
        try:
            result = vt_ip.get_votes(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_votes_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.get_votes(TEST_IP)
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

    @unittest.skip('The test takes a long time')
    def test_get_relationship_connection_error(self):
        err_code = 0
        vt_ip = VirusTotalAPIIPAddresses(API_KEY, None, TEST_PROXI)
        try:
            result = vt_ip.get_relationship(TEST_IP)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_relationship_wrong_api_key(self):
        vt_ip_wrong_api_key = VirusTotalAPIIPAddresses('')
        result = vt_ip_wrong_api_key.get_relationship(TEST_IP)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_ip_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_ip_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)


class TestAnalyses(unittest.TestCase):

    @unittest.skip('The test requires a valid api key')
    def test_get_report_file_id(self):
        vt_analyses = VirusTotalAPIAnalyses(API_KEY)
        result = vt_analyses.get_report(TEST_FILE_ID)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_analyses.get_last_http_error()
        self.assertEqual(http_err, vt_analyses.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_url_id(self):
        vt_analyses = VirusTotalAPIAnalyses(API_KEY)
        result = vt_analyses.get_report(TEST_URL_ID)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_analyses.get_last_http_error()
        self.assertEqual(http_err, vt_analyses.HTTP_OK)

    @unittest.skip('The test requires a valid api key')
    def test_get_report_wrong_object_id(self):
        vt_analyses = VirusTotalAPIAnalyses(API_KEY)
        result = vt_analyses.get_report('')
        if PRINT_RESULT:
            print('\nResult: ', result)
        http_err = vt_analyses.get_last_http_error()
        self.assertEqual(http_err, vt_analyses.HTTP_NOT_FOUND_ERROR)

    def test_get_report_timeout_error(self):
        err_code = 0
        vt_analyses = VirusTotalAPIAnalyses(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_analyses.get_report(TEST_FILE_ID)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    @unittest.skip('The test takes a long time')
    def test_get_report_connection_error(self):
        err_code = 0
        vt_analyses = VirusTotalAPIAnalyses(API_KEY, None, TEST_PROXI)
        try:
            result = vt_analyses.get_report(TEST_FILE_ID)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ECONNABORTED)

    def test_get_report_wrong_api_key(self):
        vt_analyses_wrong_api_key = VirusTotalAPIAnalyses('')
        result = vt_analyses_wrong_api_key.get_report(TEST_FILE_ID)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_analyses_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_analyses_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
  
