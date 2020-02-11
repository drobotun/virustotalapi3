import unittest
import json
import errno

from vtapi3 import VirusTotalAPI, VirusTotalAPIAnalyses, VirusTotalAPIError

API_KEY = '<Insert VirusTotal API key>'
TEST_FILE_ID = 'ZTRiNjgxZmJmZmRkZTNlM2YyODlkMzk5MTZhZjYwNDI6MTU3NjYwMTE1Ng=='
TEST_URL_ID = 'u-dce9e8fbe86b145e18f9dcd4aba6bba9959fdff55447a8f9914eb9c4fc1931f9-1576610003'
TEST_TIMEOUT = 0.01
PRINT_RESULT = False
TEST_BASE_URL = 'https://www.fgykhjfhgyf.try'

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

    def test_get_report_connection_error(self):
        err_code = 0
        vt_analyses = VirusTotalAPIAnalyses(API_KEY)
        vt_analyses.base_url = TEST_BASE_URL
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
