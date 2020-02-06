import os
import errno
import unittest

import vtapi3

from vtapi3.__main__ import (get_environment_api_key, get_file_id_to_analyse, get_file_scan_report,
                    get_file_analyse_report, get_hash_report, get_url_id_to_analyse,
                    get_url_scan_report, get_url_analyse_report, get_ip_report,
                    get_domain_report)

API_KEY = '<Insert VirusTotal API key>'

TEST_FILE = 'test_file.txt'
TEST_FILE_ID_SHA256 = '9b54bb6ed1c5574aeb5343b0c5e9686ab4b68c65bc2b5d408b7ed16499878ad8'
TEST_URL = 'https://xakep.ru/author/drobotun/'
TEST_DOMAIN ='www.virustotal.com'
TEST_IP = '216.239.38.21'
TEST_FILE = 'test_file.txt'


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

    @unittest.skip('The test requires a valid api key')
    def test_get_file_id_to_analyse(self):
        result = get_file_id_to_analyse(TEST_FILE, API_KEY)
        self.assertRegex(result, 'File ID:')

    def test_get_file_id_to_analyse_error_file(self):
        result = get_file_id_to_analyse('', API_KEY)
        self.assertEqual(result.err_code, errno.ENOENT)

    def test_get_file_id_to_analyse_wrong_api_key(self):
        result = get_file_id_to_analyse(TEST_FILE, '')
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_get_file_scan_report(self):
        result = get_file_scan_report(TEST_FILE, API_KEY)
        self.assertRegex(result, 'Analysis report:')
    
    def test_get_file_scan_report_error_file(self):
        result = get_file_scan_report('', API_KEY)
        self.assertEqual(result.err_code, errno.ENOENT)

    def test_get_file_scan_report_wrong_api_key(self):
        result = get_file_scan_report(TEST_FILE, '')
        self.assertEqual(result, 'HTTP error 401')   

    @unittest.skip('The test requires a valid api key')
    def test_get_file_analyse_report(self):
        result = get_file_analyse_report(TEST_FILE, API_KEY)
        self.assertRegex(result, 'Analysis report:')

    def test_get_file_analyse_report_error_file(self):
        result = get_file_analyse_report('', API_KEY)
        self.assertEqual(result.err_code, errno.ENOENT)

    def test_get_file_analyse_report_wrong_api_key(self):
        result = get_file_analyse_report(TEST_FILE, '')
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_get_hash_report(self):
        result = get_hash_report(TEST_FILE_ID_SHA256, API_KEY)
        self.assertRegex(result, 'Analysis report:') 

    def test_get_hash_report_wrong_api_key(self):
        result = get_hash_report(TEST_FILE_ID_SHA256, '')
        self.assertEqual(result, 'HTTP error 401')        

    @unittest.skip('The test requires a valid api key')
    def test_get_url_id_to_analyse(self):
        result = get_url_id_to_analyse(TEST_URL, API_KEY)
        self.assertRegex(result, 'URL ID:')

    def test_get_url_id_to_analyse_wrong_api_key(self):
        result = get_url_id_to_analyse(TEST_URL, '')
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_get_url_scan_report(self):
        result = get_url_scan_report(TEST_URL, API_KEY)
        self.assertRegex(result, 'Analysis report:')

    def test_get_url_scan_report_wrong_api_key(self):
        result = get_url_scan_report(TEST_URL, '')
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_get_url_analyse_report(self):
        result = get_url_analyse_report(TEST_URL, API_KEY)
        self.assertRegex(result, 'Analysis report:')

    def test_get_url_analyse_report_wrong_api_key(self):
        result = get_url_analyse_report(TEST_URL, '')
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_get_ip_report(self):
        result = get_ip_report(TEST_IP, API_KEY)
        self.assertRegex(result, 'Analysis report:')

    def test_get_ip_report_wrong_api_key(self):
        result = get_ip_report(TEST_IP, '')
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_get_domain_report(self):
        result = get_domain_report(TEST_DOMAIN, API_KEY)
        self.assertRegex(result, 'Analysis report:')

    def test_get_domain_report_wrong_api_key(self):
        result = get_domain_report(TEST_DOMAIN, '')
        self.assertEqual(result, 'HTTP error 401')

if __name__ == '__main__':
    unittest.main()
  