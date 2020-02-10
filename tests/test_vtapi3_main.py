import os
import sys
import errno
import argparse
import unittest

import vtapi3

from vtapi3.__main__ import (get_environment_api_key, get_file_id_to_analyse, get_file_scan_report,
                    get_file_analyse_report, get_hash_report, get_url_id_to_analyse,
                    get_url_scan_report, get_url_analyse_report, get_ip_report,
                    get_domain_report, create_cmd_parser, main)

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

    def test_main_no_environment_api_key(self):
        if 'VT_API_KEY' in os.environ:
            os.environ.pop('VT_API_KEY')
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', TEST_FILE])
        result = main(options)
        self.assertEqual(result.err_code, errno.EINVAL)

    @unittest.skip('The test requires a valid api key')
    def test_main_fid(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', TEST_FILE])
        result = main(options)
        self.assertRegex(result, 'File ID:')

    def test_main_fid_error_file(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', ''])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    def test_main_fid_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-fid', TEST_FILE])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_fsr(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-fsr', TEST_FILE])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_fsr_error_file(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-fsr', ''])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    def test_main_fsr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-fsr', TEST_FILE])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_far(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-far', TEST_FILE])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_far_error_file(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-far', ''])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    def test_main_far_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-far', TEST_FILE])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_hr(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-hr', TEST_FILE_ID_SHA256])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_hr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-hr', TEST_FILE_ID_SHA256])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_uid(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-uid', TEST_URL])
        result = main(options)
        self.assertRegex(result, 'URL ID:')

    def test_main_uid_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-uid', TEST_URL])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_usr(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-usr', TEST_URL])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_usr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-usr', TEST_URL])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_uar(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-uar', TEST_URL])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_uar_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-uar', TEST_URL])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_ipr(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-ipr', TEST_IP])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_ipr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-ipr', TEST_IP])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_dr(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args(['-dr', TEST_DOMAIN])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_dr_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args(['-dr', TEST_DOMAIN])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

    @unittest.skip('The test requires a valid api key')
    def test_main_default(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args([TEST_FILE])
        result = main(options)
        self.assertRegex(result, 'Analysis report:')

    def test_main_default_error_file(self):
        os.environ['VT_API_KEY'] = API_KEY
        parser = create_cmd_parser()
        options = parser.parse_args([''])
        result = main(options)
        self.assertEqual(result.err_code, errno.ENOENT)

    def test_main_default_wrong_api_key(self):
        os.environ['VT_API_KEY'] = ''
        parser = create_cmd_parser()
        options = parser.parse_args([TEST_FILE])
        result = main(options)
        self.assertEqual(result, 'HTTP error 401')

if __name__ == '__main__':
    unittest.main()
  