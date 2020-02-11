import unittest
import json
import errno

from vtapi3 import VirusTotalAPI, VirusTotalAPIFiles, VirusTotalAPIError

from tests.test_vtapi3_const import (API_KEY, TEST_FILE, TEST_COMMENTS, TEST_FILE_ID_SHA256,
                                     TEST_FILE_ID_SHA1, TEST_FILE_ID_MD5, TEST_FILE_ID,
                                     TEST_SANDBOX_ID, TEST_TIMEOUT, PRINT_RESULT)

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

    def test_get_comments_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_comments(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_comments_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.put_comments(TEST_FILE_ID_SHA256, TEST_COMMENTS)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_comments_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.put_comments(TEST_FILE_ID_SHA256, TEST_COMMENTS)
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

    def test_get_votes_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_votes(TEST_FILE_ID_SHA256)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

    def test_put_votes_timeout_error(self):
        err_code = 0
        vt_files = VirusTotalAPIFiles(API_KEY, TEST_TIMEOUT)
        try:
            result = vt_files.put_votes(TEST_FILE_ID_SHA256)
        except VirusTotalAPIError as err:
            err_code = err.err_code
        self.assertEqual(err_code, errno.ETIMEDOUT)

    def test_put_votes_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.put_votes(TEST_FILE_ID_SHA256)
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

    def test_get_behaviours_wrong_api_key(self):
        vt_files_wrong_api_key = VirusTotalAPIFiles('')
        result = vt_files_wrong_api_key.get_behaviours(TEST_SANDBOX_ID)
        if PRINT_RESULT:
            result = json.loads(result)
            print('\nResult: ', json.dumps(result, sort_keys=False, indent=4))
        http_err = vt_files_wrong_api_key.get_last_http_error()
        self.assertEqual(http_err, vt_files_wrong_api_key.HTTP_AUTHENTICATION_REQUIRED_ERROR)

if __name__ == '__main__':
    unittest.main()
