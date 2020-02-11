import unittest
import errno

from vtapi3 import VirusTotalAPI
from tests.test_vtapi3_const import API_KEY

class TestBase(unittest.TestCase):

    def test_get_version_api(self):
        vt_api = VirusTotalAPI(API_KEY)
        self.assertEqual(vt_api.get_version_api(), 'version 3')

    def test_get_last_http_error(self):
        vt_api = VirusTotalAPI(API_KEY)
        vt_api._last_http_error = vt_api.HTTP_OK
        self.assertEqual(vt_api.get_last_http_error(), vt_api.HTTP_OK)

    def test_get_last_result(self):
        vt_api = VirusTotalAPI(API_KEY)
        vt_api._last_result = 'test_get_last_result'
        self.assertEqual(vt_api.get_last_result(), 'test_get_last_result')

if __name__ == '__main__':
    unittest.main()