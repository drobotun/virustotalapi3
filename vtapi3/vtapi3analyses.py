"""The module describes the VirusTotalAPIAnalyses class

   Author: Evgeny Drobotun (c) 2019
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

   More information: https://virustotalapi3.readthedocs.io/en/latest/analyses_class.html
"""

import errno
import requests

from .vtapi3base import VirusTotalAPI
from .vtapi3error import VirusTotalAPIError

class VirusTotalAPIAnalyses(VirusTotalAPI):
    """The retrieving information about analysis of the file or URL method are defined in the class.

       Methods:
          get_report(): Retrieve information about a file or URL analysis.
    """

    def get_report(self, object_id):
        """Retrieve information about a file or URL analysis.

        Args:
           object_id: Analysis identifier (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/analyses/' + object_id
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
