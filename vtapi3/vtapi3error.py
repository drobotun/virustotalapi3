"""The module describes the VirusTotalAPIError class

   Author: Evgeny Drobotun (c) 2019
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

   More information: https://virustotalapi3.readthedocs.io/en/latest/error_class.html
"""

class VirusTotalAPIError(Exception):
    """A class that implements exceptions that may occur when module class methods are used.
    """

    def __init__(self, message, err_code):
        """Inits VirusTotalAPIError.
        """
        super().__init__(message)
        self.err_code = err_code
