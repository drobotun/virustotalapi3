"""The module describes classes that implement methods for accessing service API functions
   www.virustotai.com.

   More information: https://virustotalapi3.readthedocs.io/en/latest

   Author: Evgeny Drobotun (c) 2019
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

   Requirements:
      $ pip install requests

   Example usage:

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_files = VirusTotalAPIFiles(<Insert API key string here>)
   try:
       result = vt_files.upload(<Insert faile name here>)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_files.get_last_http_error() == vt_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_files.get_last_http_error()) +']')
      ...
"""
__title__ = 'vtapi3'
__version__ = '1.2.0'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .vtapi3base import VirusTotalAPI
from .vtapi3files import VirusTotalAPIFiles
from .vtapi3urls import VirusTotalAPIUrls
from .vtapi3domains import VirusTotalAPIDomains
from .vtapi3ipaddresses import VirusTotalAPIIPAddresses
from .vtapi3analyses import VirusTotalAPIAnalyses
from .vtapi3error import VirusTotalAPIError
