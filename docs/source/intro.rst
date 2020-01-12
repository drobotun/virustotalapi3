Introduction
============

Overview
--------

``vtapi3`` is a Python module that implements the service API functions www.virustotal.com (3 versions) are available using the public key. For a detailed description of the API, see: https://developers.virustotal.com/v3.0/reference.

The ``vtapi3`` module implements the following VirusTotal API functions:

**For files:**

- **POST** /files
- **GET** /files/upload_url
- **GET** /files/{id}
- **POST** /files/{id}/analyse
- **GET** /files/{id}/comments
- **POST** /files/{id}/comments
- **GET** /files/{id}/votes
- **POST** /files/{id}/votes
- **GET** /files/{id}/{relationship}
- **GET** /file_behaviours/{sandbox_id}/pcap

**For URLs:**

- **POST** /urls
- **GET** /urls/{id}
- **POST** /urls/{id}/analyse
- **GET** /urls/{id}/comments
- **POST** /urls/{id}/comments
- **GET** /urls/{id}/votes
- **POST** /urls/{id}/votes
- **GET** /urls/{id}/network_location

**For domains:**

- **GET** /domains/{domain}
- **GET** /domains/{domain}/comments
- **POST** /domains/{domain}/comments
- **GET** /domains/{domain}/{relationship}
- **GET** /domains/{domain}/votes
- **POST** /domains/{domain}/votes

**For IP-addresses:**

- **GET** /domains/{domain}
- **GET** /domains/{domain}/comments
- **POST** /domains/{domain}/comments
- **GET** /domains/{domain}/{relationship}
- **GET** /domains/{domain}/votes
- **POST** /domains/{domain}/votes

**File and URL analysis:**

- **GET** /analyses/{id}

Installation
""""""""""""

.. code-block:: bash

    $ pip install vtapi3

Usage
"""""

.. code-block:: python

   import json
   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_files.upload('<file path>')
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

Output
""""""

.. code-block:: json

    {
      "data": {
        "type": "analysis",
        "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
      }
    }

License
"""""""

MIT Copyright (c) 2020 Evgeny Drobotun

Release History
---------------

1.0.2 (12.01.2020)
""""""""""""""""""

- Fixed errors in source comments.
- Fixing README.rst for better PYPI presentation.
- Fixing setup.py for better PYPI presentation.
- README.rst translated into English.
- Added two tests (``test_get_version_avi()`` and ``test_get_lost_http_error ()``) in test_vt_3.py

1.0.1 (08.01.2020)
""""""""""""""""""

- First release of vtapi3
