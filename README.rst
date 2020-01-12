.. image:: https://i.imgur.com/6nji8Ec.png
    :target: https://www.virustotal.com

VirusTotal API 3 version
========================

.. image:: https://img.shields.io/github/license/drobotun/virustotalapi3?style=flat
    :target: http://doge.mit-license.org
.. image:: https://travis-ci.org/drobotun/virustotalapi3.svg?branch=master
    :target: https://travis-ci.org/drobotun/virustotalapi3
.. image:: https://img.shields.io/pypi/v/vtapi3
    :target: https://pypi.org/project/vtapi3/
.. image:: https://img.shields.io/pypi/pyversions/vtapi3
    :target: https://pypi.org/project/vtapi3/
.. image:: https://img.shields.io/pypi/dm/vtapi3
    :target: https://pypi.org/project/vtapi3/

The module that implements the service API functions www.virustotal.com (3 versions) available using the public key.
For a detailed description of the API, see: https://developers.virustotal.com/v3.0/reference

The following VirusTotal API functions are implemented:

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
