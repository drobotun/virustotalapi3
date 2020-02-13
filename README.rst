.. image:: https://i.imgur.com/6nji8Ec.png
    :target: https://www.virustotal.com

VirusTotal API 3 version
========================

.. image:: https://img.shields.io/github/license/drobotun/virustotalapi3?style=flat
    :target: http://doge.mit-license.org
.. image:: https://travis-ci.org/drobotun/virustotalapi3.svg?branch=master
    :target: https://travis-ci.org/drobotun/virustotalapi3
.. image:: https://ci.appveyor.com/api/projects/status/tto83lriiwdkq55q?svg=true
    :target: https://ci.appveyor.com/project/drobotun/virustotalapi3
.. image:: https://codecov.io/gh/drobotun/virustotalapi3/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/drobotun/virustotalapi3
.. image:: https://coveralls.io/repos/github/drobotun/virustotalapi3/badge.svg
    :target: https://coveralls.io/github/drobotun/virustotalapi3
.. image:: https://img.shields.io/scrutinizer/quality/g/drobotun/virustotalapi3	
	:target: https://scrutinizer-ci.com/g/drobotun/virustotalapi3/
.. image:: https://badge.fury.io/py/vtapi3.svg
    :target: https://pypi.org/project/vtapi3/	
.. image:: https://img.shields.io/pypi/pyversions/vtapi3.svg?logo=python&logoColor=FBE072
    :target: https://pypi.org/project/vtapi3/
.. image:: https://img.shields.io/pypi/status/vtapi3
    :target: https://pypi.org/project/vtapi3/
.. image:: https://img.shields.io/pypi/format/vtapi3
    :target: https://pypi.org/project/vtapi3/
.. image:: https://readthedocs.org/projects/virustotalapi3/badge/?version=latest
    :target: https://virustotalapi3.readthedocs.io/
.. image:: https://img.shields.io/pypi/dm/vtapi3
    :target: https://pypi.org/project/vtapi3/
.. image:: https://i.imgur.com/JtZ54GZ.png
    :target: https://xakep.ru/2020/01/09/virustotal-api/#xakepcut

The module that implements the service API functions www.virustotal.com (3 versions).
For a detailed description of the API, see: https://developers.virustotal.com/v3.0/reference.

The following VirusTotal API functions are implemented:

**For files:**

- |POST| /files
- |GET| /files/upload_url
- |GET| /files/{id}
- |POST| /files/{id}/analyse
- |GET| /files/{id}/comments
- |POST| /files/{id}/comments
- |GET| /files/{id}/votes
- |POST| /files/{id}/votes
- |GET| /files/{id}/{relationship}
- |GET| /file_behaviours/{sandbox_id}/pcap
- |GET| /files/{id}/download_url (Added in version 1.2.0, requires a private key to access API functions)
- |GET| /files/{id}/download (Added in version 1.2.0, requires a private key to access API functions)

**For URLs:**

- |POST| /urls
- |GET| /urls/{id}
- |POST| /urls/{id}/analyse
- |GET| /urls/{id}/comments
- |POST| /urls/{id}/comments
- |GET| /urls/{id}/votes
- |POST| /urls/{id}/votes
- |GET| /urls/{id}/network_location

**For domains:**

- |GET| /domains/{domain}
- |GET| /domains/{domain}/comments
- |POST| /domains/{domain}/comments
- |GET| /domains/{domain}/{relationship}
- |GET| /domains/{domain}/votes
- |POST| /domains/{domain}/votes

**For IP-addresses:**

- |GET| /domains/{domain}
- |GET| /domains/{domain}/comments
- |POST| /domains/{domain}/comments
- |GET| /domains/{domain}/{relationship}
- |GET| /domains/{domain}/votes
- |POST| /domains/{domain}/votes

**File and URL analysis:**

- |GET| /analyses/{id}

Installation
""""""""""""

.. code-block:: bash

    pip install vtapi3

Usage
"""""

In python programs
''''''''''''''''''

.. rubric:: Code

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

.. rubric:: Output

.. code-block:: json

    {
      "data": {
        "type": "analysis",
        "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
      }
    }

From command line (added in version 1.1.0)
''''''''''''''''''''''''''''''''''''''''''

Before using the package from the command line, you must create an environment variable ``VT_API_KEY`` in which to place the value of the access key to the VirusTotal API functions.

::

    python -m vtapi3  [-h] [-fid] [-fsr] [-far] [-hr] [-uid] [-usr] [-uar] [-ipr]
                      [-dr]
                      resource

.. rubric:: Positional arguments

- ``resource`` - Object that you want to analyse in VirusTotal (file, URL, IP address or domain).

.. rubric:: Optional arguments

- ``-h``, ``--help`` - Show help message and exit.
- ``-fid``, ``--file-id`` - Getting the identifier of the file for further analysis.
- ``-fsr``, ``--file-scan-report`` - Getting a report on the results of scanning a file.
- ``-far``, ``--file-analyse-report`` - Getting a report on the results of file analysis (enabled by default).
- ``-hr``, ``--hash-report`` - Getting a report on the results of analyzing a file by its hash (SHA256, SHA1 or MD5).
- ``-uid``, ``--url-id`` - Getting the identifier of the URL for further analysis.
- ``-usr``, ``--url-scan-report`` - Getting a report on the results of scanning a URL.
- ``-uar``, ``--url-analyse-report`` - Getting a report on the results of URL analysis.
- ``-ipr``, ``--ip-report`` - Getting a report on the results of IP address analysis.
- ``-dr``, ``--domain-report`` - Getting a report on the results of domain analysis.

License
"""""""

MIT Copyright (c) 2020 Evgeny Drobotun

Documentation
"""""""""""""

Documentation for using this package: https://virustotalapi3.readthedocs.io


.. |POST| image:: https://i.imgur.com/CWgYjh1.png
.. |GET| image:: https://i.imgur.com/CBcN0Fh.png
