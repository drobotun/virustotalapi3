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
.. image:: https://readthedocs.org/projects/virustotalapi3/badge/?version=latest
    :target: https://virustotalapi3.readthedocs.io/
.. image:: https://img.shields.io/pypi/dm/vtapi3
    :target: https://pypi.org/project/vtapi3/
.. image:: https://i.imgur.com/JtZ54GZ.png
    :target: https://xakep.ru/2020/01/09/virustotal-api/#xakepcut

The module that implements the service API functions www.virustotal.com (3 versions) available using the public key.
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

    $ pip install vtapi3

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

    $ python -m vtapi3.py  [-h] [-fid] [-fsr] [-far] [-hr] [-uid] [-usr] [-uar] [-ipr]
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

Release History
===============

1.1.2 (5.02.2020)
"""""""""""""""""

- Fixed ``__init__.py`` (to ensure correct implementation of import).
- Added ``__main__.py`` (to improve the command line experience).

1.1.1 (4.02.2020)
"""""""""""""""""

- Fixed several errors in the ``get_file_id_to_analyse()`` and ``get_url_id_to_analyse functions()``.
- Added VirusTotalAPIError(IO Error) exception in the ``get_file_id()`` and ``upload()`` functions of the VirusTotalAPIFiles class.

1.1.0 (3.02.2020)
"""""""""""""""""

- Added the ability to performance the package from the command line.

1.0.4 (1.02.2020)
"""""""""""""""""

- Fixing README.rst for better PYPI presentation.

1.0.3 (26.01.2020)
""""""""""""""""""

- Added a new attribute ``_last_result`` to the VirustotalAPI base class.
- Added a new method ``get_last_result`` to the VirustotalAPI base class.

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

.. |POST| image:: https://i.imgur.com/CWgYjh1.png
.. |GET| image:: https://i.imgur.com/CBcN0Fh.png
