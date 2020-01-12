VirusTotalAPIFiles
==================

The analysis new files and retrieving information about any file from the VirusTotal database methods are defined in the class.

----


Methods:
--------

get_file_id(file_path, hash_alg)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Get SHA256, SHA1 or MD5 file identifier.

Arguments:
""""""""""

- *file_path* : Path to the file to be scanned (str).
- *hash_alg* : Necessary identifier ('sha256', 'sha1' or 'md5'). The default value is 'sha256'.

Return value:
"""""""""""""
    The SHA256, SHA1 or MD5 identifier of the file (str).

Exception:
""""""""""

- :ref:`error-label` (File not found)`: In case the file you want to upload to the server is not found.
- :ref:`error-label` (Permission error)`: In case do not have access rights to the file.

Usage:
""""""

.. code-block:: python

    from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
        ...
    try:
        file_id = VirusTotalAPIFiles.get_file_id('<file path>')
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else: 
        print(file_id)
        ...

----

upload(file_path)
~~~~~~~~~~~~~~~~~
    Upload and analyse a file.

Arguments:
""""""""""
    - *file_path* : Path to the file to be scanned (str).

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.
- :ref:`error-label` (File not found): In case the file you want to upload to the server is not found.
- :ref:`error-label` (Permission error): In case do not have access rights to the file.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.upload('<file path>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

.. note:: The total payload size can not exceed 32 MB. For uploading larger files see the `get_upload_url()`_ .

Example response:
"""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response will look like this:

.. code-block::

   {
     "data": {
       "type": "analysis",
       "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
     }
   }

----

get_upload_url()
~~~~~~~~~~~~~~~~
    Get a URL for uploading files larger than 32 MB.

Arguments:
""""""""""
    None.

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.get_upload_url()
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

Example response:
"""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response will look like this:

.. code-block::

   {
     "data": "http://www.virustotal.com/_ah/upload/AMmfu6b-_DXUeFe36Sb3b0F4B8mH9Nb-CHbRoUNVOPwG/"
   }

----

get_report(file_id)
~~~~~~~~~~~~~~~~~~~
   Retrieve information about a file.

Arguments:
""""""""""

- *fle_id* : SHA-256, SHA-1 or MD5 identifying the file (str).

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.get_report('<file id>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

Example response:
"""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response will look like this:

.. code-block::

   {    
     "type": "file",
     "id": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
     "links": {
       "self": "https://www.virustotal.com/api/v3/files/8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85"
     },
     "data": {
       "attributes": {
         "first_seen_itw_date": 1075654056,
         "first_submission_date": 1170892383,
         "last_analysis_date": 1502355193,
         "last_analysis_results": {
           "AVG": {
             "category": "undetected",
             "engine_name": "AVG",
             "engine_update": "20170810",
             "engine_version": "8.0.1489.320",
             "method": "blacklist",
             "result": null
           }
           ...
         },
         "last_analysis_stats": {
           "harmless": 0,
           "malicious": 0,
           "suspicious": 0,
           "timeout": 0,
           "type-unsupported": 8,
           "undetected": 59
         },
         "last_submission_date": 1502355193,
         "magic": "data",
         "md5": "76cdb2bad9582d23c1f6f4d868218d6c",
         "names": [
           "zipnew.dat",
           "327916-1502345099.zip",
           "ac3plug.zip",
           "IMG_6937.zip",
           "DOC952.zip",
           "20170801486960.zip"
         ],
         "nsrl_info": {
           "filenames": [
             "WINDOWS DIALUP.ZIP",
             "kemsetup.ZIP",
             "Data_Linux.zip",
             "2003.zip",
             "_6A271FB199E041FC82F4D282E68B01D6"
           ],
           "products": [
             "Master Hacker Internet Terrorism (Core Publishing Inc.)",
             "Read Rabbits Math Ages 6-9 (Smart Saver)",
             "Neverwinter Nights Gold (Atari)",
             "Limited Edition Print Workshop 2004 (ValuSoft)",
             "Crysis (Electronic Arts Inc.)"
           ]
         },
         "reputation": -889,
         "sha1": "b04f3ee8f5e43fa3b162981b50bb72fe1acabb33",
         "sha256": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
         "size": 22,
         "ssdeep": "3:pjt/l:Nt",
         "tags": [
           "software-collection",
           "nsrl",
           "attachment",
           "trusted",
           "via-tor"
         ],
         "times_submitted": 26471,
         "total_votes": {
           "harmless": 639,
           "malicious": 958
         },
         "trid": [
           {
             "file_type": "ZIP compressed archive (empty)",
             "probability": 100
           }
         ],
         "trusted_verdict": {
           "filename": "lprn_spotlightstory_015.zip",
           "link": "https://dl.google.com/dl/spotlight/test/lprn_spotlightstory/9/lprn_spotlightstory_015.zip",
           "organization": "Google",
           "verdict": "goodware"
         },
         "type_description": "unknown",
         }
       }
     }
   }

----

analyse(file_id)
~~~~~~~~~~~~~~~~
   Reanalyse a file already in VirusTotal.

Arguments:
""""""""""

- *fle_id* : SHA-256, SHA-1 or MD5 identifying the file (str).

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.analyse('<file id>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

Example response:
"""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response will look like this:

.. code-block::

   {
     "data": {
       "type": "analysis",
       "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
     }
   }

----

get_comments(file_id, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve comments for a file.

Arguments:
""""""""""

- *fle_id* : SHA-256, SHA-1 or MD5 identifying the file (str).
- *limit* : Maximum number of comments to retrieve (int). The default value is 10.
- *cursor* : Continuation cursor (str). The default value is ''.

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.get_comments('<file id>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

----

put_comments(file_id, text)
~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a comment to a file.

Arguments:
""""""""""

- *fle_id* : SHA-256, SHA-1 or MD5 identifying the file (str).
- *text* : Text of the comment (str). Any word starting with ``#`` in your comment's text will be considered a tag, and added to the comment's tag attribute.

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.put_comment('<file id>', '<text of the comment>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

Example response:
"""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response will look like this:

.. code-block::

   {
     "data": {
       "type": "comment",
       "id": "<comment's ID>",
       "links": {
         "self": "https://www.virustotal.com/api/v3/comments/<comment's ID>"
       },
       "attributes": {
         "date": 1521725475,
         "tags": ["ipsum"],
         "html": "Lorem #ipsum dolor sit ...",
         "text": "Lorem #ipsum dolor sit ...",
         "votes": {
           "abuse": 0,
           "negative": 0,
           "positive": 0
         }
       }
     }
   }

----

get_votes(file_id, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve votes for a file.

Arguments:
""""""""""

- *fle_id* : SHA-256, SHA-1 or MD5 identifying the file (str).
- *limit* : Maximum number of vites to retrieve (int). The default value is 10.
- *cursor* : Continuation cursor (str). The default value is ''.

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.get_votes('<file id>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

----

put_votes(file_id, malicious)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a vote to a file.

Arguments:
""""""""""

- *fle_id* : SHA-256, SHA-1 or MD5 identifying the file (str).
- *malicious* : Determines a malicious (True) or harmless (False) file (bool). The default value is ``False``.

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.put_votes('<file id>', True)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

----

get_relationship(file_id, relationship, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve objects related to a file.

Arguments:
""""""""""

- *fle_id* : SHA-256, SHA-1 or MD5 identifying the file (str).
- *relationship* : Relationship name (str). The default value is ``/behaviours``. For more information, see https://developers.virustotal.com/v3.0/reference#files-relationships.
- *limit* : Maximum number of related objects to retrieve (int). The default value is 10.
- *cursor* : Continuation cursor (str). The default value is ''.

Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.get_relationship('<file id>', 'bundled_files')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...

----

get_behaviours(sandbox_id)
~~~~~~~~~~~~~~~~~~~~~~~~~~
   Get the PCAP for the sandbox.

Arguments:
""""""""""

- *sandbox_id* : Identifier obtained using the `get_relationship(file_id, relationship, limit, cursor)`_ method with the value of the ``relationship`` argument equal to ``behaviours`` (str).
   
Return value:
"""""""""""""
    The response from the server as a byte sequence.

Exception:
""""""""""

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

Usage:
""""""

.. code-block:: python

   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_api_files = VirusTotalAPIFiles('<API key>')
   try:
       result = vt_api_files.get_relationship('<file id>', 'bundled_files')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
       ...
