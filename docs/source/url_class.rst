VirusTotalAPIUrls
=================

The analysis new URLs and retrieving information about any URLs from the VirusTotal database methods are defined in the class.

----

Methods:
--------

get_url_id_base64(url)
~~~~~~~~~~~~~~~~~~~~~~
   Get base64 encoded URL identifier.

Arguments:
""""""""""

- *url* : The URL for which you want to get the identifier (str).

Return value:
"""""""""""""
   The identifier of the url, base64 encoded (str).

Usage:
""""""

.. code-block:: python

    from vtapi3 import VirusTotalAPIUrls
        ...
    url_id = VirusTotalAPIUrls.get_url_id_base64('<url>')
    print(url_id)
        ...

----

get_url_id_sha256(url)
~~~~~~~~~~~~~~~~~~~~~~
   Get the URL identifier as a SHA256 hash.

Arguments:
""""""""""

- *url* : The URL for which you want to get the identifier (str).

Return value:
"""""""""""""
   The identifier of the url, SHA256 encoded (str).

Usage:
""""""

.. code-block:: python

    from vtapi3 import VirusTotalAPIUrls
        ...
    url_id = VirusTotalAPIUrls.get_url_id_sha256('<url>')
    print(url_id)
        ...

----

upload(url)
~~~~~~~~~~~~~~~~~
    Upload URL for analysis.

Arguments:
""""""""""
    - *url* : URL to be analyzed (str).

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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.upload('<url>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

Response structure:
"""""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response structure will look like this:

.. code-block:: json

   {
     "data": {"id": "<string>", "type": "analysis"}
   }

----

get_report(url_id)
~~~~~~~~~~~~~~~~~~~
   Retrieve information about an URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).

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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.get_report('<url id>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

Response structure:
"""""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response structure will look like this (for more information, see https://developers.virustotal.com/v3.0/reference#ip-object):

.. code-block:: json

   {
     "data": "<URL OBJECT>"
   }

----

analyse(url_id)
~~~~~~~~~~~~~~~~
   Analyse an URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).

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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.analyse('<url id>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

Response structure:
"""""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response structure will look like this:

.. code-block:: json

   {
     "data": {"id": "<string>", "type": "analysis"}
   }

----

get_comments(url_id, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve comments for an URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).
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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.get_comments('<url id>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

----

put_comments(url_id, text)
~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a comment to a URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).
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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.put_comment('<url id>', '<text of the comment>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

----

get_votes(url_id, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve votes for a URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).
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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.get_votes('<url id>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

----

put_votes(url_id, malicious)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a vote to a URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).
- *malicious* : Determines a malicious (True) or harmless (False) URL (bool). The default value is ``False``.

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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.put_votes('<url id>', True)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

----

get_network_location(url_id)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Get the domain or IP address for a URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).

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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.get_network_location('<url id>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...

Response structure:
"""""""""""""""""""
    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response structure will look like this:

.. code-block:: json

   {
     "data": "<DOMAIN OBJECT> or <IP OBJECT>",
     "links": {"self": "<string>"}
   }

----

get_relationship(url_id, relationship, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve objects related to an URL.

Arguments:
""""""""""

- *url_id* : URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL (method `get_url_id_sha256(url)`_ ), the string resulting from encoding the URL in base64 without the "=" padding (method `get_url_id_base64(url)`_ ).
- *relationship* : Relationship name (str). The default value is ``/last_serving_ip_address``. For more information, see https://developers.virustotal.com/v3.0/reference#urls-relationships.
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

   from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
      ...
   vt_api_urls = VirusTotalAPIUrls('<API key>')
   try:
       result = vt_api_urls.get_relationship('<url id>', 'graphs')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_urls.get_last_http_error() == vt_api_urls.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_urls.get_last_http_error()) +']')
       ...
