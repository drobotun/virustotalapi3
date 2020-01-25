VirusTotalAPI
=============

A base class for subclasses that implement methods for working with files, URLs, domain names, and IP addresses.

----

Attributes
----------
          
base_url
~~~~~~~~
    The base URL for sending requests (str). Has the value: ``https://www.virustotal.com/api/v3``.

headers
~~~~~~~
    Request header containing API key (dict).

timeout
~~~~~~~
    Server response timeout. A tuple that includes a timeout value for ``connect`` and a timeout value for ``read``. If specify a single timeout value, it will be applied to both timeout ``connect`` and timeout ``read``.

proxies
~~~~~~~
    The Protocol and the URL of the proxy server (dict).

_version_api
~~~~~~~~~~~~
    VirusTotal API version (str). Has the value: ``version 3``.

_last_http_error
~~~~~~~~~~~~~~~~
    HTTP status code of last operation (int).

----

Constants
---------

HTTP error codes constants

- **HTTP_OK** - Function completed successfully.
- **HTTP_BAD_REQUEST_ERROR** - The API request is invalid or malformed. The message usually provides details about why the request is not valid.
- **HTTP_AUTHENTICATION_REQUIRED_ERROR** - The operation requires an authenticated user. Verify that you have provided your API key.
- **HTTP_FORBIDDEN_ERROR** - You are not allowed to perform the requested operation.
- **HTTP_NOT_FOUND_ERROR** - The requested resource was not found.
- **HTTP_ALREADY_EXISTS_ERROR** - The resource already exists.
- **HTTP_QUOTA_EXCEEDED_ERROR** - You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.
- **HTTP_TRANSIENT_ERROR** - Transient server error. Retry might work.

----

Methods:
--------

__init__(api_key, timeout, proxies)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Inits VirusTotalAPI.

Arguments:
""""""""""

- *api_key* : Your API key to access the functions of the service VirusTotal (str). How to get the api key is described in: https://developers.virustotal.com/v3.0/reference#getting-started.
- *timeout* : Server response timeout (int). Optional.
- *proxies* : The protocol and the URL of the proxy server (dict). Optional.

----

get_version_api()
~~~~~~~~~~~~~~~~~
    Return the API version values.

Arguments:
""""""""""
    None.

Return value:
"""""""""""""
    String containing API version (``version 3``).

Usage:
""""""

.. code-block:: python

   import vtapi3
      ...
   vt_api = vtapi3.VirusTotalAPI('<API key>')
   version_api = vt_api.get_version_api()
   print(version_api)
      ...

----

get_last_http_error()
~~~~~~~~~~~~~~~~~~~~~
    Return the HTTP status code of last operation.

Arguments:
""""""""""
    None.

Return value:
"""""""""""""
    HTTP status code of last operation.

Usage:
""""""

.. code-block:: python

   import vtapi3
      ...
   vt_api = vtapi3.VirusTotalAPI('<API key>')
   http_error = vt_api.get_last_http_error()
   print(http_error)
      ...




