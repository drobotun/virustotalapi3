VirusTotalAPIIPAddresses
========================

The retrieving information about any IP addresses from the VirusTotal database methods are defined in the class.

----

Methods:
--------

.. index:: get_report()

get_report(ip_address)
~~~~~~~~~~~~~~~~~~~~~~
   Retrieve information about an IP address.

**Arguments:**

- ``ip_address`` : IP address (str).

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
      ...
   vt_api_ip_addresses = VirusTotalAPIIPAddresses('<API key>')
   try:
       result = vt_api_ip_addresses.get_report('<ip_address>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
       ...

**Example response:**

    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response will look like this:

.. code-block:: json

   {    
     "type": "ip_address",
     "id": "8.8.8.8",
     "links": {
       "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
     },
     "data": {
       "attributes": {
         "as_owner": "Google Inc.",
         "asn": 15169,
         "country": "US"
       }
     }
   }

----

.. index:: get_comments()

get_comments(ip_address, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve comments for an IP address.

**Arguments:**

- ``ip_address`` : IP address (str).
- ``limit`` : Maximum number of comments to retrieve (int). The default value is 10.
- ``cursor`` : Continuation cursor (str). The default value is ''.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
      ...
   vt_api_ip_addresses = VirusTotalAPIIPAddresses('<API key>')
   try:
       result = vt_api_ip_addresses.get_comments('<ip_address>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
       ...

----

.. index:: put_comments()

put_comments(ip_address, text)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a comment to an IP address.

**Arguments:**

- ``ip_address`` : IP address (str).
- ``text`` : Text of the comment (str). Any word starting with ``#`` in your comment's text will be considered a tag, and added to the comment's tag attribute.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
      ...
   vt_api_ip_addresses = VirusTotalAPIIPAddresses('<API key>')
   try:
       result = vt_api_ip_addresses.put_comment('<ip_address>', '<text of the comment>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
       ...

----

.. index:: get_relationship()

get_relationship(ip_address, relationship, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve objects related to an IP address.

**Arguments:**

- ``ip_address`` : IP address (str).
- ``relationship`` : Relationship name (str). The default value is ``/resolutions``. For more information, see https://developers.virustotal.com/v3.0/reference#ip-relationships.
- ``limit`` : Maximum number of related objects to retrieve (int). The default value is 10.
- ``cursor`` : Continuation cursor (str). The default value is ''.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
      ...
   vt_api_ip_addresses = VirusTotalAPIIPAddresses('<API key>')
   try:
       result = vt_api_ip_addresses.get_relationship('<ip_address>', 'downloaded_files')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
       ...

----

.. index:: get_votes()

get_votes(ip_address, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve votes for an IP address.

**Arguments:**

- ``ip_address`` : IP address (str).
- ``limit`` : Maximum number of vites to retrieve (int). The default value is 10.
- ``cursor`` : Continuation cursor (str). The default value is ''.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
      ...
   vt_api_ip_addresses = VirusTotalAPIIPAddresses('<API key>')
   try:
       result = vt_api_ip_addresses.get_votes('<ip_address>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
       ...

----

.. index:: put_votes()

put_votes(ip_address, malicious)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a vote for an IP address.

**Arguments:**

- ``ip_address`` : IP address (str).
- ``malicious`` : Determines a malicious (True) or harmless (False) file (bool). The default value is ``False``.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
      ...
   vt_api_ip_addresses = VirusTotalAPIIPAddresses('<API key>')
   try:
       result = vt_api_ip_addresses.put_votes('<ip_address>', True)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
       ...
