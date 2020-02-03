VirusTotalAPIDomains
====================

The retrieving information about any domain from the VirusTotal database methods are defined in the class.

----

Methods:
--------

.. index:: get_report()

get_report(domain)
~~~~~~~~~~~~~~~~~~~
   Retrieve information about an Internet domain.

**Arguments:**

- ``domain`` : Domain name (str).

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError
      ...
   vt_api_domains = VirusTotalAPIDomains('<API key>')
   try:
       result = vt_api_domains.get_report('<domain>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_domains.get_last_http_error() == vt_api_domains.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_domains.get_last_http_error()) +']')
       ...

**Example response:**

    When ``_last_http_error`` = ``HTTP_OK`` and after conversion to JSON, the response will look like this:

.. code-block:: json

   {
     "data": {
       "type": "domain",
       "id": "virustotal.com",
       "links": {
         "self": "https://virustotal.com/api/v3/domains/virustotal.com"
       },
       "attributes": {
         "categories": {
           "Alexa": "services",
           "BitDefender": "computersandsoftware",
           "TrendMicro": "computers internet",
           "Websense ThreatSeeker": "computer security"
         },
         "creation_date": 1032308169,
         "last_update_date": 1389199030,
         "registrar": "MarkMonitor Inc.",
         "reputation": 13,
         "total_votes": {
           "harmless": 2,
           "malicious": 0
         },
    	   "whois": "Domain Name: VIRUSTOTAL.COM\r\n   Registry Domain ID: ...",    
         "whois_date": 1560599498
       }
     }
   }

----

.. index:: get_comments()

get_comments(domain, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve comments for an Internet domain.

**Arguments:**

- ``domain`` : Domain name (str).
- ``limit`` : Maximum number of comments to retrieve (int). The default value is 10.
- ``cursor`` : Continuation cursor (str). The default value is ''.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError
      ...
   vt_api_domains = VirusTotalAPIDomains('<API key>')
   try:
       result = vt_api_domains.get_comments('<domain>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_domains.get_last_http_error() == vt_api_domains.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_domains.get_last_http_error()) +']')
       ...

----

.. index:: put_comments()

put_comments(domain, text)
~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a comment to an Internet domain..

**Arguments:**

- ``domain`` : Domain name (str).
- ``text`` : Text of the comment (str). Any word starting with ``#`` in your comment's text will be considered a tag, and added to the comment's tag attribute.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError
      ...
   vt_api_domainss = VirusTotalAPIDomains('<API key>')
   try:
       result = vt_api_domains.put_comment('<domain>', '<text of the comment>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_domains.get_last_http_error() == vt_api_domains.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_domains.get_last_http_error()) +']')
       ...

----

.. index:: get_relationship()

get_relationship(domain, relationship, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve objects related to an Internet domain.

**Arguments:**

- ``domain`` : Domain name (str).
- ``relationship`` : Relationship name (str). The default value is ``/resolutions``. For more information, see https://developers.virustotal.com/v3.0/reference#domains-relationships.
- ``limit`` : Maximum number of related objects to retrieve (int). The default value is 10.
- ``cursor`` : Continuation cursor (str). The default value is ''.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError
      ...
   vt_api_domains = VirusTotalAPIDomains('<API key>')
   try:
       result = vt_api_domains.get_relationship('<domain>', 'downloaded_files')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_domains.get_last_http_error() == vt_api_domains.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_domains.get_last_http_error()) +']')
       ...

----

.. index:: get_votes()

get_votes(domain, limit, cursor)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Retrieve votes for a hostname or domain.

**Arguments:**

- ``domain`` : Domain name (str).
- ``limit`` : Maximum number of vites to retrieve (int). The default value is 10.
- ``cursor`` : Continuation cursor (str). The default value is ''.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError
      ...
   vt_api_domains = VirusTotalAPIDomains('<API key>')
   try:
       result = vt_api_domains.get_votes('<domain>', 5)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_domains.get_last_http_error() == vt_api_domains.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_domains.get_last_http_error()) +']')
       ...

----

.. index:: put_votes()

put_votes(domain, malicious)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   Add a vote for a hostname or domain.

**Arguments:**

- ``domain`` : Domain name(str).
- ``malicious`` : Determines a malicious (True) or harmless (False) file (bool). The default value is ``False``.

**Return value:**

    The response from the server as a byte sequence.

**Exception:**

- :ref:`error-label` (Connection error): In case of server connection errors.
- :ref:`error-label` (Timeout error): If the response timeout from the server is exceeded.

**Usage:**

.. code-block:: python

   from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError
      ...
   vt_api_domains = VirusTotalAPIDomains('<API key>')
   try:
       result = vt_api_domains.put_votes('<domain>', True)
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_domains.get_last_http_error() == vt_api_domains.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_domains.get_last_http_error()) +']')
       ...
