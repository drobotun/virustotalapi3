VirusTotalAPIAnalyses
=====================

The retrieving information about analysis of the file or URL method are defined in the class.

----

Methods:
--------

get_report(object_id)
~~~~~~~~~~~~~~~~~~~~~~
   Retrieve information about a file or URL analysis.

Arguments:
""""""""""

- *object_id* : Analysis identifier (str).

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

   from vtapi3 import VirusTotalAPIAnalyses, VirusTotalAPIError
      ...
   vt_api_analyses = VirusTotalAPIAnalyses('<API key>')
   try:
       result = vt_api_analyses.get_report('<object id>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_api_analyses.get_last_http_error() == vt_api_analyses.HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_api_analyses.get_last_http_error()) +']')
       ...
