"""The module describes classes that implement methods for accessing service API functions
   www.virustotai.com.

   More information: https://developers.virustotal.com/v3.0/reference#getting-started

   Author: Evgeny Drobotun (c) 2019
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

   Requirements:
      $ pip install requests

   Example usage:

   from vtapi3.vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_files = VirusTotalAPIFiles(<Insert API key string here>)
   try:
       result = vt_files.upload(<Insert faile name here>)
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
"""
import os
import sys
import json
import argparse
import base64
import hashlib
import errno
import requests


class VirusTotalAPI:
    """A base class for subclasses that implement methods for working with files, URLs, domain
       names, and IP addresses.

       Attributes:
          base_url: The base URL for sending requests (str).
          headers: Request header containing API key (dict).
          timeout: Server response timeout. A tuple that includes a timeout value for 'connect' and
             a timeout value for 'read'. If specify a single timeout value, it will be applied to
             both timeout 'connect' and timeout 'read'.
          proxies: The Protocol and the URL of the proxy server (dict).
          _version_api: VirusTotal API version (str).
          _last_http_error: HTTP status code of last operation (int).
          _last_result: Result of the last execution of a subclass method of this class.

       Constants: HTTP error codes constants.

       Methods:
         get_version_api(): Return the API version values.
         get_last_http_error(): Return the HTTP status code of last operation.
         get_last_result(): Return the result of executing methods of subclasses of this class.
    """

    HTTP_OK = requests.codes['ok']
    HTTP_BAD_REQUEST_ERROR = requests.codes['bad_request']
    HTTP_AUTHENTICATION_REQUIRED_ERROR = requests.codes['unauthorized']
    HTTP_FORBIDDEN_ERROR = requests.codes['forbidden']
    HTTP_NOT_FOUND_ERROR = requests.codes['not_found']
    HTTP_ALREADY_EXISTS_ERROR = requests.codes['conflict']
    HTTP_QUOTA_EXCEEDED_ERROR = requests.codes['too_many_requests']
    HTTP_TRANSIENT_ERROR = requests.codes['service_unavailable']

    def __init__(self, api_key=None, timeout=None, proxies=None):
        """Inits VirusTotalAPI.

           Args:
              api_key: your API key to access the functions of the service VirusTotal (str).
              timeout: Server response timeout (int). Optional.
              proxies: The Protocol and the URL of the proxy server (dict). Optional.
        """
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {'x-apikey' : api_key}
        self.timeout = timeout
        self.proxies = proxies
        self._version_api = 'version 3'
        self._last_http_error = None
        self._last_result = None

    def get_version_api(self):
        """Return the API version values.

           Return:
              String containing API version ('version 3').
        """
        return self._version_api

    def get_last_http_error(self):
        """Return the HTTP status code of last operation.

           Return:
              HTTP status code of last operation.
        """
        return self._last_http_error

    def get_last_result(self):
        """Return the result of executing methods of subclasses of this class.

           Return:
              Result of the last execution of a subclass method of this class.
        """
        return self._last_result


class VirusTotalAPIFiles(VirusTotalAPI):
    """The analysis new files and retrieving information about any file from the VirusTotal database
       methods are defined in the class.

       Methods:
          get_file_id(): Get SHA256, SHA1 or MD5 file identifier.
          upload(): Upload and analyse a file.
          get_upload_url(): Get a URL for uploading files larger than 32MB.
          get_report(): Retrieve information about a file.
          reanalyse(): Reanalyse a file already in VirusTotal.
          get_comments(): Retrieve comments for a file.
          put_comments(): Add a comment to a file.
          get_votes(): Retrieve votes for a file.
          put_votes(): Add a votes to a file.
          get_relationship(): Retrieve objects related to a file.
          get_behaviours(): Get the PCAP for the sandbox.
    """

    @staticmethod
    def get_file_id(file_path, hash_alg='sha256'):
        """Get SHA256, SHA1 or MD5 file identifier.

           Args:
              file_path: Path to the file to be scanned (str).
              hash: Necessary identifier ('sha256', 'sha1' or 'md5'). The default value is
                 'sha256'.

           Return:
              The SHA256, SHA1 or MD5 identifier of the file.

           Exception
              VirusTotalAPIError(File not found): In case the file is not found.
              VirusTotalAPIError(Permission error): In case do not have access rights to the file.
              VirusTotalAPIError(IO Error): If an IO error occurs during file operations.
        """
        buffer_size = 65536
        hasher = hashlib.new(hash_alg)
        try:
            with open(file_path, 'rb') as file:
                buffer = file.read(buffer_size)
                while len(buffer) > 0:
                    hasher.update(buffer)
                    buffer = file.read(buffer_size)
        except FileNotFoundError:
            raise VirusTotalAPIError('File not found', errno.ENOENT)
        except PermissionError:
            raise VirusTotalAPIError('Permission error', errno.EPERM)
        except OSError:
            raise VirusTotalAPIError('IO Error', errno.EIO)
        else:
            return hasher.hexdigest()

    def upload(self, file_path):
        """Upload and analyse a file.

        Args:
           file_path: Path to the file to be scanned (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
           VirusTotalAPIError(File not found): In case the file you want to upload to the server is
              not found.
           VirusTotalAPIError(Permission error): In case do not have access rights to the file.
           VirusTotalAPIError(IO Error): If an IO error occurs during file operations.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files'
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (file_path, file)}
                response = requests.post(api_url, headers=self.headers, files=files,
                                         timeout=self.timeout, proxies=self.proxies)
        except FileNotFoundError:
            raise VirusTotalAPIError('File not found', errno.ENOENT)
        except PermissionError:
            raise VirusTotalAPIError('Permission error', errno.EPERM)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        except OSError:
            raise VirusTotalAPIError('IO Error', errno.EIO)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_upload_url(self):
        """Get a URL for uploading files larger than 32MB.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/upload_url'
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_report(self, file_id):
        """Retrieve information about a file.

        Args:
           file_id: SHA-256, SHA-1 or MD5 identifying the file (str).

       Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def analyse(self, file_id):
        """Reanalyse a file already in VirusTotal.

        Args:
           file_id: SHA-256, SHA-1 or MD5 identifying the file (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id + '/analyse'
        try:
            response = requests.post(api_url, headers=self.headers,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_comments(self, file_id, limit=10, cursor='""'):
        """Retrieve comments for a file.

        Args:
           file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/comments'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_comments(self, file_id, text):
        """Add a comment to a file.

        Args:
           file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
           text: Text of the comment (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/files/' + file_id + '/comments'
        try:
            response = requests.post(api_url, headers=self.headers, json=comments,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_votes(self, file_id, limit=10, cursor='""'):
        """Retrieve votes for a file.

        Args:
           file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/votes'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_votes(self, file_id, malicious=False):
        """Add a votes to a file.

        Args:
           file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
           malicious: Determines a malicious (True) or harmless (False) file (bool).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict': verdict}}}
        api_url = self.base_url + '/files/' + file_id + '/votes'
        try:
            response = requests.post(api_url, headers=self.headers, json=votes,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_relationship(self, file_id, relationship='/behaviours', limit=10, cursor='""'):
        """Retrieve objects related to a file.

        Args:
           file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
           relationship: Relationship name (str). The default value is "/behaviours".
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + relationship
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_behaviours(self, sandbox_id):
        """Get the PCAP for the sandbox.

        Args:
           sandbox_id: Identifier obtained using the 'get_relationship' method with
              the value of the 'relationship' argument equal to 'behaviours' (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/file_behaviours/' + sandbox_id + '/pcap'
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content


class VirusTotalAPIUrls(VirusTotalAPI):
    """The analysis new URLs and retrieving information about any URLs from the VirusTotal database
       methods are defined in the class.

       Methods:
          get_url_id_base64(): Get base64 encoded URL identifier.
          get_url_id_sha256(): Get the URL identifier as a SHA256 hash.
          upload(): Upload URL for analysis.
          get_report(): Retrieve information about an URL.
          analyse(): Analyse an URL.
          get_comments(): Retrieve comments for an URL.
          put_comments(): Add a comment to a URL.
          get_votes(): Retrieve votes for an URL.
          put_votes(): Add a votes to a URL.
          get_network_location(): Get the domain or IP address for a URL.
    """

    @staticmethod
    def get_url_id_base64(url):
        """Get base64 encoded URL identifier.

        Args:
           url: The URL for which you want to get the identifier (str).

        Return:
           The identifier of the url, base64 encoded (str).
        """
        return base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').rstrip('=')

    @staticmethod
    def get_url_id_sha256(url):
        """Get the URL identifier as a SHA256 hash.

        Args:
           url: The URL for which you want to get the identifier (str).

        Return:
           The identifier of the url, SHA256 encoded (str).
        """
        return hashlib.sha256(url.encode()).hexdigest()

    def upload(self, url):
        """Upload URL for analysis.

        Args:
           url: URL to be analyzed (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        data = {'url': url}
        api_url = self.base_url + '/urls'
        try:
            response = requests.post(api_url, headers=self.headers, data=data,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_report(self, url_id):
        """Retrieve information about an URL.

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def analyse(self, url_id):
        """Analyse an URL.

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id + '/analyse'
        try:
            response = requests.post(api_url, headers=self.headers,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_comments(self, url_id, limit=10, cursor='""'):
        """Retrieve comments for an URL.

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + '/comments'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_comments(self, url_id, text):
        """Add a comment to a URL.

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').
           text: Text of the comment (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/urls/' + url_id + '/comments'
        try:
            response = requests.post(api_url, headers=self.headers, json=comments,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_votes(self, url_id, limit=10, cursor='""'):
        """Retrieve votes for a URL.

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + '/votes'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_votes(self, url_id, malicious=False):
        """Add a vote for a URL.

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').
           malicious: Determines a malicious (True) or harmless (False) URL (bool).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict': verdict}}}
        api_url = self.base_url + '/urls/' + url_id + '/votes'
        try:
            response = requests.post(api_url, headers=self.headers, json=votes,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_network_location(self, url_id):
        """Get the domain or IP address for a URL.

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id + '/network_location'
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_relationship(self, url_id, relationship='/last_serving_ip_address',
                         limit=10, cursor='""'):
        """Retrieve objects related to an URL

        Args:
           url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the
              canonized URL (method 'get_url_id_sha256()'), the string resulting from encoding the
              URL in base64 without the "=" padding (method 'get_url_id_base64()').
           relationship: Relationship name (str). The default value is '/last_serving_ip_address'.
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + relationship
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content


class VirusTotalAPIDomains(VirusTotalAPI):
    """The retrieving information about any domain from the VirusTotal database methods are defined
       in the class.

       Methods:
          get_report(): Retrieve information about an Internet domain.
          get_comments(): Retrieve comments for an Internet domain.
          put_comments(): Add a comment to an Internet domain.
          get_relationship(): Retrieve objects related to an Internet domain.
          get_votes(): Retrieve votes for a hostname or domain.
          put_votes(): Add a vote for a hostname or domain.
    """

    def get_report(self, domain):
        """Retrieve information about an Internet domain.

        Args:
           domain: Domain name (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/domains/' + domain
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_comments(self, domain, limit=10, cursor='""'):
        """Retrieve comments for an Internet domain.

        Args:
           domain: Domain name (str).
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/domains/' + domain + '/comments'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_comments(self, domain, text):
        """Add a comment to an Internet domain.

        Args:
           domain: Domain name (str).
           text: Text of the comment (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/domains/' + domain + '/comments'
        try:
            response = requests.post(api_url, headers=self.headers, json=comments,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_relationship(self, domain, relationship='/resolutions', limit=10, cursor='""'):
        """Retrieve objects related to an Internet domain.

        Args:
           domain: Domain name (str).
           relationship: Relationship name (str). The default value is '/resolutions'.
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/domains/' + domain + relationship
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_votes(self, domain, limit=10, cursor='""'):
        """Retrieve votes for a hostname or domain.

        Args:
           domain: Domain name (str).
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/domains/' + domain + '/votes'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_votes(self, domain, malicious=False):
        """Add a vote for a hostname or domain.

        Args:
           domain: Domain name (str).
           malicious: Determines a malicious (True) or harmless (False) domain (bool).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict': verdict}}}
        api_url = self.base_url + '/domains/' + domain + '/votes'
        try:
            response = requests.post(api_url, headers=self.headers, json=votes,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content


class VirusTotalAPIIPAddresses(VirusTotalAPI):
    """The retrieving information about any IP addresses from the VirusTotal database methods are
       defined in the class.

       Methods:
          get_report(): Retrieve information about an IP address.
          get_comments(): Retrieve comments for an IP address.
          put_comments(): Add a comment to an IP address.
          get_relationship(): Retrieve objects related to an IP address.
          get_votes(): Retrieve votes for an IP address.
          put_votes(): Add a vote for an IP address.
    """

    def get_report(self, ip_address):
        """Retrieve information about an IP address.

        Args:
           ip_address: IP address (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/ip_addresses/' + ip_address
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_comments(self, ip_address, limit=10, cursor='""'):
        """Retrieve comments for an IP address.

        Args:
           ip_address: IP address (str).
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/comments'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_comments(self, ip_address, text):
        """Add a comment to an IP address.

        Args:
           ip_address: IP address (str).
           text: Text of the comment (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/comments'
        try:
            response = requests.post(api_url, headers=self.headers, json=comments,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_relationship(self, ip_address, relationship='/resolutions', limit=10, cursor='""'):
        """Retrieve objects related to an IP address.

        Args:
           ip_address: IP address (str).
           relationship: Relationship name (str). The default value is '/resolutions'.
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + relationship
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_votes(self, ip_address, limit=10, cursor='""'):
        """Retrieve votes for an IP address.

        Args:
           domain: Domain name (str).
           limit: Maximum number of comments to retrieve (int). The default value is 10.
           cursor: Continuation cursor (str). The default value is ''.

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/votes'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_votes(self, ip_address, malicious=False):
        """Add a vote for an IP address.

        Args:
           domain: IP address (str).
           malicious: Determines a malicious (True) or harmless (False) domain (bool).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict': verdict}}}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/votes'
        try:
            response = requests.post(api_url, headers=self.headers, json=votes,
                                     timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content


class VirusTotalAPIAnalyses(VirusTotalAPI):
    """The retrieving information about analysis of the file or URL method are defined in the class.

       Methods:
          get_report(): Retrieve information about a file or URL analysis.
    """

    def get_report(self, object_id):
        """Retrieve information about a file or URL analysis.

        Args:
           object_id: Analysis identifier (str).

        Return:
           The response from the server as a byte sequence.

        Exception
           VirusTotalAPIError(Connection error): In case of server connection errors.
           VirusTotalAPIError(Timeout error): If the response timeout from the server is exceeded.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/analyses/' + object_id
        try:
            response = requests.get(api_url, headers=self.headers,
                                    timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content


class VirusTotalAPIError(Exception):
    """A class that implements exceptions that may occur when module class methods are used.
    """

    def __init__(self, message, err_code):
        """Inits VirusTotalAPIError.
        """
        super().__init__(message)
        self.err_code = err_code


def get_environment_api_key():
    """Returns the value of the API key from environment variables. To work correctly, you need
       to create an environment variable VT_API_KEY and write the current API key value to it.
       
       Return:
           The API key value from the environment variable VT_API_KEY.

        Exception
           VirusTotalAPIError(API key environment error): If there is no environment variable
              VT_API_KEY.
       
    """
    if 'VT_API_KEY' in os.environ:
        return os.environ['VT_API_KEY']
    else:
        raise VirusTotalAPIError('API key environment error', errno.EINVAL)

def get_file_id_to_analyse(file_path, api_key):
    """Returns the file ID for further analysis on VirusTotal.
    
       Args:
          file_path: Path to the file for which you want to get the ID (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The file ID if successful, or error message if not.
    """
    vt_files = VirusTotalAPIFiles(api_key)
    try:
        result = vt_files.upload(file_path)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            return 'File ID: ' + str(result['data']['id'])
        else:
            return 'HTTP error ' + str(vt_files.get_last_http_error())
    except VirusTotalAPIError as err:
        return err

def get_file_scan_report(file_path, api_key):
    """Returns an analysis report for a file uploaded to VirusTotal.
    
       Args:
          file_path: Path to the file to be analyzed on VirusTotal (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    vt_files = VirusTotalAPIFiles(api_key)
    try:
        result = vt_files.upload(file_path)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            file_id = str(result['data']['id'])
        else:
            return 'HTTP error ' + str(vt_files.get_last_http_error())
        vt_analyses = VirusTotalAPIAnalyses(api_key)
        result = vt_analyses.get_report(file_id)
        if vt_analyses.get_last_http_error() == vt_analyses.HTTP_OK:
            result = json.loads(result)
            return 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            return 'HTTP error ' + str(vt_analyses.get_last_http_error())
    except VirusTotalAPIError as err:
        return err    

def get_file_analyse_report(file_path, api_key):
    """Returns an analysis report for a file in the VirusTotal database.
    
       Args:
          file_path: Path to the file for which you want to get the analysis report (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    try:
        vt_files = VirusTotalAPIFiles(api_key)
        file_id = vt_files.get_file_id(file_path)
        result = vt_files.get_report(file_id)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            return 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            return 'HTTP error ' + str(vt_files.get_last_http_error())
    except VirusTotalAPIError as err:
        return err    

def get_hash_report(hash_id, api_key):
    """Returns an analysis report for a file in the VirusTotal database.
    
       Args:
          hash_id: Hash (SHA256, SHA1 or MD5) of the file for which you want to get an analysis
             report (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    try:
        vt_files = VirusTotalAPIFiles(api_key)
        result = vt_files.get_report(hash_id)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            return 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            return 'HTTP error ' + str(vt_files.get_last_http_error())
    except VirusTotalAPIError as err:
        return err

def get_url_id_to_analyse(url, api_key):
    """Returns the URL ID for further analysis on VirusTotal.
    
       Args:
          url: URL address for which you want to get an ID (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The URL ID if successful, or error message if not.
    """
    vt_urls = VirusTotalAPIUrls(api_key)
    try:
        result = vt_urls.upload(url)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            return 'URL ID: ' + result['data']['id']
        else:
            return 'HTTP error ' + str(vt_urls.get_last_http_error())
    except VirusTotalAPIError as err:
        return err

def get_url_scan_report(url, api_key):
    """Returns an analysis report for a URL uploaded to VirusTotal.
    
       Args:
          url: URL to be analyzed on VirusTotal (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    vt_urls = VirusTotalAPIUrls(api_key)
    try:
        result = vt_urls.upload(url)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            url_id = result['data']['id']
        else:
            return 'HTTP error ' + str(vt_urls.get_last_http_error())
        vt_analyses = VirusTotalAPIAnalyses(api_key)
        result = vt_analyses.get_report(url_id)
        if vt_analyses.get_last_http_error() == vt_analyses.HTTP_OK:
            result = json.loads(result)
            return 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            return 'HTTP error ' + str(vt_analyses.get_last_http_error())
    except VirusTotalAPIError as err:
        return err

def get_url_analyse_report(url, api_key):
    """Returns an analysis report for a URL in the VirusTotal database.
    
       Args:
          url: URL for which you want to get the analysis report (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    vt_urls = VirusTotalAPIUrls(api_key)
    try:
        url_id = vt_urls.get_url_id_base64(url)
        result = vt_urls.get_report(url_id)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            return 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            return 'HTTP error ' + str(vt_urls.get_last_http_error())
    except VirusTotalAPIError as err:
        return err

def get_ip_report(ip_address, api_key):
    """Returns a report on the results of IP address analysis.
    
       Args:
          ip_address: IP address for which you want to get the analysis report (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    try:
        vt_ip = VirusTotalAPIIPAddresses(api_key)
        result = vt_ip.get_report(ip_address)
        if vt_ip.get_last_http_error() == vt_ip.HTTP_OK:
            result = json.loads(result)
            return 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            return 'HTTP error ' + str(vt_ip.get_last_http_error())
    except VirusTotalAPIError as err:
        return err

def get_domain_report(domain, api_key):
    """Returns a report on the results of domain analysis.
    
       Args:
          domain: Domain for which you want to get the analysis report (str).
          api_key: Access key to VirusTotal API functions (str).
          
       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    try:
        vt_domain = VirusTotalAPIDomains(api_key)
        result = vt_domain.get_report(domain)
        if vt_domain.get_last_http_error() == vt_domain.HTTP_OK:
            result = json.loads(result)
            return 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            return 'HTTP error ' + str(vt_domain.get_last_http_error())
    except VirusTotalAPIError as err:
        return err

def main():
    print('\nThe vtapi3 package. Implements the VirusTotal service API functions (3 versions).')
    print('MIT Copyright (c) 2020, Evgeny Drobotun\n')
    try:
        api_key = get_environment_api_key()
    except VirusTotalAPIError as err:
        print(err)
        sys.exit()

    parser = argparse.ArgumentParser(description='vtapi3 package options')
    parser.add_argument('resource',
                        help='Object that you want to analyse in VirusTotal (file, URL, IP address or domain)')
    parser.add_argument('-fid', '--file-id', action='store_true', dest='file_id',
                        help='Getting the identifier of the file for further analysis')
    parser.add_argument('-fsr', '--file-scan-report', action='store_true', dest='file_scan_report',
                        help='Getting a report on the results of scanning a file')
    parser.add_argument('-far', '--file-analyse-report', action='store_true', dest='file_analyse_report',
                        help='Getting a report on the results of file analysis (enabled by default)')
    parser.add_argument('-hr', '--hash-report', action='store_true', dest='hash_report',
                        help='Getting a report on the results of analyzing a file by its hash (SHA256, SHA1 or MD5)')
    parser.add_argument('-uid', '--url-id', action='store_true', dest='url_id',
                        help = 'Getting the identifier of the URL for further analysis')
    parser.add_argument('-usr', '--url-scan-report', action='store_true', dest='url_scan_report',
                        help = 'Getting a report on the results of scanning a URL')
    parser.add_argument('-uar', '--url-analyse-report', action='store_true', dest='url_analyse_report',
                        help='Getting a report on the results of URL analysis')
    parser.add_argument('-ipr', '--ip-report', action='store_true', dest='ip_report',
                        help='Getting a report on the results of IP address analysis')
    parser.add_argument('-dr', '--domain-report', action='store_true', dest='domain_report',
                        help='Getting a report on the results of domain analysis')
    options = parser.parse_args()
    
    if options.file_id:
        print(get_file_id_to_analyse(options.resource, api_key))
    elif options.file_scan_report:
        print(get_file_scan_report(options.resource, api_key))
    elif options.file_analyse_report:
        print(get_file_analyse_report(options.resource, api_key))
    elif options.hash_report:
        print(get_hash_report(options.resource, api_key))
    elif options.url_id:
        print(get_url_id_to_analyse(options.resource, api_key))
    elif options.url_scan_report:
        print(get_url_scan_report(options.resource, api_key))
    elif options.url_analyse_report:
        print(get_url_analyse_report(options.resource, api_key))
    elif options.ip_report:
        print(get_ip_report(options.resource, api_key))
    elif options.domain_report:
        print(get_domain_report(options.resource, api_key))
    else:
        print(get_file_analyse_report(options.resource, api_key))

if __name__ == '__main__':
    main()
