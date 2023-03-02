"""The module describes the VirusTotalAPIFiles class

   Author: Evgeny Drobotun (c) 2019
   License: MIT (https://github.com/drobotun/virustotalapi3/blob/master/LICENSE)

   More information: https://virustotalapi3.readthedocs.io/en/latest/file_class.html
"""

import hashlib
import errno
import requests

from .vtapi3base import VirusTotalAPI
from .vtapi3error import VirusTotalAPIError

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
          get_download_url(): Get a download URL for a file (special privileges required).
          get_download(): Download a file (special privileges required).
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

    def get_download_url(self, file_id):
        """Get a download URL for a file. This function requires special privileges
           (you need a private key to access the VirusTotal API).
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
        api_url = self.base_url + '/files/' + file_id + '/download_url'
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

    def get_download(self, file_id):
        """Download a file. This function requires special privileges (you need a private
           key to access the VirusTotal API).
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
        api_url = self.base_url + '/files/' + file_id + '/download'
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
