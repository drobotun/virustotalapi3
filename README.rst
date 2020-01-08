.. image:: https://i.imgur.com/6nji8Ec.png
    :target: https://www.virustotal.com

VirusTotal API 3 версия
=======================

.. image:: https://img.shields.io/github/license/drobotun/virustotalapi3?style=flat
    :target: http://doge.mit-license.org
.. image:: https://travis-ci.org/drobotun/virustotalapi3.svg?branch=master
    :target: https://travis-ci.org/drobotun/virustotalapi3
.. image:: https://img.shields.io/pypi/v/vtapi3
    :target: https://pypi.org/project/vtapi3/
.. image:: https://img.shields.io/pypi/pyversions/vtapi3
    :target: https://pypi.org/project/vtapi3/

Модуль, реализующий функции API сервиса www.virustotal.com (3 версии), доступных с использованием открытого ключа.
Подробное описание API смотри на: https://developers.virustotal.com/v3.0/reference

Реализованы следующие функции API VirusTotal:

**Для файлов:**

- .. image:: https://i.imgur.com/M59T6Ut.png /files
- **GET** /files/upload_url
- **GET** /files/{id}
- **POST** /files/{id}/analyse
- **GET** /files/{id}/comments
- **POST** /files/{id}/comments
- **GET** /files/{id}/votes
- **POST** /files/{id}/votes
- **GET** /files/{id}/{relationship}
- **GET** /file_behaviours/{sandbox_id}/pcap

**Для URL:**

- **POST** /urls
- **GET** /urls/{id}
- **POST** /urls/{id}/analyse
- **GET** /urls/{id}/comments
- **POST** /urls/{id}/comments
- **GET** /urls/{id}/votes
- **POST** /urls/{id}/votes
- **GET** /urls/{id}/network_location

**Для доменов:**

- **GET** /domains/{domain}
- **GET** /domains/{domain}/comments
- **POST** /domains/{domain}/comments
- **GET** /domains/{domain}/{relationship}
- **GET** /domains/{domain}/votes
- **POST** /domains/{domain}/votes

**Для IP-адресов:**

- **GET** /domains/{domain}
- **GET** /domains/{domain}/comments
- **POST** /domains/{domain}/comments
- **GET** /domains/{domain}/{relationship}
- **GET** /domains/{domain}/votes
- **POST** /domains/{domain}/votes

**Анализ файлов и URL:**

- **GET** /analyses/{id}

Установка пакета
----------------

.. code-block:: bash

    $ pip install vtapi3

Пример использования
--------------------

.. code-block:: python

   import json
   from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_files = VirusTotalAPIFiles('<ключ доступа к API>')
   try:
       result = vt_files.upload('<путь к файлу>')
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

Ответ сервера
-------------

.. code-block:: json

    {
      "data": {
        "type": "analysis",
        "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
      }
    }
    
