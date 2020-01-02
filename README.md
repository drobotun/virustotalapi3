# VirusTotal API 3 версия
Модуль, реализующий функции API сервиса www.virustotal.com (3 версии), доступных с использованием открытого ключа.
Подробное описание API смотри на: https://developers.virustotal.com/v3.0/reference#getting-started

## Пример использования

```python
   from vtapi3.vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
      ...
   vt_files = VirusTotalAPIFiles('<API key string>')
   try:
       result = vt_files.upload('<faile name>')
   except VirusTotalAPIError as err:
       print(err, err.err_code)
   else:
       if vt_files.get_last_http_error() == HTTP_OK:
           result = json.loads(result)
           result = json.dumps(result, sort_keys=False, indent=4)
           print(result)
       else:
           print('HTTP Error [' + str(vt_files.get_last_http_error()) +']')
      ...
```
