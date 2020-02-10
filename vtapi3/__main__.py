import os
import json
import errno
import argparse
import vtapi3

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
        result = os.environ['VT_API_KEY']
    else:
        raise vtapi3.VirusTotalAPIError('API key environment error', errno.EINVAL)
    return result

def get_file_id_to_analyse(file_path, api_key):
    """Returns the file ID for further analysis on VirusTotal.

       Args:
          file_path: Path to the file for which you want to get the ID (str).
          api_key: Access key to VirusTotal API functions (str).

       Return:
          The file ID if successful, or error message if not.
    """
    vt_files = vtapi3.VirusTotalAPIFiles(api_key)
    try:
        result = vt_files.upload(file_path)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            result = 'File ID: ' + str(result['data']['id'])
        else:
            result = 'HTTP error ' + str(vt_files.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_file_scan_report(file_path, api_key):
    """Returns an analysis report for a file uploaded to VirusTotal.

       Args:
          file_path: Path to the file to be analyzed on VirusTotal (str).
          api_key: Access key to VirusTotal API functions (str).

       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    vt_files = vtapi3.VirusTotalAPIFiles(api_key)
    try:
        result = vt_files.upload(file_path)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            file_id = str(result['data']['id'])
            vt_analyses = vtapi3.VirusTotalAPIAnalyses(api_key)
            result = vt_analyses.get_report(file_id)
            if vt_analyses.get_last_http_error() == vt_analyses.HTTP_OK:
                result = json.loads(result)
                result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
            else:
                result = 'HTTP error ' + str(vt_analyses.get_last_http_error())
        else:
            result = 'HTTP error ' + str(vt_files.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
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
        vt_files = vtapi3.VirusTotalAPIFiles(api_key)
        file_id = vt_files.get_file_id(file_path)
        result = vt_files.get_report(file_id)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_files.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
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
        vt_files = vtapi3.VirusTotalAPIFiles(api_key)
        result = vt_files.get_report(hash_id)
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_files.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_url_id_to_analyse(url, api_key):
    """Returns the URL ID for further analysis on VirusTotal.

       Args:
          url: URL address for which you want to get an ID (str).
          api_key: Access key to VirusTotal API functions (str).

       Return:
          The URL ID if successful, or error message if not.
    """
    vt_urls = vtapi3.VirusTotalAPIUrls(api_key)
    try:
        result = vt_urls.upload(url)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            result = 'URL ID: ' + result['data']['id']
        else:
            result = 'HTTP error ' + str(vt_urls.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_url_scan_report(url, api_key):
    """Returns an analysis report for a URL uploaded to VirusTotal.

       Args:
          url: URL to be analyzed on VirusTotal (str).
          api_key: Access key to VirusTotal API functions (str).

       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    vt_urls = vtapi3.VirusTotalAPIUrls(api_key)
    try:
        result = vt_urls.upload(url)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            url_id = result['data']['id']
            vt_analyses = vtapi3.VirusTotalAPIAnalyses(api_key)
            result = vt_analyses.get_report(url_id)
            if vt_analyses.get_last_http_error() == vt_analyses.HTTP_OK:
                result = json.loads(result)
                result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
            else:
                result = 'HTTP error ' + str(vt_analyses.get_last_http_error())
        else:
            result = 'HTTP error ' + str(vt_urls.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def get_url_analyse_report(url, api_key):
    """Returns an analysis report for a URL in the VirusTotal database.

       Args:
          url: URL for which you want to get the analysis report (str).
          api_key: Access key to VirusTotal API functions (str).

       Return:
          The report on the results of the analysis if successful, or error message if not.
    """
    vt_urls = vtapi3.VirusTotalAPIUrls(api_key)
    try:
        url_id = vt_urls.get_url_id_base64(url)
        result = vt_urls.get_report(url_id)
        if vt_urls.get_last_http_error() == vt_urls.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_urls.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
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
        vt_ip = vtapi3.VirusTotalAPIIPAddresses(api_key)
        result = vt_ip.get_report(ip_address)
        if vt_ip.get_last_http_error() == vt_ip.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_ip.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
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
        vt_domain = vtapi3.VirusTotalAPIDomains(api_key)
        result = vt_domain.get_report(domain)
        if vt_domain.get_last_http_error() == vt_domain.HTTP_OK:
            result = json.loads(result)
            result = 'Analysis report:\n' + json.dumps(result, sort_keys=False, indent=4)
        else:
            result = 'HTTP error ' + str(vt_domain.get_last_http_error())
        return result
    except vtapi3.VirusTotalAPIError as err:
        return err

def create_cmd_parser():
    parser = argparse.ArgumentParser(prog='vtapi3')
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
                        help='Getting the identifier of the URL for further analysis')
    parser.add_argument('-usr', '--url-scan-report', action='store_true', dest='url_scan_report',
                        help='Getting a report on the results of scanning a URL')
    parser.add_argument('-uar', '--url-analyse-report', action='store_true', dest='url_analyse_report',
                        help='Getting a report on the results of URL analysis')
    parser.add_argument('-ipr', '--ip-report', action='store_true', dest='ip_report',
                        help='Getting a report on the results of IP address analysis')
    parser.add_argument('-dr', '--domain-report', action='store_true', dest='domain_report',
                        help='Getting a report on the results of domain analysis')
    return parser

def get_cmd_options(parser):
    return parser.parse_args()

def main(options):
    print('\nThe vtapi3 package. Implements the VirusTotal service API functions (3 versions).')
    print('MIT Copyright (c) 2020, Evgeny Drobotun\n')
    try:
        api_key = get_environment_api_key()
        if options.file_id:
            result = get_file_id_to_analyse(options.resource, api_key)
        elif options.file_scan_report:
            result = get_file_scan_report(options.resource, api_key)
        elif options.file_analyse_report:
            result = get_file_analyse_report(options.resource, api_key)
        elif options.hash_report:
            result = get_hash_report(options.resource, api_key)
        elif options.url_id:
            result = get_url_id_to_analyse(options.resource, api_key)
        elif options.url_scan_report:
            result = get_url_scan_report(options.resource, api_key)
        elif options.url_analyse_report:
            result = get_url_analyse_report(options.resource, api_key)
        elif options.ip_report:
            result = get_ip_report(options.resource, api_key)
        elif options.domain_report:
            result = get_domain_report(options.resource, api_key)
        else:
            result = get_file_analyse_report(options.resource, api_key)
        return result
    except vtapi3.VirusTotalAPIError as err:
        print(err)
        print('\nTo work correctly, you need the VT_API_KEY environment variable')
        print('with the current access key to the VirusTotal API functions.')
        return err

if __name__ == '__main__':
    print(main(get_cmd_options(create_cmd_parser())))
