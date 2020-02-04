import vtapi3
import argparse

def main():
    print('\nThe vtapi3 package. Implements the VirusTotal service API functions (3 versions).')
    print('MIT Copyright (c) 2020, Evgeny Drobotun\n')
    try:
        api_key = vtapi3.get_environment_api_key()
    except vtapi3.VirusTotalAPIError as err:
        print(err)
        sys.exit()
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
        print(vtapi3.get_file_id_to_analyse(options.resource, api_key))
    elif options.file_scan_report:
        print(vtapi3.get_file_scan_report(options.resource, api_key))
    elif options.file_analyse_report:
        print(vtapi3.get_file_analyse_report(options.resource, api_key))
    elif options.hash_report:
        print(vtapi3.get_hash_report(options.resource, api_key))
    elif options.url_id:
        print(vtapi3.get_url_id_to_analyse(options.resource, api_key))
    elif options.url_scan_report:
        print(vtapi3.get_url_scan_report(options.resource, api_key))
    elif options.url_analyse_report:
        print(vtapi3.get_url_analyse_report(options.resource, api_key))
    elif options.ip_report:
        print(vtapi3.get_ip_report(options.resource, api_key))
    elif options.domain_report:
        print(vtapi3.get_domain_report(options.resource, api_key))
    else:
        print(vtapi3.get_file_analyse_report(options.resource, api_key))

if __name__ == '__main__':
    main()
