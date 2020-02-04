Command line option
===================

This feature has been implemented since version 1.1.0. Using the command line options you can:

- upload the file to VirusTotal for scanning and get the file ID for later use with the ``get_report()`` function of the ``VirusTotalAPIAnalyses`` class;
- upload a file to VirusTotal for scanning and get a report on the results of its scanning;
- get a report on the results of analyzing a file that is available in the VirusTotal database;
- get a report on the results of analyzing a file that is available in the VirusTotal database by its hash ID (SHA1, SHA256 or MD5);
- upload a URL to VirusTotal for scanning and get the URL ID for later use using the ``get_report()`` function of the ``VirusTotalAPIAnalyses`` class;
- upload a URL to VirusTotal for scanning and get a report on the results of its scanning;
- get a report on the results of analyzing a URL that is available in the VirusTotal database;
- get a report on the results of IP address analysis;
- get a report on the results of domain analysis.

-----

Сommon format
-------------

.. code-block:: bash

    $ python -m vtapi3 <resource> [-h], [-fid], [-fsr], [-far], [-hr], [-uid], [-usr], [-uar], [-ipr] or [-dr]

Positional arguments
--------------------

.. index:: resource

resource
''''''''

    Object that you want to analyse in VirusTotal (file, URL, IP address or domain). The file path, file hash (SHA1, SHA256, or MD5), URL, IP address, or domain name can be used.

-----

Optional arguments
------------------

.. index:: --help

-h, --help
''''''''''

    Show help message and exit.

-----

.. index:: --file-id

-fid, --file-id
'''''''''''''''

    Getting the identifier of the file for further analysis.
	
-----

.. index:: --file-scan-report

-fsr, --file-scan-report
''''''''''''''''''''''''

    Getting a report on the results of scanning a file.
	
-----

.. index:: --file-analyse-report
	
-far, --file-analyse-report
'''''''''''''''''''''''''''

    Getting a report on the results of file analysis (enabled by default).
	
.. rubric:: Example JSON response

::

    {    
      "type": "file",
      "id": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
     "links": {
        "self": "https://www.virustotal.com/api/v3/files/8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85"
      },
      "data": {
        "attributes": {
          "first_seen_itw_date": 1075654056,
          "first_submission_date": 1170892383,
          "last_analysis_date": 1502355193,
          "last_analysis_results": {
            "AVG": {
              "category": "undetected",
              "engine_name": "AVG",
              "engine_update": "20170810",
              "engine_version": "8.0.1489.320",
              "method": "blacklist",
              "result": null
            }
            ...
          },
          "last_analysis_stats": {
            "harmless": 0,
            "malicious": 0,
            "suspicious": 0,
            "timeout": 0,
            "type-unsupported": 8,
            "undetected": 59
          },
          "last_submission_date": 1502355193,
          "magic": "data",
          "md5": "76cdb2bad9582d23c1f6f4d868218d6c",
          "names": [
            "zipnew.dat",
            "327916-1502345099.zip",
            "ac3plug.zip",
            "IMG_6937.zip",
            "DOC952.zip",
            "20170801486960.zip"
          ],
          "nsrl_info": {
            "filenames": [
              "WINDOWS DIALUP.ZIP",
              "kemsetup.ZIP",
              "Data_Linux.zip",
              "2003.zip",
              "_6A271FB199E041FC82F4D282E68B01D6"
            ],
            "products": [
              "Master Hacker Internet Terrorism (Core Publishing Inc.)",
              "Read Rabbits Math Ages 6-9 (Smart Saver)",
              "Neverwinter Nights Gold (Atari)",
              "Limited Edition Print Workshop 2004 (ValuSoft)",
              "Crysis (Electronic Arts Inc.)"
            ]
          },
          "reputation": -889,
          "sha1": "b04f3ee8f5e43fa3b162981b50bb72fe1acabb33",
          "sha256": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
          "size": 22,
          "ssdeep": "3:pjt/l:Nt",
          "tags": [
            "software-collection",
            "nsrl",
            "attachment",
            "trusted",
            "via-tor"
          ],
          "times_submitted": 26471,
          "total_votes": {
            "harmless": 639,
            "malicious": 958
          },
          "trid": [
            {
              "file_type": "ZIP compressed archive (empty)",
              "probability": 100
            }
          ],
          "trusted_verdict": {
            "filename": "lprn_spotlightstory_015.zip",
            "link": "https://dl.google.com/dl/spotlight/test/lprn_spotlightstory/9/lprn_spotlightstory_015.zip",
            "organization": "Google",
            "verdict": "goodware"
          },
          "type_description": "unknown",
          }
        }
      }
    }
	
-----

.. index:: --hash-report
	
-hr, --hash-report
''''''''''''''''''

    Getting a report on the results of analyzing a file by its hash (SHA256, SHA1 or MD5).

-----

.. index:: --url-id

-uid, --url-id
''''''''''''''
    
	Getting the identifier of the URL for further analysis.
	
-----
	
.. index:: --url-scan-report
	
-usr, --url-scan-report
'''''''''''''''''''''''

    Getting a report on the results of scanning a URL.
	
-----
	
.. index:: --url-analyse-report

-uar, --url-analyse-report
''''''''''''''''''''''''''

    Getting a report on the results of URL analysis.
	
-----

.. index:: --ip-report

-ipr, --ip-report
'''''''''''''''''

    Getting a report on the results of IP address analysis.
	
.. rubric:: Example JSON response

::

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

-----
	
.. index:: --domain-report

-dr, --domain-report
''''''''''''''''''''

    Getting a report on the results of domain analysis.
	
.. rubric:: Example JSON response

::

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
