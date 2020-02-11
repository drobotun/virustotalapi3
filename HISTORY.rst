Release History
===============

1.2.0 (11.02.2020)
"""""""""""""""""

- Сhanged the structure of files and directories of the module.
- Added the ``get_download_url()`` and ``get_download()`` functions (``VirusTotalAPIFiles`` class).
- The ``main()`` function was refactored in ``__main__.py``.
- Сhanged the structure and composition (added tests for checking functions when the "Connection Error" error occurs) of tests (the value of code coverage by tests is 93%).

1.1.3 (7.02.2020)
"""""""""""""""""

- Fixed several bugs in ``__main__.ru``

1.1.2 (5.02.2020)
"""""""""""""""""

- Fixed ``__init__.py`` (to ensure correct implementation of import).
- Added ``__main__.py`` (to improve the command line experience).

1.1.1 (4.02.2020)
"""""""""""""""""

- Fixed several errors in the ``get_file_id_to_analyse()`` and ``get_url_id_to_analyse functions()``.
- Added VirusTotalAPIError(IO Error) exception in the ``get_file_id()`` and ``upload()`` functions of the VirusTotalAPIFiles class.

1.1.0 (3.02.2020)
"""""""""""""""""

- Added the ability to performance the package from the command line.

1.0.4 (1.02.2020)
"""""""""""""""""

- Fixing README.rst for better PYPI presentation.

1.0.3 (26.01.2020)
""""""""""""""""""

- Added a new attribute ``_last_result`` to the VirustotalAPI base class.
- Added a new method ``get_last_result`` to the VirustotalAPI base class.

1.0.2 (12.01.2020)
""""""""""""""""""

- Fixed errors in source comments.
- Fixing README.rst for better PYPI presentation.
- Fixing setup.py for better PYPI presentation.
- README.rst translated into English.
- Added two tests (``test_get_version_avi()`` and ``test_get_lost_http_error ()``) in test_vt_3.py

1.0.1 (08.01.2020)
""""""""""""""""""

- First release of vtapi3