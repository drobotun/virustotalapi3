from setuptools import setup, find_packages
import vtapi3

with open('README.rst', 'r', encoding='utf-8') as readme_file:
    readme = readme_file.read()
with open('HISTORY.rst', 'r', encoding='utf-8') as history_file:
    history = history_file.read()

setup(
    name='vtapi3',
    version = vtapi3.__version__,
    description = 'VirusTotal API',
    long_description = readme + '\n\n' + history,
    author = vtapi3.__author__,
    author_email = vtapi3.__author_email__,
    url='https://github.com/drobotun/virustotalapi3/',
    zip_safe=False,
    license=vtapi3.__license__,
    keywords='virustotal api',
    project_urls={
        'Documentation': 'https://virustotalapi3.readthedocs.io/',
        'Source': 'https://github.com/drobotun/virustotalapi3/'
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.7',
    ],
    test_suite="tests",
    packages=find_packages(exclude=["tests*"]),
    install_requires=['requests >= 2.22.0']
    )
