# -*- coding: utf-8 -*-
from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='parse-nmap',
    version='0.2.0',
    author='Christoph Bless',
    author_email='bitbucket@cbless.de',
    url='https://bitbucket.org/cbless/parse-nmap',
    license=' GPLv3',
    description=('Parse-nmap is a tool which parses nmap scan results (only XML) from a file. By using parse-nmap it is possible to filter the results by platform or ip or to generate target lists.'),
    long_description=long_description,
    packages=['parsenmap'],
    install_requires=[
        'python-libnmap'
    ],
    entry_points = {
        "console_scripts": [
            "parse-nmap = parsenmap.main:parse_nmap",
        ]
    }
)
