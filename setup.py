#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


from setuptools import find_packages
from setuptools import setup


desc = ('license-expression is small utility library to parse, compare and '
        'simplify and normalize license expressions.')

setup(
    name='license-expression',
    version='0.1',
    license='apache-2.0',
    description=desc,
    long_description=desc,
    author='nexB Inc.',
    author_email='info@nexb.',
    url='https://github.com/nexB/license-expression',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Utilities',
    ],
    keywords=[
        'license', 'spdx', 'license expression', 'open source',
    ],
    install_requires=[
        'boolean.py',
    ]
)
