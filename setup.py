#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from glob import glob
from os.path import basename
from os.path import splitext
from setuptools import find_packages
from setuptools import setup


desc = ('license-expression is small utility library to parse, compare, '
        'simplify and normalize license expressions (such as SPDX license '
        'expressions) using boolean logic.')

setup(
    name='license-expression',
    version='0.8',
    license='apache-2.0',
    description=desc,
    long_description=desc,
    author='nexB Inc.',
    author_email='info@nexb.com',
    url='https://github.com/nexB/license-expression',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
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
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Utilities',
    ],
    keywords=[
        'license', 'spdx', 'license expression', 'open source', 'boolean',
        'parse expression', 'normalize expression', 'compare expression',
        'licence'
    ],
    install_requires=[
        'boolean.py',
    ]
)
