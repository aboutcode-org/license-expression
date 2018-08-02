==================
license-expression
==================

license-expression is a small utility library to parse, compare, simplify and normalize
license expressions (e.g. SPDX license expressions) using boolean logic such as:
`GPL-2.0-or-later WITH Classpath-Exception AND MIT`.

See also for details:
https://spdx.org/sites/cpstandard/files/pages/files/spdxversion2.1.pdf#page=95&zoom=auto

license: apache-2.0

Python: 2.7 and 3.5+

Build and tests status
======================

.. |travis-master-icon| image:: https://api.travis-ci.org/nexB/license-expression.png?branch=master
                        :target: https://travis-ci.org/nexB/license-expression
                        :alt: MacOSX Master branch tests status
                        :align: middle

.. |appveyor-master-icon| image:: https://ci.appveyor.com/api/projects/status/github/nexB/license-expression?svg=true
                          :target: https://ci.appveyor.com/project/nexB/license-expression
                          :alt: Windows Master branch tests status
                          :align: middle

+-------+-----------------------+----------------------+------------------------+
|Branch |**Linux (Travis)**     |**MacOSX (Travis)**   |**Windows (AppVeyor)**  |
+=======+=======================+======================+========================+
|       |                       |                      |                        |
|Master | |travis-master-icon|  | |travis-master-icon| | |appveyor-master-icon| |
|       |                       |                      |                        |
+-------+-----------------------+----------------------+------------------------+

Source code and download
========================

* https://github.com/nexB/license-expression.git
* https://pypi.python.org/pypi/license-expression

Support
=======

Submit bugs and questions at:

* https://github.com/nexB/license-expression/issues

Description
===========

This module defines a mini language to parse, validate, simplify, normalize and
compare license expressions using a boolean logic engine.

This supports SPDX license expressions and also accepts other license naming
conventions and license identifiers aliases to resolve and normalize licenses.

Using boolean logic, license expressions can be tested for equality, containment,
equivalence and can be normalized or simplified.

The main entry point is the Licensing object.

Usage examples
==============

For example:

.. code-block:: python

    >>> from license_expression import Licensing, LicenseSymbol
    >>> licensing = Licensing()
    >>> expression = ' GPL-2.0 or LGPL-2.1 and mit '
    >>> parsed = licensing.parse(expression)
    >>> expected = 'GPL-2.0 OR (LGPL-2.1 AND mit)'
    >>> assert expected == parsed.render('{symbol.key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0'),
    ...   LicenseSymbol('LGPL-2.1'),
    ...   LicenseSymbol('mit')
    ... ]
    >>> assert expected == licensing.license_symbols(expression)
    >>> assert expected == licensing.license_symbols(parsed)

    >>> symbols = ['GPL-2.0+', 'Classpath', 'BSD']
    >>> licensing = Licensing(symbols)
    >>> expression = 'GPL-2.0+ with Classpath or (bsd)'
    >>> parsed = licensing.parse(expression)
    >>> expected = 'GPL-2.0+ WITH Classpath OR BSD'
    >>> assert expected == parsed.render('{symbol.key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0+'),
    ...   LicenseSymbol('Classpath'),
    ...   LicenseSymbol('BSD')
    ... ]
    >>> assert expected == licensing.license_symbols(parsed)
    >>> assert expected == licensing.license_symbols(expression)

And expression can be simplified:

.. code-block:: python

    >>> expression2 = ' GPL-2.0 or (mit and LGPL-2.1) or bsd Or GPL-2.0  or (mit and LGPL-2.1)'
    >>> parsed2 = licensing.parse(expression2)
    >>> assert str(parsed2.simplify()) == 'BSD OR GPL-2.0 OR (LGPL-2.1 AND mit)'

Two expressions can be compared for equivalence and containment:

.. code-block:: python

    >>> expr1 = licensing.parse(' GPL-2.0 or (LGPL-2.1 and mit) ')
    >>> expr2 = licensing.parse(' (mit and LGPL-2.1)  or GPL-2.0 ')
    >>> licensing.is_equivalent(expr1, expr2)
    True
    >>> licensing.is_equivalent(' GPL-2.0 or (LGPL-2.1 and mit) ',
    ...                         ' (mit and LGPL-2.1)  or GPL-2.0 ')
    True
    >>> expr1.simplify() == expr2.simplify()
    True
    >>> expr3 = licensing.parse(' GPL-2.0 or mit or LGPL-2.1')
    >>> licensing.is_equivalent(expr2, expr3)
    False
    >>> expr4 = licensing.parse('mit and LGPL-2.1')
    >>> expr4.simplify() in expr2.simplify()
    True
    >>> licensing.contains(expr2, expr4)
    True

Development
===========

* Checkout a clone from https://github.com/nexB/license-expression.git
* Then run ``./configure`` (or ``configure.bat``) and then ``source bin/activate``. This will
  install all vendored dependencies in a local virtualenv, including development deps.
* To run the tests, run ``py.test -vvs``
