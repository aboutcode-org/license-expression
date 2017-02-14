===============================
license-expression
===============================

license-expression is small utility library to parse, compare, simplify and normalize
license expressions (e.g. SPDX license expressions) using boolean logic such as:
`GPL-2.0 or later WITH Classpath Exception AND MIT`.


See also for details:
https://spdx.org/sites/cpstandard/files/pages/files/spdxversion2.1.pdf#page=95&zoom=auto

license: apache-2.0

Python: 2.7 and 3.4+


Build and tests status
======================

+-------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------+
|Branch |                         **Linux (Travis)**                                    |                         **MacOSX (Travis)**                                   |                         **Windows (AppVeyor)**                                                              |
+=======+===============================================================================+===============================================================================+=============================================================================================================+
|       |.. image:: https://api.travis-ci.org/nexB/license-expression.png?branch=master |.. image:: https://api.travis-ci.org/nexB/license-expression.png?branch=master |.. image:: https://ci.appveyor.com/api/projects/status/github/nexB/license-expression?svg=true               |
|Master |   :target: https://travis-ci.org/nexB/license-expression                      |   :target: https://travis-ci.org/nexB/license-expression                      |   :target: https://ci.appveyor.com/project/nexB/license-expression                                          |
|       |   :alt: Linux Master branch tests status                                      |   :alt: MacOSX Master branch tests status                                     |   :alt: Windows Master branch tests status                                                                  |
+-------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------+


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

For example::

    >>> from license_expression import Licensing, LicenseSymbol
    >>> l = Licensing()
    >>> expr = l.parse(" GPL-2.0 or LGPL 2.1 and mit ")
    >>> expected = 'GPL-2.0 OR (LGPL 2.1 AND mit)'
    >>> assert expected == expr.render('{original_key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0', known=False),
    ...   LicenseSymbol('LGPL 2.1', known=False),
    ...   LicenseSymbol('mit', known=False)
    ... ]
    >>> assert expected == l.license_symbols(expr)

    >>> symbols = ['GPL-2.0+', 'Classpath', 'BSD']
    >>> l = Licensing(symbols)
    >>> expr = l.parse("GPL-2.0+ with Classpath or (bsd)")
    >>> expected = 'gpl-2.0+ WITH classpath OR bsd'
    >>> assert expected == expr.render('{key}')

    >>> expected = [
    ...   LicenseSymbol('GPL-2.0+', known=True),
    ...   LicenseSymbol('Classpath', is_exception=True, known=True),
    ...   LicenseSymbol('BSD', known=True)
    ... ]
    >>> assert expected == l.license_symbols(expr)


And expression can be simplified::

    >>> expr2 = l.parse(' GPL-2.0 or (mit and LGPL 2.1) or bsd Or GPL-2.0  or (mit and LGPL 2.1)')
    >>> assert str(expr2.simplify()) == 'bsd OR gpl-2.0 OR (lgpl 2.1 AND mit)'
    

Two expressions can be compared for equivalence and containment::

    >>> expr1 = l.parse(' GPL-2.0 or (LGPL 2.1 and mit) ')
    >>> expr2 = l.parse(' (mit and LGPL 2.1)  or GPL-2.0 ')
    >>> l.is_equivalent(expr1, expr2)
    True
    >>> expr1.simplify() == expr2.simplify()
    True
    >>> expr3 = l.parse(' GPL-2.0 or mit or LGPL 2.1')
    >>> l.is_equivalent(expr2, expr3)
    False
    >>> expr4 = l.parse('mit and LGPL 2.1')
    >>> expr4.simplify() in expr2.simplify()
    True
    >>> l.contains(expr2, expr4)
    True

    
Development
===========

* Checkout a clone from https://github.com/nexB/license-expression.git
* Then run `./configure` (or `configure.bat`) and then `source bin/activate`. This will
  install all vendored dependencies in a local virtualenv, including development deps.
* To run the tests, run `py.test -vvs`
