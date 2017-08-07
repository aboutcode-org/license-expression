let assert = require('assert')

let license_expression = require('../src/license_expression.js/__javascript__/__init__.js')

// Transcrypt uses '__init__.py' to derive the name of the top-level object
// If you want it to be called 'license_expression', rename '__init__.py' file
license_expression = license_expression.__init__

describe('Licensing', function() {
    describe('parse', function() {
        it('should parse a single license', function() {
            let licensing = license_expression.Licensing()

            assert.ok('MIT', licensing.parse('MIT').toString())
        })
    })
})
