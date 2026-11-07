import test from 'node:test'
import assert from 'node:assert/strict'

import { SDK_MINIMUM, sdkVersionAcceptable } from './sdk-version.mjs'

// Matches a refusal that quotes `version` literally.
function namesVersion(version) {
  return new RegExp(version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
}

test('the rule accepts the pinned 16.4.1', () => {
  assert.equal(sdkVersionAcceptable('16.4.1'), true)
})

test('the rule accepts a later 16.x release', () => {
  assert.equal(sdkVersionAcceptable('16.4.2'), true)
  assert.equal(sdkVersionAcceptable('16.5.0'), true)
})

test('the rule compares the minor version numerically', () => {
  assert.equal(sdkVersionAcceptable('16.10.0'), true)
})

test('the rule refuses the 15 line, naming the version', () => {
  assert.match(sdkVersionAcceptable('15.1.0'), /@stellar\/stellar-sdk 15\.1\.0 /)
})

test('the rule refuses the 17 line, naming the version', () => {
  assert.match(sdkVersionAcceptable('17.4.0'), /@stellar\/stellar-sdk 17\.4\.0 /)
})

test('the rule refuses 17 releases that pass the minor and patch bounds', () => {
  for (const version of ['17.4.1', '17.5.0']) {
    assert.match(
      sdkVersionAcceptable(version),
      new RegExp(`@stellar/stellar-sdk ${version.replaceAll('.', '\\.')} is outside the supported range`),
    )
  }
})

test('the rule refuses prerelease and build suffixes, naming the version', () => {
  for (const version of ['16.4.1-rc.1', '16.5.0-beta.1', '16.4.1+build.1']) {
    const verdict = sdkVersionAcceptable(version)
    assert.match(verdict, /not a semver version/)
    assert.match(verdict, namesVersion(version))
  }
})

test('the rule refuses components with a leading zero, naming the version', () => {
  for (const version of ['016.4.1', '16.04.1', '16.4.01']) {
    const verdict = sdkVersionAcceptable(version)
    assert.match(verdict, /not a semver version/)
    assert.match(verdict, namesVersion(version))
  }
})

test('the rule refuses 16.4.0, which predates the minimum', () => {
  assert.match(sdkVersionAcceptable('16.4.0'), /16\.4\.0 /)
})

test('the refusal names the minimum', () => {
  assert.match(sdkVersionAcceptable('17.4.0'), new RegExp(SDK_MINIMUM.replaceAll('.', '\\.')))
})

test('the rule refuses a value that is not a version', () => {
  assert.match(sdkVersionAcceptable('next'), /not a semver version/)
  assert.match(sdkVersionAcceptable(''), /not a semver version/)
})
