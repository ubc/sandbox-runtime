import { describe, test, expect } from 'bun:test'
import { collectUnrecognizedConfigKeys } from '../src/utils/config-loader.js'

// LTIC fork: the settings loader warns on keys the schema does not
// recognize instead of letting zod strip them silently. These tests pin
// down both directions: every key the fork's configs rely on (including
// the fork-only keys) is recognized, and unknown/mistyped keys are named.
describe('collectUnrecognizedConfigKeys', () => {
  const base = {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }

  test('recognizes every key used by the ccx configs, including fork keys', () => {
    const config = {
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: ['gist.github.com', '*:25'],
        // Fork key (upstream PR #283)
        allowAllDomains: true,
        deniedDomainReasons: {
          'gist.github.com': 'blocked by sandbox policy',
        },
        allowUnixSockets: ['/var/run/docker.sock'],
        allowLocalBinding: true,
      },
      filesystem: {
        denyRead: ['/Users'],
        allowRead: ['~/src'],
        // Fork key (upstream PR #284)
        denyReadAlways: ['/**/.env*', '/**/credentials'],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
      ignoreViolations: {
        '*': ['sysctl-read kern.'],
      },
      enableWeakerNetworkIsolation: true,
    }

    expect(collectUnrecognizedConfigKeys(config)).toEqual([])
  })

  test('flags a mistyped fork key in network', () => {
    const config = {
      ...base,
      network: { ...base.network, allowAllDomainz: true },
    }

    expect(collectUnrecognizedConfigKeys(config)).toEqual([
      'network.allowAllDomainz',
    ])
  })

  test('flags a mistyped fork key in filesystem', () => {
    const config = {
      ...base,
      filesystem: { ...base.filesystem, denyReadAlway: ['/**/.env*'] },
    }

    expect(collectUnrecognizedConfigKeys(config)).toEqual([
      'filesystem.denyReadAlway',
    ])
  })

  test('flags unknown top-level keys', () => {
    const config = { ...base, allowEverything: true }

    expect(collectUnrecognizedConfigKeys(config)).toEqual(['allowEverything'])
  })

  test('flags nested unknown keys inside tlsTerminate', () => {
    const config = {
      ...base,
      network: { ...base.network, tlsTerminate: { caCert: '/etc/ca.crt' } },
    }

    expect(collectUnrecognizedConfigKeys(config)).toEqual([
      'network.tlsTerminate.caCert',
    ])
  })

  test('does not flag record keys (ignoreViolations command patterns)', () => {
    const config = {
      ...base,
      ignoreViolations: { 'git push': ['/usr/bin/nc'] },
    }

    expect(collectUnrecognizedConfigKeys(config)).toEqual([])
  })

  test('reports multiple unknown keys with full paths', () => {
    const config = {
      ...base,
      network: { ...base.network, allowedDomainz: [] },
      filesystem: { ...base.filesystem, denyReed: [] },
    }

    expect(collectUnrecognizedConfigKeys(config).sort()).toEqual([
      'filesystem.denyReed',
      'network.allowedDomainz',
    ])
  })
})
