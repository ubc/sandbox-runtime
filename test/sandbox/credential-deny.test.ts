import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { DANGEROUS_CREDENTIAL_PATHS } from '../../src/sandbox/sandbox-utils.js'
import { isLinux, isSupportedPlatform } from '../helpers/platform.js'

/**
 * Tests for the `credentials` config section (mode: deny / allow).
 *
 * File entries with mode: deny are unioned into the read-deny set; env var
 * entries with mode: deny are unset inside the sandbox. The
 * DANGEROUS_CREDENTIAL_PATHS defaults apply only when a `credentials` block
 * is present, and an explicit mode: allow entry exempts the matching default.
 */

function baseConfig(
  overrides: Partial<SandboxRuntimeConfig> = {},
): SandboxRuntimeConfig {
  return {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
    ...overrides,
  }
}

describe.if(isSupportedPlatform)(
  'credential read-deny normalization (getFsReadConfig)',
  () => {
    afterAll(async () => {
      await SandboxManager.reset()
    })

    it('does not apply DANGEROUS_CREDENTIAL_PATHS without a credentials block', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          filesystem: {
            denyRead: ['/some/secret'],
            allowWrite: ['/tmp'],
            denyWrite: [],
          },
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      expect(readConfig.denyOnly).toEqual(['/some/secret'])

      await SandboxManager.reset()
    })

    it('applies DANGEROUS_CREDENTIAL_PATHS when a credentials block is present', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          credentials: {},
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      for (const defaultPath of DANGEROUS_CREDENTIAL_PATHS) {
        expect(readConfig.denyOnly).toContain(defaultPath)
      }

      await SandboxManager.reset()
    })

    it('unions credential deny entries with caller-supplied denyRead', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          filesystem: {
            denyRead: ['/some/secret'],
            allowWrite: ['/tmp'],
            denyWrite: [],
          },
          credentials: {
            files: [{ path: '~/.config/gcloud', mode: 'deny' }],
          },
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      // Caller denyRead survives, credential deny entry and defaults are added
      expect(readConfig.denyOnly).toContain('/some/secret')
      expect(readConfig.denyOnly).toContain('~/.config/gcloud')
      expect(readConfig.denyOnly).toContain('~/.netrc')

      await SandboxManager.reset()
    })

    it('exempts a default path with an explicit mode: allow entry', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          credentials: {
            // Spelled as an absolute path to verify the exemption matches
            // after path normalization, not by string equality with '~/.aws'.
            files: [{ path: join(homedir(), '.aws'), mode: 'allow' }],
          },
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      expect(readConfig.denyOnly).not.toContain('~/.aws')
      // The other defaults are still applied
      expect(readConfig.denyOnly).toContain('~/.ssh')
      expect(readConfig.denyOnly).toContain('~/.netrc')

      await SandboxManager.reset()
    })

    it('mode: allow does not override caller-supplied denyRead for the same path', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          filesystem: {
            denyRead: ['~/.aws'],
            allowWrite: ['/tmp'],
            denyWrite: [],
          },
          credentials: {
            files: [{ path: '~/.aws', mode: 'allow' }],
          },
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      expect(readConfig.denyOnly).toContain('~/.aws')

      await SandboxManager.reset()
    })

    it('feeds credential deny paths into the macOS profile as file-read denies', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          credentials: {
            files: [{ path: '~/.netrc', mode: 'deny' }],
          },
        }),
      )

      // Profile generation is pure string construction, so it can be
      // exercised on any platform even though sandbox-exec only runs on macOS.
      const wrapped = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: SandboxManager.getFsReadConfig(),
        writeConfig: undefined,
      })

      expect(wrapped).toContain('deny file-read*')
      expect(wrapped).toContain('.netrc')
      expect(wrapped).toContain('.config/gh')

      await SandboxManager.reset()
    })
  },
)

describe('macOS env -u preamble generation', () => {
  it('emits env -u flags before sandbox-exec for denied env vars', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      unsetEnvVars: ['GH_TOKEN', 'AWS_SECRET_ACCESS_KEY'],
    })

    expect(
      wrapped.startsWith('env -u GH_TOKEN -u AWS_SECRET_ACCESS_KEY '),
    ).toBe(true)
    // The -u flags must precede the VAR=VALUE assignments and sandbox-exec.
    // Match on the var name only — shellquote escapes '=' in the assignments.
    expect(wrapped.indexOf('-u GH_TOKEN')).toBeLessThan(
      wrapped.indexOf('SANDBOX_RUNTIME'),
    )
    expect(wrapped.indexOf('-u GH_TOKEN')).toBeLessThan(
      wrapped.indexOf('sandbox-exec'),
    )
  })

  it('still sandboxes when env unsets are the only restriction', () => {
    const command = 'echo hello'
    const wrapped = wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
      unsetEnvVars: ['GH_TOKEN'],
    })

    expect(wrapped).not.toBe(command)
    expect(wrapped).toContain('env -u GH_TOKEN')
  })

  it('emits no -u flags when no env vars are denied', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      unsetEnvVars: [],
    })

    expect(wrapped).not.toContain(' -u ')
  })
})

describe.if(isLinux)('credential deny on Linux (bwrap)', () => {
  const TEST_DIR = join(tmpdir(), 'credential-deny-test-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'fake-netrc')
  const SECRET_DIR = join(TEST_DIR, 'fake-aws')
  const SECRET_DIR_FILE = join(SECRET_DIR, 'credentials')
  const SECRET_CONTENT = 'machine github.com password hunter2'
  const DENIED_ENV_VAR = 'SRT_TEST_SECRET_TOKEN'
  const ALLOWED_ENV_VAR = 'SRT_TEST_VISIBLE_VALUE'

  // process.env mutations don't reach children spawned by bun without an
  // explicit env option, so the credential vars are passed per-spawn instead.
  const childEnv = {
    ...process.env,
    [DENIED_ENV_VAR]: 'super-secret-value',
    [ALLOWED_ENV_VAR]: 'visible-value',
  }

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: childEnv,
    })
  }

  beforeAll(async () => {
    mkdirSync(SECRET_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, SECRET_CONTENT)
    writeFileSync(SECRET_DIR_FILE, SECRET_CONTENT)

    await SandboxManager.reset()
    await SandboxManager.initialize(
      baseConfig({
        filesystem: {
          denyRead: [],
          allowWrite: [TEST_DIR, '/tmp'],
          denyWrite: [],
        },
        credentials: {
          files: [
            { path: SECRET_FILE, mode: 'deny' },
            { path: SECRET_DIR, mode: 'deny' },
          ],
          envVars: [{ name: DENIED_ENV_VAR, mode: 'deny' }],
        },
      }),
    )
  })

  afterAll(async () => {
    await SandboxManager.reset()
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  describe('bwrap argv generation', () => {
    it('emits a /dev/null mask for a denied credential file', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')

      expect(wrapped).toContain(`--ro-bind /dev/null ${SECRET_FILE}`)
      expect(wrapped).toContain(`--tmpfs ${SECRET_DIR}`)
    })

    it('emits --unsetenv for a denied credential env var', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')

      expect(wrapped).toContain(`--unsetenv ${DENIED_ENV_VAR}`)
      expect(wrapped).not.toContain(`--unsetenv ${ALLOWED_ENV_VAR}`)
    })

    it('honors a credentials block passed via customConfig', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true', undefined, {
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        credentials: {
          files: [{ path: SECRET_FILE, mode: 'deny' }],
          envVars: [{ name: 'CUSTOM_ONLY_TOKEN', mode: 'deny' }],
        },
      })

      expect(wrapped).toContain(`--ro-bind /dev/null ${SECRET_FILE}`)
      expect(wrapped).toContain('--unsetenv CUSTOM_ONLY_TOKEN')
    })
  })

  describe('integration', () => {
    it('a denied credential file reads back empty inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
      const result = runInSandbox(wrapped)

      // The /dev/null mask makes the file readable but empty
      expect(result.stdout).not.toContain('hunter2')
      expect(result.stdout.trim()).toBe('')
    })

    it('a file inside a denied credential directory is unreadable inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `cat ${SECRET_DIR_FILE}`,
      )
      const result = runInSandbox(wrapped)

      // The tmpfs mount hides the directory contents entirely
      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain('hunter2')
    })

    it('a denied env var is absent inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printenv ${DENIED_ENV_VAR}`,
      )
      const result = runInSandbox(wrapped)

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain('super-secret-value')
    })

    it('a non-denied env var is still inherited inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printenv ${ALLOWED_ENV_VAR}`,
      )
      const result = runInSandbox(wrapped)

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('visible-value')
    })
  })
})
