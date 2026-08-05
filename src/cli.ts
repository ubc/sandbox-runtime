#!/usr/bin/env node
import { quote } from './utils/shell-quote.js'
import { Command } from 'commander'
import { SandboxManager } from './index.js'
import type { SandboxRuntimeConfig } from './sandbox/sandbox-config.js'
import { spawn } from 'child_process'
import { logForDebugging } from './utils/debug.js'
import { loadConfig, loadConfigFromString } from './utils/config-loader.js'
import * as readline from 'readline'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { fileURLToPath } from 'url'

/**
 * Get default config path
 */
function getDefaultConfigPath(): string {
  return path.join(os.homedir(), '.srt-settings.json')
}

/**
 * Read the package version from package.json at runtime.
 *
 * `process.env.npm_package_version` is only set when run via an npm script,
 * not for a globally-installed `srt` binary — so relying on it makes
 * `srt --version` indistinguishable between builds. Reading package.json
 * directly (it sits one level above dist/cli.js, and above src/cli.ts when
 * run from source) makes the version a reliable build identifier. The LTIC
 * fork carries a distinctive `-ltic.N` suffix so users can confirm they are
 * on the patched fork (allowAllDomains + denyReadAlways) rather than upstream.
 */
function getPackageVersion(): string {
  try {
    const pkgPath = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      '..',
      'package.json',
    )
    return JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version || '0.0.0'
  } catch {
    return process.env.npm_package_version || '0.0.0'
  }
}

/**
 * LTIC fork: stream sandbox violations to a file the sandboxed child can
 * read.
 *
 * The violation store lives in this host-side process; the sandboxed agent
 * only ever sees a generic 403 / EPERM when it trips a rule. Appending each
 * violation line to a host-written file (advertised to the child via
 * SRT_VIOLATIONS_FILE) lets tooling inside the sandbox — e.g. a Claude Code
 * PostToolUse hook — surface denial reasons to the agent.
 *
 * The file lives under ~/.local/state/srt, which the sandbox config should
 * grant read but NOT write: violation lines flow into an agent's context,
 * so sandboxed code must not be able to forge them.
 */
function startViolationsFile(): string | undefined {
  try {
    const dir = path.join(os.homedir(), '.local', 'state', 'srt')
    fs.mkdirSync(dir, { recursive: true })

    // Prune logs from long-dead sessions so the directory doesn't grow
    // without bound.
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
    for (const name of fs.readdirSync(dir)) {
      if (!/^violations-\d+\.log$/.test(name)) continue
      const p = path.join(dir, name)
      try {
        if (fs.statSync(p).mtimeMs < weekAgo) fs.unlinkSync(p)
      } catch {
        // Another session may have pruned it first.
      }
    }

    const file = path.join(dir, `violations-${process.pid}.log`)
    fs.writeFileSync(file, '')

    const store = SandboxManager.getSandboxViolationStore()
    // The store notifies synchronously on every addViolation, so each
    // callback carries exactly the events past `seen`; the initial
    // subscribe() replay is skipped because `seen` already covers it.
    let seen = store.getTotalCount()
    store.subscribe(() => {
      const total = store.getTotalCount()
      if (total <= seen) return
      const fresh = store.getViolations().slice(-(total - seen))
      seen = total
      const text = fresh
        .map(v => `${v.timestamp.toISOString()} ${v.line}`)
        .join('\n')
      fs.appendFile(file, text + '\n', () => {})
    })
    return file
  } catch (error) {
    logForDebugging(
      `Failed to set up violations file: ${error instanceof Error ? error.message : String(error)}`,
    )
    return undefined
  }
}

/**
 * Create a minimal default config if no config file exists
 */
function getDefaultConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: [],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

async function main(): Promise<void> {
  const program = new Command()

  program
    .name('srt')
    .description(
      'Run commands in a sandbox with network and filesystem restrictions',
    )
    .version(getPackageVersion())

  // ── Windows install/uninstall ─────────────────────────────────
  // Self-elevating one-shot install (one UAC prompt). Also
  // available programmatically as installWindowsSandbox().
  program
    .command('windows-install')
    .description(
      'Windows: provision the `srt-sandbox` user account + install WFP ' +
        'filters (one UAC prompt). No logout needed.',
    )
    .option('--sublayer-guid <guid>', 'WFP sublayer GUID')
    .option(
      '--proxy-port-range <lo-hi>',
      'loopback PERMIT port range (e.g. 60080-60089)',
    )
    .option(
      '--sandbox-user <name>',
      'name for the sandbox user account (default: srt-sandbox)',
    )
    .option('--force', 'replace an existing install with different config')
    .action(async (o: Record<string, string | boolean | undefined>) => {
      const { installWindowsSandbox, resolveSrtWin, VENDORED_SRT_WIN_EXE } =
        await import('./sandbox/windows-sandbox-utils.js')
      const range =
        typeof o.proxyPortRange === 'string'
          ? (o.proxyPortRange.split('-').map(Number) as [number, number])
          : undefined
      try {
        const r = installWindowsSandbox({
          sublayerGuid: o.sublayerGuid as string | undefined,
          proxyPortRange: range,
          sandboxUser: o.sandboxUser as string | undefined,
          force: Boolean(o.force),
          // Our own CLI opts into the packaged exe explicitly —
          // there is no ambient vendor fallback.
          srtWin: resolveSrtWin({ path: VENDORED_SRT_WIN_EXE }),
        })
        if (r.cancelled) {
          console.error('Install cancelled at the UAC prompt. Nothing changed.')
          process.exit(2)
        }
        console.log(
          `Installed.\n` +
            `  sandbox user: ${r.user.provisioned ? 'provisioned' : 'MISSING'}` +
            (r.user.sid ? ` (${r.user.sid})` : '') +
            `\n` +
            `  WFP:   ${r.wfp.state}, ${r.wfp.filters} filters` +
            (r.wfp.portRange
              ? `, port range ${r.wfp.portRange[0]}-${r.wfp.portRange[1]}`
              : '') +
            `\n\n` +
            `No logout needed — the WFP filter keys on the dedicated ` +
            `\`srt-sandbox\` user's SID, so your network is unaffected.`,
        )
      } catch (e) {
        console.error(`Error: ${(e as Error).message}`)
        process.exit(1)
      }
    })

  program
    .command('windows-uninstall')
    .description(
      'Windows: remove WFP filters + the `srt-sandbox` account (one UAC prompt).',
    )
    .option('--sublayer-guid <guid>', 'WFP sublayer GUID')
    .action(async (o: Record<string, string | undefined>) => {
      const { uninstallWindowsSandbox, resolveSrtWin, VENDORED_SRT_WIN_EXE } =
        await import('./sandbox/windows-sandbox-utils.js')
      try {
        const r = uninstallWindowsSandbox({
          sublayerGuid: o.sublayerGuid,
          srtWin: resolveSrtWin({ path: VENDORED_SRT_WIN_EXE }),
        })
        if (r.cancelled) {
          console.error('Uninstall cancelled at the UAC prompt.')
          process.exit(2)
        }
        console.log('WFP filters and `srt-sandbox` account removed.')
      } catch (e) {
        console.error(`Error: ${(e as Error).message}`)
        process.exit(1)
      }
    })

  // Default command - run command in sandbox
  program
    .argument('[command...]', 'command to run in the sandbox')
    .option('-d, --debug', 'enable debug logging')
    .option(
      '-s, --settings <path>',
      'path to config file (default: ~/.srt-settings.json)',
    )
    .option(
      '-c <command>',
      'run command string directly (like sh -c), no escaping applied',
    )
    .option(
      '--control-fd <fd>',
      'read config updates from file descriptor (JSON lines protocol)',
      parseInt,
    )
    .allowUnknownOption()
    .action(
      async (
        commandArgs: string[],
        options: {
          debug?: boolean
          settings?: string
          c?: string
          controlFd?: number
        },
      ) => {
        try {
          // Enable debug logging if requested. logForDebugging() reads
          // SRT_DEBUG (not DEBUG, to avoid clashing with the npm `debug`
          // package and other tools) — keep this in sync with utils/debug.ts.
          if (options.debug) {
            process.env.SRT_DEBUG = 'true'
          }

          // Load config from file
          const configPath = options.settings || getDefaultConfigPath()
          let runtimeConfig = loadConfig(configPath)

          if (!runtimeConfig) {
            // An explicitly requested settings file must load successfully —
            // silently falling back to the default config would run the
            // command without the restrictions the caller asked for.
            if (options.settings) {
              console.error(
                `Error: Could not load settings from ${configPath} (missing, unreadable, or invalid). ` +
                  'Refusing to run with the default config.',
              )
              process.exit(1)
            }
            logForDebugging(
              `No config found at ${configPath}, using default config`,
            )
            runtimeConfig = getDefaultConfig()
          }

          // Windows: srtWin.path is required (no ambient vendor
          // fallback). When the user's config doesn't set it, this
          // CLI opts into the packaged exe explicitly — that's our
          // code making the choice, not a library default.
          if (
            process.platform === 'win32' &&
            runtimeConfig.windows?.srtWin?.path === undefined
          ) {
            const { VENDORED_SRT_WIN_EXE } = await import(
              './sandbox/windows-sandbox-utils.js'
            )
            runtimeConfig = {
              ...runtimeConfig,
              windows: {
                ...runtimeConfig.windows,
                srtWin: { path: VENDORED_SRT_WIN_EXE },
              },
            }
          }

          // Initialize sandbox with config. LTIC fork: enable the log
          // monitor so filesystem (seatbelt/seccomp) denials reach the
          // violation store — the CLI otherwise only collects proxy denials.
          logForDebugging('Initializing sandbox...')
          await SandboxManager.initialize(runtimeConfig, undefined, true)

          // LTIC fork: expose violations to the sandboxed child (see
          // startViolationsFile). The child inherits process.env.
          const violationsFile = startViolationsFile()
          if (violationsFile) {
            process.env.SRT_VIOLATIONS_FILE = violationsFile
            logForDebugging(`Violations file: ${violationsFile}`)
          }

          // Set up control fd for dynamic config updates if specified
          let controlReader: readline.Interface | null = null
          if (options.controlFd !== undefined) {
            try {
              const controlStream = fs.createReadStream('', {
                fd: options.controlFd,
              })
              controlReader = readline.createInterface({
                input: controlStream,
                crlfDelay: Infinity,
              })

              controlReader.on('line', line => {
                const newConfig = loadConfigFromString(line)
                if (newConfig) {
                  logForDebugging(
                    `Config updated from control fd: ${JSON.stringify(newConfig)}`,
                  )
                  SandboxManager.updateConfig(newConfig)
                } else if (line.trim()) {
                  // Only log non-empty lines that failed to parse
                  logForDebugging(
                    `Invalid config on control fd (ignored): ${line}`,
                  )
                }
              })

              controlReader.on('error', err => {
                logForDebugging(`Control fd error: ${err.message}`)
              })

              logForDebugging(
                `Listening for config updates on fd ${options.controlFd}`,
              )
            } catch (err) {
              logForDebugging(
                `Failed to open control fd ${options.controlFd}: ${err instanceof Error ? err.message : String(err)}`,
              )
            }
          }

          // Cleanup control reader on exit
          process.on('exit', () => {
            controlReader?.close()
          })

          // Determine command string based on mode
          let command: string
          if (options.c) {
            // -c mode: use command string directly, no escaping
            command = options.c
            logForDebugging(`Command string mode (-c): ${command}`)
          } else if (commandArgs.length > 0) {
            // Default mode: argv-style invocation. The result is later
            // executed via `bash -c <command>`, so each arg must be
            // shell-quoted to survive that re-parse — a plain join(' ')
            // splits arguments containing whitespace (#157).
            command = quote(commandArgs)
            logForDebugging(`Original command: ${command}`)
          } else {
            console.error(
              'Error: No command specified. Use -c <command> or provide command arguments.',
            )
            process.exit(1)
          }

          logForDebugging(
            JSON.stringify(
              SandboxManager.getNetworkRestrictionConfig(),
              null,
              2,
            ),
          )

          // Wrap the command with sandbox restrictions. On Windows
          // the wrapper returns an argv array that MUST be spawned
          // with {shell:false} — that's the boundary keeping the
          // command bytes off the host shell. On other platforms
          // we keep the existing shell-string path.
          let child
          if (process.platform === 'win32') {
            // env carries the proxy vars the sandboxed child must inherit.
            const { argv, env } =
              await SandboxManager.wrapWithSandboxArgv(command)
            child = spawn(argv[0], argv.slice(1), {
              shell: false,
              stdio: 'inherit',
              env,
            })
          } else {
            const sandboxedCommand =
              await SandboxManager.wrapWithSandbox(command)
            child = spawn(sandboxedCommand, {
              shell: true,
              stdio: 'inherit',
            })
          }

          // Handle process exit
          child.on('exit', (code, signal) => {
            // Clean up bwrap mount point artifacts before exiting.
            // On Linux, bwrap creates empty files on the host when protecting
            // non-existent deny paths. This removes them.
            SandboxManager.cleanupAfterCommand()

            if (signal) {
              if (signal === 'SIGINT' || signal === 'SIGTERM') {
                process.exit(0)
              } else {
                console.error(`Process killed by signal: ${signal}`)
                process.exit(1)
              }
            }
            process.exit(code ?? 0)
          })

          child.on('error', error => {
            console.error(`Failed to execute command: ${error.message}`)
            process.exit(1)
          })

          // Handle cleanup on interrupt
          process.on('SIGINT', () => {
            child.kill('SIGINT')
          })

          process.on('SIGTERM', () => {
            child.kill('SIGTERM')
          })
        } catch (error) {
          console.error(
            `Error: ${error instanceof Error ? error.message : String(error)}`,
          )
          process.exit(1)
        }
      },
    )

  program.parse()
}

main().catch(error => {
  console.error('Fatal error:', error)
  process.exit(1)
})
