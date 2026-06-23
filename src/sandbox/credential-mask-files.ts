/**
 * Credential file masking (Linux).
 *
 * For a `credentials.files` entry with `mode: "mask"`, srt reads the real
 * file content on the host, registers one or more sentinels in the
 * {@link SentinelRegistry}, and writes a fake file (sentinel-substituted)
 * to a manager-owned temp directory. The Linux sandbox then `--ro-bind`s
 * the fake over the real path, so the sandboxed process reads the
 * sentinel(s). The proxy substitution from env-var masking already scans
 * every header for any registered sentinel, so a tool that does
 * `Authorization: Bearer $(cat <maskedFile>)` reaches the upstream with
 * the real bytes — no proxy changes required.
 *
 * Without `extract`, masking is **whole-file**: one sentinel replaces the
 * entire content. With `extract`, masking is **structured**: a regex picks
 * out the credential value(s) and only those spans are replaced, so a tool
 * that parses the file (JSON/YAML/.netrc) still sees valid syntax. See
 * {@link extractAndSubstitute} and {@link CredentialFileConfigSchema}.
 *
 * On macOS, SBPL cannot redirect reads, so masked files degrade to
 * `mode: "deny"` (see macos-sandbox-utils.ts).
 */

import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { logForDebugging } from '../utils/debug.js'
import { normalizePathForSandbox } from './sandbox-utils.js'
import type { CredentialFileConfig } from './sandbox-config.js'
import type { SentinelRegistry } from './credential-sentinel.js'

/**
 * Sentinel-registry key prefix for masked files. Keeps file keys disjoint
 * from env-var names so a credential file at path `GH_TOKEN` cannot collide
 * with the env var `GH_TOKEN`.
 */
const FILE_KEY_PREFIX = 'file:'

/**
 * Placeholder marker for the i-th distinct extracted credential. NUL bytes
 * are illegal in every text format we expect to mask (.netrc, YAML, JSON,
 * INI) and never occur in credential values, so a marker can never collide
 * with real content nor with another capture that happens to contain a
 * marker-like substring.
 */
export function extractPlaceholder(i: number): string {
  return `\0SRT_EXTRACT_${i}\0`
}

/**
 * Result of {@link extractAndSubstitute}: the file content with each
 * distinct captured credential replaced by `extractPlaceholder(i)`, plus
 * the captures themselves in placeholder-index order.
 */
export interface ExtractResult {
  fakeContent: string
  captures: string[]
}

/**
 * Apply `pattern` globally to `content`, collect the distinct capture-group-1
 * values in first-seen order, and return `content` with each occurrence of a
 * captured value replaced by its index placeholder.
 *
 * Returns `null` when the pattern matches nothing — the caller treats that
 * as fail-closed (degrade to `mode: "deny"`), because a non-matching
 * pattern is almost certainly a config mistake and binding the unmodified
 * real file would expose the credential it was meant to mask.
 *
 * Throws when a match has no group-1 capture. The schema already rejects
 * patterns with zero groups, so this only fires when group 1 is optional
 * and absent for some match (e.g. `"token: (\\S+)?"`); accepting that
 * would silently mask nothing for that occurrence.
 *
 * Pure: no registry, no filesystem, deterministic placeholders — testable
 * in isolation.
 */
export function extractAndSubstitute(
  content: string,
  pattern: string,
): ExtractResult | null {
  // The schema validates `pattern` compiles; recompiling here with `g` is
  // what makes matchAll iterate every occurrence.
  const re = new RegExp(pattern, 'g')
  const indexByCapture = new Map<string, number>()
  for (const m of content.matchAll(re)) {
    const cap = m[1]
    if (cap === undefined) {
      throw new Error(
        `extract pattern /${pattern}/ matched at offset ${m.index} but ` +
          `capture group 1 is undefined — group 1 must capture the ` +
          `credential value on every match.`,
      )
    }
    // Empty captures are skipped: replacing the empty string is a no-op
    // semantically and split('').join(marker) would interleave a marker
    // between every character.
    if (cap.length === 0) continue
    if (!indexByCapture.has(cap)) {
      indexByCapture.set(cap, indexByCapture.size)
    }
  }
  if (indexByCapture.size === 0) return null

  // Replace longest captures first so a capture that is a substring of
  // another (rare for tokens, but cheap to guard) cannot corrupt the longer
  // one's bytes mid-replacement. Placeholders contain NUL, so a later pass
  // can never re-match inside an already-substituted span.
  const byLengthDesc = [...indexByCapture.entries()].sort(
    (a, b) => b[0].length - a[0].length,
  )
  let fakeContent = content
  for (const [cap, i] of byLengthDesc) {
    fakeContent = fakeContent.split(cap).join(extractPlaceholder(i))
  }
  const captures = [...indexByCapture.keys()]
  return { fakeContent, captures }
}

/** One masked file's bind mapping for the platform builder. */
export interface MaskedFileBind {
  /** Resolved (tilde-expanded, realpath'd) host path of the real file. */
  realPath: string
  /** Path to the fake file containing the sentinel. */
  fakePath: string
}

/**
 * Manager-owned temp dir holding the fake files.
 *
 * INVARIANT: this directory must live OUTSIDE every sandbox write path. The
 * sandbox is `--ro-bind / /` with writable binds layered on top
 * (getDefaultWritePaths() + the caller's allowWrite). os.tmpdir() is fine —
 * the default writable temp is `/tmp/claude`, not `/tmp` itself, and the
 * caller would have to explicitly allowWrite os.tmpdir() to break this. If
 * the sandbox could write the fake file, it could replace the sentinel and
 * the bind would no longer guarantee the real content stays hidden (the
 * bind itself stays read-only, but the source file is what's exposed).
 */
export class MaskedFileStore {
  private dir: string | undefined
  private readonly byKey = new Map<string, string>()

  /**
   * Write `sentinel` to a fake file for `key` and return its path.
   * Idempotent on `key`: a repeat call rewrites the same fake (so a
   * changed sentinel after re-register propagates) instead of leaking a
   * new file per wrapWithSandbox() call.
   */
  write(key: string, sentinel: string): string {
    if (this.dir === undefined) {
      this.dir = fs.mkdtempSync(join(tmpdir(), 'srt-credmask-'))
    }
    let fakePath = this.byKey.get(key)
    if (fakePath === undefined) {
      fakePath = join(this.dir, `${this.byKey.size}.fake`)
      this.byKey.set(key, fakePath)
    }
    // 0600: owner rw so the idempotent rewrite above succeeds; the bind
    // into the sandbox is --ro-bind so the sandboxed process sees it
    // read-only regardless of the host mode. No group/other.
    fs.writeFileSync(fakePath, sentinel, { mode: 0o600 })
    return fakePath
  }

  /** Remove the temp dir and every fake file in it. Idempotent. */
  dispose(): void {
    if (this.dir !== undefined) {
      try {
        fs.rmSync(this.dir, { recursive: true, force: true })
      } catch (err) {
        logForDebugging(`MaskedFileStore cleanup failed: ${err}`, {
          level: 'error',
        })
      }
    }
    this.dir = undefined
    this.byKey.clear()
  }

  /** Temp dir path, or undefined if no fake has been written yet. */
  get dirPath(): string | undefined {
    return this.dir
  }
}

/**
 * For each `mode: "mask"` file entry: resolve the path, read the real
 * content, register `(file:<path>, content, injectHosts)` in `registry`,
 * write the sentinel to a fake file via `store`, and return the bind list.
 *
 * Entries whose path does not exist, is unreadable, or resolves to a
 * directory are skipped with a debug log — same posture as a masked env
 * var that's unset on the host: nothing to protect, and surfacing a hard
 * error would make a portable config brittle across machines.
 *
 * The directory check is the authoritative one (the schema only catches a
 * trailing slash); whole-file masking has no meaning for a directory.
 */
export function buildMaskedFileBinds(
  files: readonly CredentialFileConfig[],
  allowedDomains: readonly string[],
  registry: SentinelRegistry,
  store: MaskedFileStore,
): MaskedFileBind[] {
  const binds: MaskedFileBind[] = []
  for (const f of files) {
    if (f.mode !== 'mask') continue
    const realPath = normalizePathForSandbox(f.path)

    let content: string
    try {
      const stat = fs.statSync(realPath)
      if (stat.isDirectory()) {
        logForDebugging(
          `[credential-mask] Skipping masked file entry that resolves to ` +
            `a directory: ${f.path} — use mode "deny" for directories.`,
          { level: 'warn' },
        )
        continue
      }
      content = fs.readFileSync(realPath, 'utf8')
    } catch (err) {
      logForDebugging(
        `[credential-mask] Skipping masked file (unreadable on host): ` +
          `${f.path} — ${(err as Error).message}`,
      )
      continue
    }

    const injectHosts = f.injectHosts ?? allowedDomains
    const key = FILE_KEY_PREFIX + realPath
    const sentinel = registry.register(key, content, injectHosts)
    const fakePath = store.write(key, sentinel)
    binds.push({ realPath, fakePath })
  }
  return binds
}

export const MASKED_FILE_STORE_PREFIX = 'srt-credmask-'
