// The tar.gz reader MOVED to core (vt decrypt addendum: the CLI and the page share one hardened reader, M-5 / F13-1 included):
// @vault-timelock/core/decrypt/tar.ts. This file re-exports it, so the page's imports (open.js) stay as they were. Its tests moved with
// it (packages/core/test/decrypt/tar.test.ts); web/test/tar.test.js runs them against the same module through the page's build.
export { TAR_LIMITS, crc32, gunzip, isGzip, readTar, readTarGz } from '@vault-timelock/core/decrypt/tar.ts'
