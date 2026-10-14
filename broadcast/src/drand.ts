// drand quicknet, pinned (Task S1 §3; audit CD-minor). SEALED.txt says `drand: quicknet <hash>` and
// derives unlock-after from genesis + (round - 1) * period, so a package whose chain-info.json is
// not exactly quicknet would be mislabelled in permanent text. sealed.ts checks against this.
// Shared constant, deliberately not in config.ts (sealed.ts must not depend on config); the same
// hash is anchors.json's `drand.quicknet` (a test pins the two equal). Part D's D0 moves it to core.
export const QUICKNET = {
  hash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  genesis: 1692803367,
  period: 3,
  schemeID: 'bls-unchained-g1-rfc9380',
} as const
