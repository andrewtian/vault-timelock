// The operator-triggered "normalize line endings / tabs" action (E1 ruling 4). Core refuses CR, TAB, U+2028 and U+2029
// and never rewrites a message; this page never rewrites one by itself either. Only when the operator presses the
// button is the text rewritten, and the page then says exactly what changed. Nothing else is touched: no NFC, no BOM,
// no trimming (those stay refusals the operator fixes in the source).
export const TAB_SPACES = 4

const count = (s, re) => (s.match(re) || []).length

// -> { crlf, cr, ls, ps, tab, total } (what normalizeText would replace)
export function normalizeSummary(text) {
  const crlf = count(text, /\r\n/g)
  const cr = count(text.replace(/\r\n/g, ''), /\r/g)
  const ls = count(text, /\u2028/g), ps = count(text, /\u2029/g), tab = count(text, /\t/g)
  return { crlf, cr, ls, ps, tab, total: crlf + cr + ls + ps + tab }
}

// -> { text, summary } with CRLF, a lone CR, U+2028 and U+2029 → LF, and TAB → TAB_SPACES spaces.
export function normalizeText(text) {
  const summary = normalizeSummary(text)
  const out = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/[\u2028\u2029]/g, '\n').replace(/\t/g, ' '.repeat(TAB_SPACES))
  return { text: out, summary }
}

export function describeSummary(s) {
  const parts = []
  if (s.crlf) parts.push(`${s.crlf} CRLF → LF`)
  if (s.cr) parts.push(`${s.cr} lone CR → LF`)
  if (s.ls) parts.push(`${s.ls} U+2028 line separator → LF`)
  if (s.ps) parts.push(`${s.ps} U+2029 paragraph separator → LF`)
  if (s.tab) parts.push(`${s.tab} TAB → ${TAB_SPACES} spaces`)
  return parts.join(', ')
}
