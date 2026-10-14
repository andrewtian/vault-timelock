// The receipt (W4): the API's `vt-receipt/1` bytes, saved as a file exactly as served (S2: no keys, no IPs, no message
// text; mainnet links are scheme-less copy text). `vt job receipt <id>` fetches the same bytes.
import { useState } from 'react'
import { P } from '@vault-timelock/core/contracts'
import { Button } from '@/components/ui/button.jsx'
import { apiBytes } from '@/lib/api.js'
import { download } from '@/keys/download.js'

export default function ReceiptButton({ jobId, testid = 'job-receipt' }) {
  const [msg, setMsg] = useState(null)
  const go = async () => {
    setMsg(null)
    try {
      const bytes = await apiBytes(P.receipt(jobId))
      download(bytes, `vt-receipt-${jobId}.json`)
      setMsg({ ok: true, text: `saved vt-receipt-${jobId}.json (${bytes.length} bytes)` })
    } catch (e) { setMsg({ ok: false, text: `${e.guard || 'error'}: ${e.message}` }) }
  }
  return (
    <span className="inline-flex flex-col items-end gap-0.5">
      <Button type="button" size="xs" variant="outline" data-testid={testid} onClick={go}>Receipt (JSON)</Button>
      {msg && <span data-testid={`${testid}-msg`} className={`text-[11px] ${msg.ok ? 'text-emerald-800' : 'text-red-700'}`}>{msg.text}</span>}
    </span>
  )
}
