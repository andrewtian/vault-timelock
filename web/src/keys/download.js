// Saves bytes as a file through a temporary object URL (ported from the prototype's keys.js `download`). The file is the
// operator's encrypted key backup; nothing is stored by the page.
// `scope` (optional Set): the URL is added to it, so a page that handles plaintext (Open) can revoke what it made, at once, on
// Clear / unmount / navigation, instead of waiting for the 30 s timer.
export function download(bytes, name, scope = null) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }))
  scope?.add(url)
  const a = document.createElement('a'); a.href = url; a.download = name; a.rel = 'noopener'
  document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => { URL.revokeObjectURL(url); scope?.delete(url) }, 30000)
}

export function revokeAll(scope) {
  for (const url of scope) URL.revokeObjectURL(url)
  scope.clear()
}
