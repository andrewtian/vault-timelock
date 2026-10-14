// Hash routes (W1): '#/', '#/jobs/<id>', '#/open', '#/decrypt', '#/status', '#/how[/network|/modes|/files]'. Hash routing needs no server fallback for deep links and keeps
// the page server static.
import { useEffect, useState } from 'react'
import NewJob from './jobs/NewJob.jsx'
import Job from './pages/Job.jsx'
import How from './how/How.jsx'
import Jobs from './pages/Jobs.jsx'
import Decrypt from './pages/Decrypt.jsx'
import Open from './pages/Open.jsx'
import Status from './pages/Status.jsx'

export function parseRoute(hash) {
  const path = hash.replace(/^#/, '') || '/'
  const m = /^\/jobs\/([0-9a-f]{16})\/?$/.exec(path)
  if (m) return { name: 'job', id: m[1] }
  if (path === '/status') return { name: 'status' }
  const how = /^\/how(?:\/(network|modes|files))?\/?$/.exec(path)
  if (how) return { name: 'how', tab: how[1] || 'vault' }
  if (path === '/new') return { name: 'new' }
  if (path === '/open') return { name: 'open' }
  if (path === '/decrypt') return { name: 'decrypt' }
  if (path === '/' || path === '/jobs') return { name: 'jobs' }
  return { name: 'missing' }
}

export function useRoute() {
  const [hash, setHash] = useState(() => window.location.hash)
  useEffect(() => {
    const on = () => setHash(window.location.hash)
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return parseRoute(hash)
}

export const NAV = [{ href: '#/', label: 'Jobs', name: 'jobs' }, { href: '#/new', label: 'New job', name: 'new' }, { href: '#/open', label: 'Open', name: 'open' }, { href: '#/decrypt', label: 'Decrypt', name: 'decrypt' }, { href: '#/status', label: 'Status', name: 'status' }, { href: '#/how', label: 'How', name: 'how' }]

export function Nav({ route }) {
  return (
    <nav aria-label="Pages" className="flex gap-3 text-sm">
      {NAV.map((n) => (
        <a key={n.name} href={n.href} aria-current={route.name === n.name ? 'page' : undefined} className="underline-offset-4 hover:underline aria-[current=page]:font-semibold">{n.label}</a>
      ))}
    </nav>
  )
}

export function Routes({ route }) {
  if (route.name === 'job') return <Job id={route.id} />
  if (route.name === 'status') return <Status />
  if (route.name === 'how') return <How tab={route.tab} />
  if (route.name === 'new') return <NewJob />
  if (route.name === 'open') return <Open />
  if (route.name === 'decrypt') return <Decrypt />
  if (route.name === 'jobs') return <Jobs />
  return <p>Not found.</p>
}
