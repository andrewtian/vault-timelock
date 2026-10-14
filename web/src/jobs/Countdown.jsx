// PORTED (R69) from the prototype, tag add7b-e540f8ae4d6b, src/Countdown.jsx — rolling digits (@number-flow/react,
// trend -1), the ring, the urgent last 10 s, motion for the container. Canonical changes (W3):
//   · time is the API's: `now()` is the server clock (lib/serverClock.js; null before the first sync). Before the first
//     sync the countdown shows "syncing" and never completes; a re-sync, a local clock jump or a Skip (the target moves
//     to the server's now) makes it JUMP to the server's answer instead of drifting.
//   · ticks on a 200 ms interval (state only when the second changes) instead of requestAnimationFrame, so a hidden tab
//     still completes it (the executor, not this view, starts the chains);
//   · the completion CTA link is gone: at zero this view only reports; the executors start by the API's clock.
//   · dark prototype palette → the app's tokens; data-remaining / data-synced for the tests.
import { memo, useEffect, useRef, useState } from 'react'
import NumberFlow, { NumberFlowGroup } from '@number-flow/react'
import { motion, useReducedMotion } from 'motion/react'

const EASE = 'cubic-bezier(.32,.72,0,1)'
const split = (s) => ({ d: Math.floor(s / 86400), h: Math.floor((s % 86400) / 3600), m: Math.floor((s % 3600) / 60), s: s % 60 })
export const mmss = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

// remaining whole seconds by the server clock, or null before the first sync
export function remainingOf(target, now) {
  const t = now()
  return t === null ? null : Math.max(0, Math.ceil((target - t) / 1000))
}

// memo: the page re-renders on every journal line; the countdown only when its props change
export const Countdown = memo(CountdownImpl)
export default Countdown

function CountdownImpl({ target, total, label, now, onComplete, skipping = false, tickMs = 200, testid = 'countdown' }) {
  const reduce = useReducedMotion()
  const [remaining, setRemaining] = useState(() => remainingOf(target, now))
  const fired = useRef(false)

  useEffect(() => {
    fired.current = false
    let last
    const tick = () => { const v = remainingOf(target, now); if (v !== last) { last = v; setRemaining(v) } }
    tick()
    const t = setInterval(tick, tickMs)
    return () => clearInterval(t)
  }, [target, now, tickMs])

  useEffect(() => { if (remaining === 0 && !fired.current) { fired.current = true; onComplete?.() } }, [remaining, onComplete])

  const synced = remaining !== null
  const r = synced ? remaining : total
  const t = split(r)
  const done = remaining === 0
  const urgent = synced && !done && remaining <= 10
  const showDays = total >= 86400
  const timing = skipping ? { duration: 600, easing: EASE } : { duration: 750, easing: EASE }
  const common = { trend: -1, transformTiming: timing, spinTiming: timing, opacityTiming: { duration: 350, easing: 'ease-out' }, format: { minimumIntegerDigits: 2 } }
  const frac = total > 0 ? r / total : 0
  const R = 92, C = 2 * Math.PI * R
  const parts = [
    ...(showDays ? [['d', t.d, {}]] : []),
    ...(total >= 3600 ? [['h', t.h, { 1: { max: 2 } }]] : []), ['m', t.m, { 1: { max: 5 } }], ['s', t.s, { 1: { max: 5 } }],
  ]

  return (
    <motion.div data-testid={testid} data-remaining={synced ? String(remaining) : ''} data-synced={String(synced)} data-done={String(done)}
      className="relative mx-auto grid w-[320px] place-items-center rounded-2xl border bg-card p-6"
      animate={done && !reduce ? { boxShadow: ['0 0 0 0 rgba(16,185,129,0)', '0 0 0 8px rgba(16,185,129,.35)', '0 0 0 0 rgba(16,185,129,0)'] } : {}}
      transition={{ duration: 0.6 }}>
      <div className="mb-3 text-xs uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="relative grid place-items-center">
        <svg width="200" height="200" viewBox="0 0 220 220" className="-rotate-90" aria-hidden>
          <circle cx="110" cy="110" r={R} stroke="currentColor" strokeWidth="6" fill="none" className="text-muted" />
          <circle cx="110" cy="110" r={R} strokeWidth="6" fill="none" strokeLinecap="round"
            stroke={done ? '#10b981' : urgent ? '#f59e0b' : '#64748b'} strokeDasharray={C} strokeDashoffset={C * (1 - frac)}
            style={{ transition: skipping ? 'stroke-dashoffset .6s cubic-bezier(.32,.72,0,1)' : 'stroke-dashoffset 1s linear, stroke .3s' }} />
        </svg>
        <div role="timer" aria-live="off" className={`tabular-nums absolute flex items-baseline text-5xl font-semibold ${done ? 'text-emerald-600' : urgent ? 'text-amber-600' : ''} ${synced ? '' : 'opacity-40'}`}>
          <NumberFlowGroup>
            {parts.map(([k, v, digits], i) => (
              <span key={k} className="flex items-baseline">
                {i > 0 && <span className="px-0.5 text-muted-foreground">:</span>}
                <NumberFlow value={v} digits={digits} {...common} />
                {k === 'd' && <span className="ml-1 text-2xl text-muted-foreground">d</span>}
              </span>
            ))}
          </NumberFlowGroup>
        </div>
      </div>
      <span data-testid={`${testid}-text`} className="mt-3 text-xs text-muted-foreground">
        {!synced ? 'syncing with the API clock…' : done ? `${label}: done` : `${label}: ${mmss(remaining)} left (API clock)`}
      </span>
    </motion.div>
  )
}
