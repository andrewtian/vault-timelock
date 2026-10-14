// I4 (MQ): secret fields that password managers must not offer to save: a TEXT input masked with -webkit-text-security,
// no autocomplete, the 1Password/LastPass/Bitwarden/Dashlane ignore hints, a random name, and never inside a <form>.
// Every field also carries an id (E2E finding L2-2). Ported from the prototype's ui.jsx SecretInput.
import { useId, useState } from 'react'
import { Input } from '@/components/ui/input.jsx'

const rnd = () => `f${Math.random().toString(36).slice(2, 10)}`

export default function SecretInput(props) {
  const [name] = useState(rnd)
  const id = useId()
  return (
    <Input id={id} name={name} {...props} type="text" autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false}
      data-1p-ignore="true" data-lpignore="true" data-bwignore="true" data-form-type="other" className={`secret-input font-mono ${props.className || ''}`}
      style={{ WebkitTextSecurity: 'disc' }} />
  )
}
