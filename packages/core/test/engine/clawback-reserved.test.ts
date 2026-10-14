// E6: the engine's claw-back refuses every reserved destination from the one source (chains/reserved.js) BEFORE any RPC read.
// ALL DATA IS SYNTHETIC; the key objects are stubs (the refusal comes first, nothing is read or signed).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PublicKey } from '@solana/web3.js'
import { getAddress } from 'viem'
import { clawbackEth, clawbackSol } from '../../src/engine/lane.js'

const ETH_KEY = { account: { address: '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C' } }
const SOL_KEY = { kp: { publicKey: new PublicKey('9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb') } }
const at = (n: bigint): string => getAddress('0x' + n.toString(16).padStart(40, '0'))

test('ETH claw-back: a precompile / reserved-range destination is refused before any read', async () => {
  for (const n of [1n, 9n, 0x11n, 0xffffn]) await assert.rejects(clawbackEth(ETH_KEY, at(n), {}), /precompile or reserved system address/, n.toString(16))
  await assert.rejects(clawbackEth(ETH_KEY, '0x000000000000000000000000000000000000dEaD', {}), /the burn address/)
  await assert.rejects(clawbackEth(ETH_KEY, at(0n), {}), /null address/)
})

test('SOL claw-back: the System Program and the incinerator are refused before any read', async () => {
  await assert.rejects(clawbackSol(SOL_KEY, '11111111111111111111111111111111', {}), /System Program/)
  await assert.rejects(clawbackSol(SOL_KEY, '1nc1nerator11111111111111111111111111111111', {}), /incinerator/)
})
