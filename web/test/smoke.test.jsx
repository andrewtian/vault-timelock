// Task 0 smoke: React + Testing Library render under jsdom.
import { test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

test('renders', () => {
  render(<div>ok</div>)
  expect(screen.getByText('ok').textContent).toBe('ok')
})
