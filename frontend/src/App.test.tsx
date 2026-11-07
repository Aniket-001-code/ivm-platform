import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import App from './App'

describe('login screen', () => {
  it('shows the seeded local demo sign-in without requesting data', () => {
    const queryClient = new QueryClient()
    render(<QueryClientProvider client={queryClient}><MemoryRouter><App /></MemoryRouter></QueryClientProvider>)
    expect(screen.getByRole('heading', { name: 'Sign in to IVM' })).toBeInTheDocument()
    expect(screen.getByLabelText('Email address')).toHaveValue('user2@demo.bank')
    expect(screen.getByLabelText('Password')).toHaveValue('DemoPass!234')
  })
})
