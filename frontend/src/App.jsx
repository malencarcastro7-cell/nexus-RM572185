// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { NavLink, Route, Routes } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, Route as RouteIcon, Server, Upload, Bot } from 'lucide-react'
import { api } from './api'
import { Logo } from './components/ui'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import AttackPaths from './pages/AttackPaths'
import Assets from './pages/Assets'
import Imports from './pages/Imports'

const ToastContext = createContext(() => {})
export const useToast = () => useContext(ToastContext)

const NAV = [
  { to: '/', label: 'Visão executiva', icon: LayoutDashboard, end: true },
  { to: '/vulnerabilidades', label: 'Vulnerabilidades', icon: ShieldAlert },
  { to: '/caminhos-de-ataque', label: 'Caminhos de ataque', icon: RouteIcon },
  { to: '/ativos', label: 'Ativos e contexto', icon: Server },
  { to: '/ingestao', label: 'Ingestão', icon: Upload },
]

export default function App() {
  const [toast, setToast] = useState(null)
  const [ai, setAi] = useState(null)

  const notify = useCallback((message, tone = 'ok') => {
    setToast({ message, tone, id: Date.now() })
  }, [])

  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 3500)
    return () => clearTimeout(t)
  }, [toast])

  useEffect(() => {
    api.health().then((h) => setAi(h.ai)).catch(() => setAi(null))
  }, [])

  return (
    <ToastContext.Provider value={notify}>
      <div className="flex min-h-full">
        <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-panel/60 px-4 py-6 md:flex">
          <div className="mb-8 flex items-center gap-3 px-2">
            <Logo size={34} />
            <div>
              <div className="font-display text-lg font-light tracking-[0.35em] text-white">NEXUS</div>
              <div className="text-[10px] uppercase tracking-widest text-muted">ASPM · IA</div>
            </div>
          </div>
          <nav className="flex flex-col gap-1">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                    isActive ? 'bg-panel-2 text-white shadow-[inset_2px_0_0_#7c3aed]' : 'text-muted hover:bg-panel-2 hover:text-white'
                  }`
                }
              >
                <Icon size={17} />
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="mt-auto rounded-lg border border-line bg-panel-2 p-3 text-xs">
            <div className="flex items-center gap-2 text-muted">
              <Bot size={14} /> Motor de IA
            </div>
            <div className="mt-1 font-medium text-white">
              {ai ? (ai.provider === 'offline' ? 'Base de conhecimento local' : `${ai.provider} · ${ai.model}`) : '—'}
            </div>
            <div className="mt-1 text-muted">RAG: CVE · OWASP · ATT&CK · CWE</div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex items-center gap-3 border-b border-line px-4 py-3 md:hidden">
            <Logo size={26} />
            <span className="font-display tracking-[0.3em] text-white">NEXUS</span>
          </header>
          <nav className="flex gap-1 overflow-x-auto border-b border-line px-2 py-2 md:hidden">
            {NAV.map(({ to, label, end }) => (
              <NavLink key={to} to={to} end={end}
                className={({ isActive }) => `whitespace-nowrap rounded-md px-3 py-1.5 text-xs ${isActive ? 'bg-panel-2 text-white' : 'text-muted'}`}>
                {label}
              </NavLink>
            ))}
          </nav>
          <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 md:px-8 md:py-8">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/vulnerabilidades" element={<Findings />} />
              <Route path="/caminhos-de-ataque" element={<AttackPaths />} />
              <Route path="/ativos" element={<Assets />} />
              <Route path="/ingestao" element={<Imports />} />
            </Routes>
          </main>
        </div>
      </div>

      {toast && (
        <div
          key={toast.id}
          className={`fixed bottom-6 right-6 z-50 max-w-sm rounded-lg border px-4 py-3 text-sm shadow-2xl ${
            toast.tone === 'error' ? 'border-rose-500/50 bg-rose-950 text-rose-100' : 'border-violet/50 bg-panel-2 text-white'
          }`}
        >
          {toast.message}
        </div>
      )}
    </ToastContext.Provider>
  )
}
