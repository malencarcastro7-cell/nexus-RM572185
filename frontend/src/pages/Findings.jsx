// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Download, Search } from 'lucide-react'
import { api } from '../api'
import FindingDrawer from '../components/FindingDrawer'
import {
  CATEGORY_LABEL, ErrorBox, FindingTags, Loading, PageHeader, PRIORITY_COLOR, PriorityBadge, ScoreBar,
  SCANNER_LABEL, STATUS_LABEL,
} from '../components/ui'

const PRIORITIES = ['P1', 'P2', 'P3', 'P4']

export default function Findings() {
  const [params, setParams] = useSearchParams()
  const [items, setItems] = useState(null)
  const [assets, setAssets] = useState([])
  const [error, setError] = useState(null)
  const [q, setQ] = useState('')
  const [filters, setFilters] = useState({ priority: [], category: '', asset_id: '', status: 'active', include_fp: false, sort: 'risk' })
  const selected = params.get('id')

  const load = () => {
    api.findings({
      priority: filters.priority.join(','),
      category: filters.category,
      asset_id: filters.asset_id,
      status: filters.status,
      include_fp: filters.include_fp,
      sort: filters.sort,
    }).then(setItems).catch(setError)
  }

  useEffect(load, [filters]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { api.assets().then(setAssets).catch(() => {}) }, [])

  const visible = useMemo(() => {
    if (!items) return []
    const term = q.trim().toLowerCase()
    if (!term) return items
    return items.filter((f) => [f.title, f.vuln_id, f.cwe, f.package, f.location, f.asset].join(' ').toLowerCase().includes(term))
  }, [items, q])

  const togglePriority = (p) => setFilters((f) => ({
    ...f, priority: f.priority.includes(p) ? f.priority.filter((x) => x !== p) : [...f.priority, p],
  }))

  return (
    <>
      <PageHeader title="Vulnerabilidades priorizadas" subtitle="Consolidadas de todos os scanners e ordenadas por risco real, não só por severidade">
        <a className="btn-ghost" href={api.exportCsvUrl(filters.include_fp)}><Download size={15} /> Exportar CSV</a>
      </PageHeader>

      <div className="panel mb-4 flex flex-wrap items-center gap-3 p-3">
        <div className="relative min-w-56 flex-1">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input className="input w-full pl-9" placeholder="Buscar CVE, pacote, CWE, arquivo..." value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="flex gap-1">
          {PRIORITIES.map((p) => {
            const on = filters.priority.includes(p)
            return (
              <button key={p} onClick={() => togglePriority(p)}
                className="rounded-md border px-2.5 py-1.5 font-mono text-xs"
                style={on ? { borderColor: PRIORITY_COLOR[p], color: PRIORITY_COLOR[p], background: `${PRIORITY_COLOR[p]}1a` } : { borderColor: '#24242f', color: '#8b8b9e' }}>
                {p}
              </button>
            )
          })}
        </div>
        <select className="input" value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })}>
          <option value="">Todas as categorias</option>
          {Object.entries(CATEGORY_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select className="input" value={filters.asset_id} onChange={(e) => setFilters({ ...filters, asset_id: e.target.value })}>
          <option value="">Todos os ativos</option>
          {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </select>
        <select className="input" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
          <option value="active">Ativas</option>
          <option value="all">Todas</option>
          {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select className="input" value={filters.sort} onChange={(e) => setFilters({ ...filters, sort: e.target.value })}>
          <option value="risk">Ordenar por risco NEXUS</option>
          <option value="cvss">Ordenar por CVSS</option>
        </select>
        <label className="flex items-center gap-2 text-xs text-muted">
          <input type="checkbox" checked={filters.include_fp} onChange={(e) => setFilters({ ...filters, include_fp: e.target.checked })} className="accent-violet-500" />
          Mostrar prováveis falsos positivos
        </label>
      </div>

      <ErrorBox error={error} />
      {!items ? <Loading /> : (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[900px] text-sm">
            <thead className="border-b border-line text-left text-xs text-muted">
              <tr>
                <th className="px-4 py-3 font-normal">Prioridade</th>
                <th className="px-2 font-normal">Risco</th>
                <th className="px-2 font-normal">Vulnerabilidade</th>
                <th className="px-2 font-normal">Ativo</th>
                <th className="px-2 font-normal">Tipo</th>
                <th className="px-2 font-normal">CVSS</th>
                <th className="px-4 font-normal">Scanners</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f) => (
                <tr key={f.id} onClick={() => setParams({ id: f.id })}
                  className={`cursor-pointer border-b border-line/60 hover:bg-panel-2 ${f.status === 'resolved' ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-3"><PriorityBadge priority={f.priority} /></td>
                  <td className="px-2"><ScoreBar score={f.risk_score} priority={f.priority} /></td>
                  <td className="max-w-md px-2 py-3">
                    <div className="truncate text-white" title={f.title}>{f.title}</div>
                    <div className="mb-1.5 truncate font-mono text-xs text-muted">
                      {f.vuln_id}{f.package && ` · ${f.package}`}{f.status !== 'open' && ` · ${STATUS_LABEL[f.status]}`}
                    </div>
                    <FindingTags f={f} />
                  </td>
                  <td className="px-2 text-soft">{f.asset}</td>
                  <td className="px-2 text-xs text-muted">{CATEGORY_LABEL[f.category]}</td>
                  <td className="px-2 font-mono text-xs">{f.cvss.toFixed(1)}</td>
                  <td className="px-4 text-xs text-muted">{f.sources.map((s) => SCANNER_LABEL[s] || s).join(' + ')}</td>
                </tr>
              ))}
              {visible.length === 0 && (
                <tr><td colSpan={7} className="py-12 text-center text-sm text-muted">Nenhuma vulnerabilidade com esses filtros.</td></tr>
              )}
            </tbody>
          </table>
          <div className="px-4 py-3 text-xs text-muted">{visible.length} vulnerabilidade(s)</div>
        </div>
      )}

      {selected && <FindingDrawer id={selected} onClose={() => setParams({})} onChanged={load} />}
    </>
  )
}
