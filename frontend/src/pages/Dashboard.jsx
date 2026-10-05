// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Flame, Clock, Target, Sparkles, Route as RouteIcon, ArrowRight, X, Gauge } from 'lucide-react'
import { api } from '../api'
import {
  CATEGORY_LABEL, ErrorBox, Loading, PageHeader, PRIORITY_COLOR, PRIORITY_LABEL, PriorityBadge, Stat, fmtDate,
} from '../components/ui'

function Funnel({ stats }) {
  const steps = [
    { label: 'Alertas brutos dos scanners', value: stats.raw_occurrences, color: '#3f3f50' },
    { label: 'Vulnerabilidades únicas (após deduplicação)', value: stats.unique_findings, color: '#5b4bb5' },
    { label: 'Acionáveis (sem falsos positivos e já corrigidas)', value: stats.actionable, color: '#7c3aed' },
    { label: 'Prioridade imediata (P1)', value: stats.p1, color: PRIORITY_COLOR.P1 },
  ]
  const max = Math.max(stats.raw_occurrences, 1)
  return (
    <div className="panel p-5">
      <div className="mb-4 flex items-baseline justify-between">
        <h2 className="text-base font-normal">Do ruído à decisão</h2>
        <span className="text-sm">
          <span className="font-display text-2xl font-light brand-text">{stats.noise_reduction_pct}%</span>
          <span className="ml-2 text-muted">de redução de ruído</span>
        </span>
      </div>
      <div className="space-y-3">
        {steps.map((s) => (
          <div key={s.label}>
            <div className="mb-1 flex justify-between text-xs">
              <span className="text-muted">{s.label}</span>
              <span className="font-mono text-white">{s.value}</span>
            </div>
            <div className="h-2.5 rounded-full bg-panel-2">
              <div className="h-full rounded-full transition-all" style={{ width: `${(s.value / max) * 100}%`, background: s.color }} />
            </div>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs text-muted">
        {stats.duplicates_removed} alertas duplicados consolidados · {stats.fp_suspected} prováveis falsos positivos isolados
      </p>
    </div>
  )
}

function Distribution({ title, data, colors, labels }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0) || 1
  return (
    <div className="panel p-5">
      <h2 className="mb-4 text-base font-normal">{title}</h2>
      <div className="mb-4 flex h-3 overflow-hidden rounded-full bg-panel-2">
        {Object.entries(data).map(([k, v]) => v > 0 && (
          <div key={k} style={{ width: `${(v / total) * 100}%`, background: colors[k] }} title={`${k}: ${v}`} />
        ))}
      </div>
      <div className="grid grid-cols-2 gap-2">
        {Object.entries(data).map(([k, v]) => (
          <div key={k} className="flex items-center justify-between rounded-md bg-panel-2 px-3 py-2 text-sm">
            <span className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full" style={{ background: colors[k] }} />
              {labels ? labels[k] : k}
            </span>
            <span className="font-mono text-white">{v}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function Trend({ trend }) {
  if (!trend.length) return null
  const W = 560, H = 150, P = 24
  const maxY = Math.max(...trend.map((t) => t.actionable), 1)
  const x = (i) => P + (i * (W - 2 * P)) / Math.max(trend.length - 1, 1)
  const y = (v) => H - P - (v / maxY) * (H - 2 * P)
  const line = (key) => trend.map((t, i) => `${i ? 'L' : 'M'}${x(i)},${y(t[key])}`).join(' ')
  return (
    <div className="panel p-5">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-base font-normal">Histórico de risco</h2>
        <div className="flex gap-4 text-xs text-muted">
          <span className="flex items-center gap-1.5"><span className="h-0.5 w-4 bg-violet" />Acionáveis</span>
          <span className="flex items-center gap-1.5"><span className="h-0.5 w-4" style={{ background: PRIORITY_COLOR.P1 }} />P1</span>
        </div>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full">
        {[0, 0.5, 1].map((r) => (
          <line key={r} x1={P} x2={W - P} y1={y(maxY * r)} y2={y(maxY * r)} stroke="#24242f" strokeDasharray="3 4" />
        ))}
        <path d={line('actionable')} fill="none" stroke="#7c3aed" strokeWidth="2" />
        <path d={line('p1')} fill="none" stroke={PRIORITY_COLOR.P1} strokeWidth="2" />
        {trend.map((t, i) => (
          <g key={i}>
            <circle cx={x(i)} cy={y(t.actionable)} r="3" fill="#7c3aed">
              <title>{`${fmtDate(t.taken_at)} · ${t.trigger}\nAcionáveis: ${t.actionable} · P1: ${t.p1}`}</title>
            </circle>
            <circle cx={x(i)} cy={y(t.p1)} r="2.5" fill={PRIORITY_COLOR.P1} />
          </g>
        ))}
      </svg>
      <div className="flex justify-between text-[11px] text-muted">
        <span>{fmtDate(trend[0].taken_at, false)}</span>
        <span>{fmtDate(trend[trend.length - 1].taken_at, false)}</span>
      </div>
    </div>
  )
}

function ExecutiveSummary({ onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { api.executiveSummary().then(setData).catch(setError) }, [])
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4" onClick={onClose}>
      <div className="panel max-h-[85vh] w-full max-w-2xl overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-start justify-between">
          <div className="flex items-center gap-2 text-violet-300"><Sparkles size={18} /> Resumo executivo gerado por IA</div>
          <button className="text-muted hover:text-white" onClick={onClose}><X size={18} /></button>
        </div>
        <ErrorBox error={error} />
        {!data && !error && <Loading text="A IA está analisando a postura de risco..." />}
        {data && (
          <div className="space-y-5 text-sm">
            <h2 className="text-xl font-light">{data.titulo}</h2>
            <p className="leading-relaxed">{data.situacao}</p>
            <div>
              <div className="label mb-2">Principais riscos</div>
              <ul className="space-y-1.5">{data.principais_riscos?.map((r, i) => <li key={i} className="flex gap-2"><span className="text-p1">•</span>{r}</li>)}</ul>
            </div>
            <div>
              <div className="label mb-2">Recomendações</div>
              <ol className="space-y-1.5">{data.recomendacoes?.map((r, i) => (
                <li key={i} className="flex gap-3"><span className="font-mono text-violet-300">{i + 1}.</span>{r}</li>
              ))}</ol>
            </div>
            <p className="rounded-lg border border-violet/40 bg-violet/10 p-3 text-white">{data.mensagem_final}</p>
            <p className="text-xs text-muted">Gerado por: {data.provider === 'offline' ? 'base de conhecimento local' : `${data.provider} · ${data.model}`}</p>
          </div>
        )}
      </div>
    </div>
  )
}

function RiskList({ title, subtitle, items, metric, navigate }) {
  return (
    <div className="panel p-5">
      <h2 className="text-base font-normal">{title}</h2>
      <p className="mb-3 text-xs text-muted">{subtitle}</p>
      <div className="space-y-1">
        {items.map((f, i) => (
          <button
            key={f.id}
            onClick={() => navigate(`/vulnerabilidades?id=${f.id}`)}
            className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left hover:bg-panel-2"
          >
            <span className="w-4 font-mono text-xs text-muted">{i + 1}</span>
            <PriorityBadge priority={f.priority} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm text-white">{f.vuln_id?.startsWith('CVE') ? f.vuln_id : f.title}</div>
              <div className="truncate text-xs text-muted">{f.asset}</div>
            </div>
            <div className="text-right font-mono text-xs">
              <div className="text-white">{metric === 'cvss' ? `CVSS ${f.cvss}` : `${Math.round(f.risk_score)} pts`}</div>
              <div className="text-muted">{metric === 'cvss' ? `${Math.round(f.risk_score)} pts` : `CVSS ${f.cvss}`}</div>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [showSummary, setShowSummary] = useState(false)
  const navigate = useNavigate()

  useEffect(() => { api.dashboard().then(setData).catch(setError) }, [])

  if (error) return <ErrorBox error={error} />
  if (!data) return <Loading />
  const { stats } = data

  return (
    <>
      <PageHeader title="Visão executiva" subtitle={`${data.assets} ativos monitorados · postura de segurança de aplicações em tempo real`}>
        <button className="btn-primary" onClick={() => setShowSummary(true)}><Sparkles size={16} /> Resumo executivo com IA</button>
      </PageHeader>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Ação imediata (P1)" value={stats.p1} icon={Target} accent={PRIORITY_COLOR.P1} hint={`de ${stats.actionable} vulnerabilidades acionáveis`} />
        <Stat label="Exploradas ativamente" value={stats.kev_open} icon={Flame} accent="#fb923c" hint="Catálogo CISA KEV" />
        <Stat label="Em caminho de ataque" value={stats.on_attack_path} icon={RouteIcon} accent="#a78bfa" hint="Levam a sistemas críticos" />
        <Stat label="MTTR" value={stats.mttr_days != null ? `${stats.mttr_days} d` : '—'} icon={Clock} hint={`${stats.resolved} vulnerabilidade(s) corrigida(s)`} />
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-5">
        <div className="lg:col-span-3"><Funnel stats={stats} /></div>
        <div className="lg:col-span-2">
          <Distribution title="Prioridade das acionáveis" data={stats.by_priority} colors={PRIORITY_COLOR}
            labels={Object.fromEntries(Object.keys(PRIORITY_LABEL).map((k) => [k, `${k} · ${PRIORITY_LABEL[k]}`]))} />
        </div>
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <RiskList title="Top 5 pelo NEXUS" subtitle="Risco real: exploração, exposição e impacto no negócio" items={data.top_risks} metric="risk" navigate={navigate} />
        <RiskList title="Top 5 pelo CVSS" subtitle="Como uma ferramenta tradicional ordenaria (só severidade)" items={data.top_by_cvss_only} metric="cvss" navigate={navigate} />
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-5">
        <div className="lg:col-span-3"><Trend trend={data.trend} /></div>
        <div className="lg:col-span-2">
          <Distribution title="Origem das acionáveis" data={stats.by_category}
            colors={{ SCA: '#7c3aed', CONTAINER: '#3b82f6', SAST: '#22d3ee', DAST: '#f472b6' }} labels={CATEGORY_LABEL} />
        </div>
      </div>

      <div className="panel p-5">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h2 className="text-base font-normal">Correlação de CVEs entre aplicações</h2>
            <p className="text-xs text-muted">A mesma vulnerabilidade presente em mais de um ativo: uma correção, vários riscos eliminados</p>
          </div>
          <Gauge size={18} className="text-muted" />
        </div>
        {data.cross_app_cves.length === 0 ? (
          <p className="text-sm text-muted">Nenhuma CVE compartilhada entre ativos.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted">
                <tr><th className="py-2 pr-4 font-normal">CVE</th><th className="pr-4 font-normal">Componente</th><th className="pr-4 font-normal">Ativos afetados</th><th className="pr-4 font-normal">CVSS</th><th className="font-normal">Maior risco</th></tr>
              </thead>
              <tbody>
                {data.cross_app_cves.map((c) => (
                  <tr key={c.vuln_id} className="border-t border-line">
                    <td className="py-2.5 pr-4 font-mono text-white">
                      {c.vuln_id} {c.exploit_known && <Flame size={12} className="inline text-p1" />}
                    </td>
                    <td className="pr-4 text-muted">{c.package}</td>
                    <td className="pr-4">
                      <div className="flex flex-wrap gap-1">{c.assets.map((a) => <span key={a} className="rounded bg-panel-2 px-1.5 py-0.5 text-xs">{a}</span>)}</div>
                    </td>
                    <td className="pr-4 font-mono">{c.cvss}</td>
                    <td className="font-mono text-white">{Math.round(c.max_risk)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Link to="/vulnerabilidades" className="mt-4 inline-flex items-center gap-1 text-sm text-violet-300 hover:text-white">
          Ver todas as vulnerabilidades priorizadas <ArrowRight size={14} />
        </Link>
      </div>

      {showSummary && <ExecutiveSummary onClose={() => setShowSummary(false)} />}
    </>
  )
}
