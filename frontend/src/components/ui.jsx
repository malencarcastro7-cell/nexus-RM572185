// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { Flame, Route, ShieldAlert, Layers, CircleCheck, Bug } from 'lucide-react'

export const PRIORITY_COLOR = { P1: '#f43f5e', P2: '#fb923c', P3: '#facc15', P4: '#64748b' }
export const PRIORITY_LABEL = { P1: 'Imediata', P2: 'Alta', P3: 'Média', P4: 'Baixa' }
export const SEVERITY_COLOR = { critical: '#f43f5e', high: '#fb923c', medium: '#facc15', low: '#38bdf8', info: '#64748b' }
export const SEVERITY_LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Média', low: 'Baixa', info: 'Info' }
export const STATUS_LABEL = {
  open: 'Aberta', in_progress: 'Em correção', resolved: 'Corrigida',
  false_positive: 'Falso positivo', risk_accepted: 'Risco aceito',
}
export const CATEGORY_LABEL = { SCA: 'SCA', CONTAINER: 'Container', SAST: 'SAST', DAST: 'DAST' }
export const DATA_LABEL = { public: 'Públicos', internal: 'Internos', confidential: 'Confidenciais', restricted: 'Restritos' }
export const ENV_LABEL = { production: 'Produção', staging: 'Homologação', development: 'Desenvolvimento' }
export const TYPE_LABEL = { webapp: 'Aplicação web', api: 'API', service: 'Serviço', database: 'Banco de dados', container: 'Container' }
export const SCANNER_LABEL = { trivy: 'Trivy', snyk: 'Snyk', zap: 'OWASP ZAP', sonarqube: 'SonarQube' }

export function PriorityBadge({ priority, large }) {
  const c = PRIORITY_COLOR[priority]
  return (
    <span
      className={`inline-flex items-center justify-center rounded-md font-mono font-semibold ${large ? 'px-2.5 py-1 text-sm' : 'px-1.5 py-0.5 text-xs'}`}
      style={{ color: c, background: `${c}1f`, border: `1px solid ${c}55` }}
      title={PRIORITY_LABEL[priority]}
    >
      {priority}
    </span>
  )
}

export function SeverityDot({ severity }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-soft">
      <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_COLOR[severity] }} />
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

export function Tag({ icon: Icon, children, tone = 'neutral', title }) {
  const tones = {
    neutral: 'border-line text-soft bg-panel-2',
    danger: 'border-rose-500/40 text-rose-300 bg-rose-500/10',
    warn: 'border-orange-400/40 text-orange-300 bg-orange-400/10',
    brand: 'border-violet/50 text-violet-300 bg-violet/10',
    ok: 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10',
    info: 'border-sky-500/40 text-sky-300 bg-sky-500/10',
  }
  return (
    <span title={title} className={`inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[11px] ${tones[tone]}`}>
      {Icon && <Icon size={11} />}
      {children}
    </span>
  )
}

export function FindingTags({ f }) {
  return (
    <div className="flex flex-wrap gap-1">
      {f.exploit_known && <Tag icon={Flame} tone="danger" title="Catálogo CISA KEV: explorada ativamente">KEV</Tag>}
      {!f.exploit_known && f.exploit_public && <Tag icon={Bug} tone="warn" title="Exploit público disponível">Exploit público</Tag>}
      {f.on_attack_path && <Tag icon={Route} tone="danger" title="Viabiliza um caminho de ataque">Caminho de ataque</Tag>}
      {f.corroborated && <Tag icon={CircleCheck} tone="brand" title="Confirmada por SAST e DAST">SAST + DAST</Tag>}
      {f.sources?.length > 1 && <Tag icon={Layers} tone="info" title={f.sources.join(', ')}>{f.sources.length} scanners</Tag>}
      {f.fp_suspected && <Tag icon={ShieldAlert} title={f.fp_reason}>Provável FP</Tag>}
    </div>
  )
}

export function ScoreBar({ score, priority }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-9 text-right font-mono text-sm text-white">{Math.round(score)}</span>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-panel-2">
        <div className="h-full rounded-full" style={{ width: `${score}%`, background: PRIORITY_COLOR[priority] }} />
      </div>
    </div>
  )
}

export function Stat({ label, value, hint, icon: Icon, accent }) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between">
        <span className="label">{label}</span>
        {Icon && <Icon size={16} style={{ color: accent || '#8b8b9e' }} />}
      </div>
      <div className="mt-2 font-display text-3xl font-light text-white" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  )
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-light tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  )
}

export function Loading({ text = 'Carregando...' }) {
  return <div className="py-16 text-center text-sm text-muted">{text}</div>
}

export function ErrorBox({ error }) {
  if (!error) return null
  return (
    <div className="mb-4 rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
      {String(error.message || error)}
    </div>
  )
}

export function Logo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden>
      <defs>
        <linearGradient id="nexus-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#7c3aed" />
          <stop offset="1" stopColor="#3b82f6" />
        </linearGradient>
      </defs>
      <path d="M14 50V14l36 36V14" fill="none" stroke="url(#nexus-g)" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M30 27l4 6-3 2 4 6" fill="none" stroke="url(#nexus-g)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      {[[14, 14], [50, 14], [14, 50], [50, 50]].map(([x, y]) => (
        <circle key={`${x}${y}`} cx={x} cy={y} r="4" fill="#06060a" stroke="url(#nexus-g)" strokeWidth="2.5" />
      ))}
    </svg>
  )
}

export function fmtDate(iso, withTime = true) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString('pt-BR', withTime
    ? { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }
    : { day: '2-digit', month: '2-digit', year: 'numeric' })
}
