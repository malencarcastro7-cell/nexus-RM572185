// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { useEffect, useState } from 'react'
import { X, Sparkles, RefreshCw, Copy, Check, ShieldCheck, ExternalLink, Info } from 'lucide-react'
import { api } from '../api'
import { useToast } from '../App'
import {
  CATEGORY_LABEL, ErrorBox, FindingTags, Loading, PRIORITY_COLOR, PRIORITY_LABEL, PriorityBadge,
  SCANNER_LABEL, SeverityDot, STATUS_LABEL, fmtDate,
} from './ui'

function CodeBlock({ code, language }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <div className="relative">
      <div className="absolute right-2 top-2 flex items-center gap-2">
        <span className="font-mono text-[10px] uppercase text-muted">{language}</span>
        <button onClick={copy} className="rounded p-1 text-muted hover:bg-panel-2 hover:text-white" title="Copiar">
          {copied ? <Check size={13} /> : <Copy size={13} />}
        </button>
      </div>
      <pre className="code pr-20">{code}</pre>
    </div>
  )
}

function RiskBreakdown({ factors, score, priority }) {
  const positive = factors.filter((f) => f.points > 0)
  const total = positive.reduce((a, f) => a + f.points, 0) || 1
  const colors = ['#7c3aed', '#f43f5e', '#3b82f6', '#22d3ee', '#a78bfa', '#f472b6']
  return (
    <div>
      <div className="mb-3 flex h-2.5 overflow-hidden rounded-full bg-panel-2">
        {positive.map((f, i) => (
          <div key={f.label} style={{ width: `${(f.points / total) * Math.min(score, 100)}%`, background: colors[i % colors.length] }} title={f.label} />
        ))}
      </div>
      <div className="space-y-1.5">
        {factors.map((f, i) => (
          <div key={f.label} className="flex items-start justify-between gap-3 text-sm">
            <div className="flex items-start gap-2">
              <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: f.points > 0 ? colors[positive.indexOf(f) % colors.length] : '#3a3a48' }} />
              <div>
                <span className="text-white">{f.label}</span>
                <span className="ml-2 text-xs text-muted">{f.detail}</span>
              </div>
            </div>
            <span className={`shrink-0 font-mono text-xs ${f.points < 0 ? 'text-emerald-300' : 'text-soft'}`}>
              {f.points > 0 ? '+' : ''}{f.points}
            </span>
          </div>
        ))}
        <div className="flex justify-between border-t border-line pt-2 text-sm">
          <span className="text-white">Score de risco contextual</span>
          <span className="font-mono" style={{ color: PRIORITY_COLOR[priority] }}>{score} → {priority} ({PRIORITY_LABEL[priority]})</span>
        </div>
      </div>
    </div>
  )
}

function AiPanel({ finding, onUpdated }) {
  const [data, setData] = useState(finding.ai_explanation)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => { setData(finding.ai_explanation) }, [finding.id, finding.ai_explanation])

  const run = async (force) => {
    setLoading(true); setError(null)
    try {
      const res = await api.explain(finding.id, force)
      setData(res)
      onUpdated?.()
    } catch (e) { setError(e) } finally { setLoading(false) }
  }

  return (
    <section className="rounded-xl border border-violet/40 bg-gradient-to-b from-violet/10 to-transparent p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium text-violet-200"><Sparkles size={16} /> IA de remediação</div>
        {data && (
          <button className="btn-ghost py-1 text-xs" onClick={() => run(true)} disabled={loading}>
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Regerar
          </button>
        )}
      </div>
      <ErrorBox error={error} />
      {!data && (
        <div className="text-sm">
          <p className="mb-3 text-muted">
            A IA explica o que é a falha, por que é perigosa <em>neste</em> ativo, como corrigir e dá um exemplo de código seguro.
            Ela recomenda, mas não aplica nada automaticamente.
          </p>
          <button className="btn-primary" onClick={() => run(false)} disabled={loading}>
            {loading ? <RefreshCw size={15} className="animate-spin" /> : <Sparkles size={15} />}
            {loading ? 'Analisando...' : 'Explicar com IA'}
          </button>
        </div>
      )}
      {data && (
        <div className="space-y-4 text-sm leading-relaxed">
          <div><div className="label mb-1">O que é</div><p>{data.o_que_e}</p></div>
          <div><div className="label mb-1">Por que é perigosa aqui</div><p>{data.por_que_perigoso}</p></div>
          {data.cenario_ataque && <div><div className="label mb-1">Cenário de ataque</div><p>{data.cenario_ataque}</p></div>}
          <div>
            <div className="label mb-1">Como corrigir</div>
            <ol className="space-y-1">
              {data.como_corrigir?.map((s, i) => (
                <li key={i} className="flex gap-2"><span className="font-mono text-violet-300">{i + 1}.</span><span>{s}</span></li>
              ))}
            </ol>
          </div>
          {data.exemplo_codigo?.code && (
            <div><div className="label mb-1">Exemplo de código seguro</div><CodeBlock {...data.exemplo_codigo} /></div>
          )}
          {data.esforco_estimado && <p className="text-xs text-muted">Esforço estimado: {data.esforco_estimado}</p>}
          {data.referencias && (
            <div className="flex flex-wrap gap-1.5 text-xs">
              <span className="rounded border border-line bg-panel-2 px-2 py-0.5">{data.referencias.cwe} · {data.referencias.cwe_nome}</span>
              <span className="rounded border border-line bg-panel-2 px-2 py-0.5">OWASP {data.referencias.owasp}</span>
              {data.referencias.mitre_attack?.map((t) => (
                <span key={t.id} className="rounded border border-line bg-panel-2 px-2 py-0.5">ATT&CK {t.id} · {t.name}</span>
              ))}
            </div>
          )}
          <div className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-2.5 text-xs text-emerald-200">
            <ShieldCheck size={14} className="mt-0.5 shrink-0" />
            Recomendação apenas. Nenhuma alteração foi aplicada; o controle permanece com o time de segurança.
          </div>
          {data.nota && <p className="flex gap-1.5 text-xs text-orange-300"><Info size={13} className="mt-0.5" />{data.nota}</p>}
          <p className="text-[11px] text-muted">
            {data.provider === 'offline' ? 'Base de conhecimento local (RAG)' : `${data.provider} · ${data.model}`} · {fmtDate(data.generated_at)}
          </p>
        </div>
      )}
    </section>
  )
}

export default function FindingDrawer({ id, onClose, onChanged }) {
  const [f, setF] = useState(null)
  const [error, setError] = useState(null)
  const notify = useToast()

  const load = () => api.finding(id).then(setF).catch(setError)
  useEffect(() => { setF(null); load() }, [id]) // eslint-disable-line react-hooks/exhaustive-deps

  const changeStatus = async (status) => {
    try {
      const updated = await api.setStatus(id, status)
      setF(updated)
      notify(`Status alterado para "${STATUS_LABEL[status]}". Risco recalculado.`)
      onChanged?.()
    } catch (e) { notify(e.message, 'error') }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/60" onClick={onClose}>
      <div className="h-full w-full max-w-2xl overflow-y-auto border-l border-line bg-ink p-6" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex justify-end">
          <button className="text-muted hover:text-white" onClick={onClose}><X size={20} /></button>
        </div>
        <ErrorBox error={error} />
        {!f && !error && <Loading />}
        {f && (
          <div className="space-y-6">
            <div>
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <PriorityBadge priority={f.priority} large />
                <span className="font-mono text-sm text-muted">{f.vuln_id}</span>
                <SeverityDot severity={f.severity} />
                <span className="text-xs text-muted">CVSS {f.cvss}</span>
              </div>
              <h2 className="text-xl font-light leading-snug">{f.title}</h2>
              <p className="mt-1 text-sm text-muted">
                {f.asset} · {CATEGORY_LABEL[f.category]} {f.cwe && `· ${f.cwe}`}
              </p>
              <div className="mt-3"><FindingTags f={f} /></div>
              {f.fp_suspected && (
                <p className="mt-3 rounded-lg border border-line bg-panel-2 p-3 text-xs">
                  <span className="text-white">Provável falso positivo:</span> {f.fp_reason} O score foi reduzido; confirme ou reabra pela triagem abaixo.
                </p>
              )}
            </div>

            <section className="panel p-4">
              <div className="label mb-3">Por que esta prioridade</div>
              <RiskBreakdown factors={f.risk_factors} score={f.risk_score} priority={f.priority} />
            </section>

            <AiPanel finding={f} onUpdated={load} />

            <section className="panel p-4 text-sm">
              <div className="label mb-3">Detalhes técnicos</div>
              <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-2">
                {f.package && (<><dt className="text-muted">Componente</dt><dd className="font-mono text-white">{f.package}</dd></>)}
                {f.installed_version && (<><dt className="text-muted">Versão instalada</dt><dd className="font-mono">{f.installed_version}</dd></>)}
                {f.fixed_version && (<><dt className="text-muted">Versão corrigida</dt><dd className="font-mono text-emerald-300">{f.fixed_version}</dd></>)}
                <dt className="text-muted">Local</dt><dd className="break-all font-mono text-xs">{f.location}</dd>
                <dt className="text-muted">Detectada por</dt><dd>{f.sources.map((s) => SCANNER_LABEL[s] || s).join(', ')}</dd>
                <dt className="text-muted">Primeira detecção</dt><dd>{fmtDate(f.first_seen)}</dd>
                <dt className="text-muted">Última detecção</dt><dd>{fmtDate(f.last_seen)}</dd>
              </dl>
              {f.description && <p className="mt-4 whitespace-pre-line text-xs leading-relaxed text-muted">{f.description.slice(0, 900)}</p>}
              {f.references?.length > 0 && (
                <div className="mt-3 flex flex-col gap-1">
                  {f.references.map((r) => (
                    <a key={r} href={r} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-violet-300 hover:text-white">
                      <ExternalLink size={11} /> {r}
                    </a>
                  ))}
                </div>
              )}
            </section>

            <section className="panel p-4 text-sm">
              <div className="label mb-3">Ocorrências consolidadas ({f.occurrences.length})</div>
              <div className="space-y-1.5">
                {f.occurrences.map((o, i) => (
                  <div key={i} className="flex items-center justify-between gap-3 rounded-md bg-panel-2 px-3 py-1.5 text-xs">
                    <span className="w-20 shrink-0 text-white">{SCANNER_LABEL[o.scanner] || o.scanner}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-muted" title={o.location}>{o.location}</span>
                    <span className="shrink-0 text-muted">{fmtDate(o.seen_at, false)}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="panel p-4">
              <div className="label mb-3">Triagem</div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(STATUS_LABEL).map(([k, label]) => (
                  <button
                    key={k}
                    onClick={() => changeStatus(k)}
                    className={`rounded-lg border px-3 py-1.5 text-xs transition ${
                      f.status === k ? 'border-violet bg-violet/20 text-white' : 'border-line text-muted hover:text-white'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  )
}
