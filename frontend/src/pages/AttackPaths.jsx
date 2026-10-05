// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Globe, Database, Server, Boxes, Network, Container, Flame, Bug, ChevronRight, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import { DATA_LABEL, ErrorBox, Loading, PageHeader } from '../components/ui'

const ICON = { internet: Globe, database: Database, api: Network, webapp: Boxes, service: Server, container: Container }
const NODE_W = 168, NODE_H = 58, COL_GAP = 92, ROW_GAP = 34, PAD = 20

function layout(nodes, edges) {
  // Camadas: Internet na coluna 0; cada ativo fica uma coluna depois do seu antecessor mais distante.
  const preds = new Map(nodes.map((n) => [n.id, []]))
  edges.forEach((e) => preds.get(e.target)?.push(e.source))
  const depth = new Map([[0, 0]])
  for (let iter = 0; iter < nodes.length + 1; iter++) {
    nodes.forEach((n) => {
      if (n.id === 0) return
      const p = preds.get(n.id)
      const d = p.length ? 1 + Math.max(...p.map((s) => depth.get(s) ?? 0)) : 1
      depth.set(n.id, Math.min(d, nodes.length))
    })
  }
  const cols = new Map()
  nodes.forEach((n) => {
    const d = depth.get(n.id)
    if (!cols.has(d)) cols.set(d, [])
    cols.get(d).push(n)
  })
  const maxRows = Math.max(...[...cols.values()].map((c) => c.length))
  const height = PAD * 2 + maxRows * NODE_H + (maxRows - 1) * ROW_GAP
  const pos = new Map()
  ;[...cols.entries()].forEach(([d, list]) => {
    const colH = list.length * NODE_H + (list.length - 1) * ROW_GAP
    list.forEach((n, i) => {
      pos.set(n.id, { x: PAD + d * (NODE_W + COL_GAP), y: (height - colH) / 2 + i * (NODE_H + ROW_GAP) })
    })
  })
  const width = PAD * 2 + (Math.max(...cols.keys()) + 1) * NODE_W + Math.max(...cols.keys()) * COL_GAP
  return { pos, width, height }
}

function Graph({ nodes, edges, highlight }) {
  const { pos, width, height } = useMemo(() => layout(nodes, edges), [nodes, edges])
  const onPath = new Set(highlight?.steps.map((s) => s.asset_id) || [])
  if (highlight) onPath.add(0)
  const pathEdges = new Set()
  if (highlight) {
    const ids = [0, ...highlight.steps.map((s) => s.asset_id)]
    ids.slice(1).forEach((id, i) => pathEdges.add(`${ids[i]}-${id}`))
  }
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} style={{ minWidth: width * 0.75 }} className="w-full">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill="#4a4a5c" />
          </marker>
          <marker id="arrow-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill="#f43f5e" />
          </marker>
        </defs>
        {edges.map((e) => {
          const a = pos.get(e.source), b = pos.get(e.target)
          if (!a || !b) return null
          const hot = pathEdges.has(`${e.source}-${e.target}`)
          const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2
          const mx = (x1 + x2) / 2
          return (
            <g key={`${e.source}-${e.target}`}>
              <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2 - 2},${y2}`} fill="none"
                stroke={hot ? '#f43f5e' : '#33333f'} strokeWidth={hot ? 2.5 : 1.5}
                strokeDasharray={hot ? '7 5' : undefined} markerEnd={`url(#${hot ? 'arrow-hot' : 'arrow'})`}>
                {hot && <animate attributeName="stroke-dashoffset" from="24" to="0" dur="1s" repeatCount="indefinite" />}
              </path>
              <text x={mx} y={(y1 + y2) / 2 - 6} textAnchor="middle" fontSize="10" fill="#6b6b7e">{e.relation}</text>
            </g>
          )
        })}
        {nodes.map((n) => {
          const p = pos.get(n.id)
          const Icon = ICON[n.asset_type] || Server
          const hot = onPath.has(n.id)
          const jewel = n.asset_type === 'database' || n.data_classification === 'restricted'
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <rect width={NODE_W} height={NODE_H} rx="10"
                fill={hot ? '#2a0f18' : '#111119'} stroke={hot ? '#f43f5e' : jewel ? '#7c3aed' : '#2a2a36'} strokeWidth={hot ? 2 : 1.2} />
              <foreignObject x="10" y="10" width="24" height="24">
                <Icon size={20} color={hot ? '#fda4af' : n.id === 0 ? '#60a5fa' : '#a1a1b5'} />
              </foreignObject>
              <text x="40" y="25" fontSize="13" fill="#fff" fontFamily="Inter">{n.name}</text>
              <text x="40" y="43" fontSize="10.5" fill="#8b8b9e" fontFamily="Inter">
                {n.id === 0 ? 'origem do atacante' : `${jewel ? 'joia da coroa · ' : ''}crit. ${n.business_criticality}/5${n.internet_exposed ? ' · exposto' : ''}`}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

export default function AttackPaths() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [active, setActive] = useState(0)
  const navigate = useNavigate()

  useEffect(() => { api.attackPaths().then(setData).catch(setError) }, [])

  if (error) return <ErrorBox error={error} />
  if (!data) return <Loading />
  const current = data.paths[active]

  return (
    <>
      <PageHeader
        title="Attack Path Analysis"
        subtitle="Grafo de ataque: exposição externa → dependências → joias da coroa. Um caminho só é viável se cada salto tiver uma falha explorável."
      />
      <div className="panel mb-6 p-4">
        <Graph nodes={data.nodes} edges={data.edges} highlight={current} />
        <div className="mt-2 flex flex-wrap gap-4 text-xs text-muted">
          <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded border-2 border-p1" /> Caminho selecionado</span>
          <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded border-2 border-violet" /> Joia da coroa (banco ou dados restritos)</span>
        </div>
      </div>

      {data.paths.length === 0 ? (
        <div className="panel flex items-center gap-3 p-6 text-sm">
          <ShieldCheck className="text-emerald-400" /> Nenhum caminho de ataque viável da internet até sistemas críticos.
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-2">
            {data.paths.map((p, i) => (
              <button key={p.id} onClick={() => setActive(i)}
                className={`panel w-full p-4 text-left transition ${i === active ? 'border-p1/70 bg-[#1a0c12]' : 'hover:border-[#3a3a48]'}`}>
                <div className="flex items-center justify-between">
                  <span className="label">Caminho #{p.id}</span>
                  <span className="font-mono text-xs text-p1">{Math.round(p.probability * 100)}% prob.</span>
                </div>
                <div className="mt-1 text-sm text-white">{p.entry} → {p.target}</div>
                <div className="mt-1 text-xs text-muted">{p.length} saltos · dados {DATA_LABEL[p.target_classification]?.toLowerCase()}</div>
              </button>
            ))}
          </div>
          <div className="panel p-5 lg:col-span-2">
            <div className="mb-4 grid grid-cols-3 gap-3">
              <div className="rounded-lg bg-panel-2 p-3">
                <div className="label">Prob. de comprometimento</div>
                <div className="mt-1 font-display text-2xl font-light text-p1">{Math.round(current.probability * 100)}%</div>
              </div>
              <div className="rounded-lg bg-panel-2 p-3">
                <div className="label">Impacto no negócio</div>
                <div className="mt-1 font-display text-2xl font-light text-white">{current.impact}/5</div>
              </div>
              <div className="rounded-lg bg-panel-2 p-3">
                <div className="label">Risco do caminho</div>
                <div className="mt-1 font-display text-2xl font-light text-white">{current.risk_score}</div>
              </div>
            </div>
            <p className="mb-5 rounded-lg border border-line bg-panel-2 p-3 text-sm leading-relaxed">{current.narrative}</p>
            <ol className="space-y-3">
              {current.steps.map((s, i) => (
                <li key={s.asset_id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <span className={`flex h-7 w-7 items-center justify-center rounded-full text-xs ${s.is_target ? 'bg-violet text-white' : 'bg-p1/20 text-p1'}`}>{i + 1}</span>
                    {i < current.steps.length - 1 && <span className="mt-1 w-px flex-1 bg-line" />}
                  </div>
                  <div className="flex-1 pb-2">
                    <div className="text-sm text-white">{s.asset_name} <span className="text-xs text-muted">· {s.relation}</span></div>
                    {s.is_target ? (
                      <div className="mt-1 text-xs text-violet-300">Alvo final: dados {DATA_LABEL[current.target_classification]?.toLowerCase()}</div>
                    ) : (
                      <button onClick={() => navigate(`/vulnerabilidades?id=${s.finding.id}`)}
                        className="mt-1.5 flex w-full items-center justify-between rounded-lg border border-line bg-panel-2 px-3 py-2 text-left text-xs hover:border-p1/60">
                        <span className="min-w-0">
                          <span className="font-mono text-white">{s.finding.vuln_id}</span>
                          <span className="ml-2 text-muted">{s.finding.title.slice(0, 70)}</span>
                        </span>
                        <span className="ml-2 flex shrink-0 items-center gap-2">
                          {s.finding.exploit_known ? <Flame size={12} className="text-p1" /> : s.finding.exploit_public ? <Bug size={12} className="text-orange-300" /> : null}
                          <span className="font-mono text-p1">{Math.round(s.finding.probability * 100)}%</span>
                          <ChevronRight size={13} className="text-muted" />
                        </span>
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ol>
            <p className="mt-2 text-xs text-muted">Corrigir qualquer falha de um salto quebra o caminho inteiro. Comece pela de menor esforço.</p>
          </div>
        </div>
      )}
    </>
  )
}
