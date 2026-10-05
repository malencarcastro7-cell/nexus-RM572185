// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { useEffect, useState } from 'react'
import { Plus, Trash2, Globe, ArrowRight } from 'lucide-react'
import { api } from '../api'
import { useToast } from '../App'
import { DATA_LABEL, ENV_LABEL, ErrorBox, Loading, PageHeader, PRIORITY_COLOR, TYPE_LABEL } from '../components/ui'

const EMPTY = {
  name: '', asset_type: 'webapp', environment: 'production', internet_exposed: false,
  business_criticality: 3, data_classification: 'internal', owner: '', description: '',
}

function Select({ value, onChange, options }) {
  return (
    <select className="input py-1.5 text-xs" value={value} onChange={(e) => onChange(e.target.value)}>
      {Object.entries(options).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
    </select>
  )
}

export default function Assets() {
  const [assets, setAssets] = useState(null)
  const [deps, setDeps] = useState([])
  const [error, setError] = useState(null)
  const [form, setForm] = useState(null)
  const [dep, setDep] = useState({ source_id: '', target_id: '', relation: 'calls' })
  const notify = useToast()

  const load = () => {
    Promise.all([api.assets(), api.dependencies()])
      .then(([a, d]) => { setAssets(a); setDeps(d) })
      .catch(setError)
  }
  useEffect(load, [])

  const update = async (asset, patch) => {
    try {
      await api.updateAsset(asset.id, patch)
      notify(`Contexto de ${asset.name} atualizado. Scores e caminhos de ataque recalculados.`)
      load()
    } catch (e) { notify(e.message, 'error') }
  }

  const create = async (e) => {
    e.preventDefault()
    try {
      await api.createAsset({ ...form, business_criticality: Number(form.business_criticality) })
      notify(`Ativo ${form.name} criado.`)
      setForm(null)
      load()
    } catch (err) { notify(err.message, 'error') }
  }

  const remove = async (asset) => {
    if (!confirm(`Remover ${asset.name} e todas as suas vulnerabilidades?`)) return
    try { await api.deleteAsset(asset.id); load() } catch (e) { notify(e.message, 'error') }
  }

  const addDep = async (e) => {
    e.preventDefault()
    try {
      await api.addDependency({ source_id: Number(dep.source_id), target_id: Number(dep.target_id), relation: dep.relation })
      notify('Dependência adicionada. Grafo de ataque recalculado.')
      setDep({ source_id: '', target_id: '', relation: 'calls' })
      load()
    } catch (err) { notify(err.message, 'error') }
  }

  const removeDep = async (id) => {
    try { await api.deleteDependency(id); notify('Dependência removida.'); load() } catch (e) { notify(e.message, 'error') }
  }

  if (error) return <ErrorBox error={error} />
  if (!assets) return <Loading />
  const name = Object.fromEntries(assets.map((a) => [a.id, a.name]))

  return (
    <>
      <PageHeader title="Ativos e contexto de negócio" subtitle="O mesmo CVE tem riscos diferentes em ativos diferentes. Altere o contexto e veja a priorização mudar.">
        <button className="btn-primary" onClick={() => setForm(EMPTY)}><Plus size={15} /> Novo ativo</button>
      </PageHeader>

      {form && (
        <form onSubmit={create} className="panel mb-6 grid gap-3 p-4 md:grid-cols-4">
          <input className="input md:col-span-2" placeholder="Nome (ex.: app-mobile-api)" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className="input md:col-span-2" placeholder="Responsável" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
          <Select value={form.asset_type} onChange={(v) => setForm({ ...form, asset_type: v })} options={TYPE_LABEL} />
          <Select value={form.environment} onChange={(v) => setForm({ ...form, environment: v })} options={ENV_LABEL} />
          <Select value={form.data_classification} onChange={(v) => setForm({ ...form, data_classification: v })} options={DATA_LABEL} />
          <Select value={form.business_criticality} onChange={(v) => setForm({ ...form, business_criticality: v })} options={{ 1: 'Criticidade 1', 2: 'Criticidade 2', 3: 'Criticidade 3', 4: 'Criticidade 4', 5: 'Criticidade 5' }} />
          <input className="input md:col-span-3" placeholder="Descrição" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" className="accent-violet-500" checked={form.internet_exposed} onChange={(e) => setForm({ ...form, internet_exposed: e.target.checked })} />
            Exposto à internet
          </label>
          <div className="flex gap-2 md:col-span-4">
            <button className="btn-primary" type="submit">Salvar</button>
            <button className="btn-ghost" type="button" onClick={() => setForm(null)}>Cancelar</button>
          </div>
        </form>
      )}

      <div className="mb-8 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {assets.map((a) => (
          <div key={a.id} className="panel flex flex-col p-4">
            <div className="mb-1 flex items-start justify-between gap-2">
              <div>
                <div className="font-medium text-white">{a.name}</div>
                <div className="text-xs text-muted">{TYPE_LABEL[a.asset_type]} · {a.owner || 'sem responsável'}</div>
              </div>
              <button onClick={() => remove(a)} className="text-muted hover:text-rose-400" title="Remover"><Trash2 size={15} /></button>
            </div>
            <p className="mb-3 min-h-8 text-xs text-muted">{a.description}</p>
            <div className="mb-3 flex gap-4 text-xs">
              <span><span className="font-mono text-white">{a.open_findings}</span> <span className="text-muted">acionáveis</span></span>
              <span><span className="font-mono" style={{ color: PRIORITY_COLOR.P1 }}>{a.p1}</span> <span className="text-muted">P1</span></span>
              <span><span className="font-mono text-white">{Math.round(a.max_risk)}</span> <span className="text-muted">risco máx.</span></span>
            </div>
            <div className="mt-auto grid grid-cols-2 gap-2">
              <button
                onClick={() => update(a, { internet_exposed: !a.internet_exposed })}
                className={`col-span-2 flex items-center justify-center gap-2 rounded-lg border px-3 py-1.5 text-xs transition ${
                  a.internet_exposed ? 'border-p1/60 bg-p1/10 text-rose-200' : 'border-line text-muted hover:text-white'
                }`}
              >
                <Globe size={13} /> {a.internet_exposed ? 'Exposto à internet' : 'Somente rede interna'}
              </button>
              <Select value={a.business_criticality} onChange={(v) => update(a, { business_criticality: Number(v) })}
                options={{ 1: 'Criticidade 1/5', 2: 'Criticidade 2/5', 3: 'Criticidade 3/5', 4: 'Criticidade 4/5', 5: 'Criticidade 5/5' }} />
              <Select value={a.data_classification} onChange={(v) => update(a, { data_classification: v })}
                options={Object.fromEntries(Object.entries(DATA_LABEL).map(([k, v]) => [k, `Dados ${v.toLowerCase()}`]))} />
              <div className="col-span-2">
                <Select value={a.environment} onChange={(v) => update(a, { environment: v })} options={ENV_LABEL} />
              </div>
            </div>
          </div>
        ))}
      </div>

      <h2 className="mb-1 text-lg font-light">Dependências entre ativos</h2>
      <p className="mb-4 text-sm text-muted">Arestas do grafo de ataque: quem chama, lê ou escreve em quem.</p>
      <div className="panel p-4">
        <form onSubmit={addDep} className="mb-4 flex flex-wrap items-center gap-2">
          <select className="input" required value={dep.source_id} onChange={(e) => setDep({ ...dep, source_id: e.target.value })}>
            <option value="">Origem</option>
            {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <ArrowRight size={16} className="text-muted" />
          <select className="input" required value={dep.target_id} onChange={(e) => setDep({ ...dep, target_id: e.target.value })}>
            <option value="">Destino</option>
            {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <input className="input w-36" placeholder="relação" value={dep.relation} onChange={(e) => setDep({ ...dep, relation: e.target.value })} />
          <button className="btn-ghost" type="submit"><Plus size={14} /> Adicionar</button>
        </form>
        <div className="space-y-1.5">
          {deps.map((d) => (
            <div key={d.id} className="flex items-center justify-between rounded-md bg-panel-2 px-3 py-2 text-sm">
              <span>
                <span className="text-white">{name[d.source_id]}</span>
                <span className="mx-2 text-xs text-muted">— {d.relation} →</span>
                <span className="text-white">{name[d.target_id]}</span>
              </span>
              <button onClick={() => removeDep(d.id)} className="text-muted hover:text-rose-400"><Trash2 size={14} /></button>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
