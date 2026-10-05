// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import { useEffect, useRef, useState } from 'react'
import { FileJson, Upload, RefreshCw, CircleCheck } from 'lucide-react'
import { api } from '../api'
import { useToast } from '../App'
import { ErrorBox, Loading, PageHeader, SCANNER_LABEL, fmtDate } from '../components/ui'

export default function Imports() {
  const [assets, setAssets] = useState([])
  const [scanners, setScanners] = useState([])
  const [history, setHistory] = useState(null)
  const [error, setError] = useState(null)
  const [file, setFile] = useState(null)
  const [assetId, setAssetId] = useState('')
  const [scanner, setScanner] = useState('auto')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [drag, setDrag] = useState(false)
  const inputRef = useRef()
  const notify = useToast()

  const load = () => {
    Promise.all([api.assets(), api.scanners(), api.imports()])
      .then(([a, s, h]) => { setAssets(a); setScanners(s); setHistory(h) })
      .catch(setError)
  }
  useEffect(load, [])

  const submit = async (e) => {
    e.preventDefault()
    if (!file || !assetId) return
    setBusy(true); setResult(null)
    try {
      const r = await api.upload(file, assetId, scanner)
      setResult(r)
      notify(`Relatório ${SCANNER_LABEL[r.scanner]} importado e correlacionado.`)
      setFile(null)
      load()
    } catch (err) { notify(err.message, 'error') } finally { setBusy(false) }
  }

  const resetDemo = async () => {
    if (!confirm('Apagar todos os dados e recarregar o ambiente de demonstração?')) return
    setBusy(true)
    try { await api.resetDemo(); notify('Ambiente de demonstração restaurado.'); setResult(null); load() }
    catch (e) { notify(e.message, 'error') } finally { setBusy(false) }
  }

  return (
    <>
      <PageHeader title="Central de ingestão" subtitle="Recebe relatórios JSON dos scanners, normaliza em um padrão único e correlaciona com o que já existe">
        <button className="btn-ghost" onClick={resetDemo} disabled={busy}><RefreshCw size={15} /> Restaurar demonstração</button>
      </PageHeader>
      <ErrorBox error={error} />

      <div className="mb-6 grid gap-4 lg:grid-cols-5">
        <form onSubmit={submit} className="panel space-y-3 p-5 lg:col-span-3">
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); setFile(e.dataTransfer.files[0]) }}
            className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-10 text-center transition ${
              drag ? 'border-violet bg-violet/10' : 'border-line hover:border-[#3a3a48]'
            }`}
          >
            <FileJson size={30} className="mb-2 text-violet-300" />
            {file ? (
              <span className="text-sm text-white">{file.name} <span className="text-muted">({Math.round(file.size / 1024)} KB)</span></span>
            ) : (
              <>
                <span className="text-sm text-white">Arraste o relatório JSON aqui ou clique para escolher</span>
                <span className="mt-1 text-xs text-muted">Trivy · Snyk · OWASP ZAP · SonarQube (formato detectado automaticamente)</span>
              </>
            )}
            <input ref={inputRef} type="file" accept=".json,application/json" className="hidden" onChange={(e) => setFile(e.target.files[0])} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <select className="input" required value={assetId} onChange={(e) => setAssetId(e.target.value)}>
              <option value="">Ativo analisado...</option>
              {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
            <select className="input" value={scanner} onChange={(e) => setScanner(e.target.value)}>
              <option value="auto">Detectar formato automaticamente</option>
              {scanners.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
          <button className="btn-primary w-full justify-center" disabled={!file || !assetId || busy}>
            {busy ? <RefreshCw size={15} className="animate-spin" /> : <Upload size={15} />} Importar e correlacionar
          </button>

          {result && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 text-sm">
              <div className="mb-3 flex items-center gap-2 text-emerald-200"><CircleCheck size={16} /> {SCANNER_LABEL[result.scanner]} → {result.asset}</div>
              <div className="grid grid-cols-4 gap-2 text-center">
                {[['Alertas brutos', result.raw_count], ['Novas', result.new_findings], ['Consolidadas', result.merged_findings], ['Corrigidas', result.auto_resolved]].map(([l, v]) => (
                  <div key={l} className="rounded-md bg-panel-2 p-2">
                    <div className="font-display text-xl font-light text-white">{v}</div>
                    <div className="text-[11px] text-muted">{l}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </form>

        <div className="panel p-5 lg:col-span-2">
          <h2 className="mb-3 text-base font-normal">Como gerar os relatórios</h2>
          <div className="space-y-3">
            {scanners.map((s) => (
              <div key={s.id}>
                <div className="text-sm text-white">{s.name} <span className="text-xs text-muted">· {s.category}</span></div>
                <code className="mt-1 block overflow-x-auto rounded-md bg-ink px-2 py-1.5 font-mono text-[11px] text-[#d6d6ff]">{s.command}</code>
              </div>
            ))}
            <div>
              <div className="text-sm text-white">Integração CI/CD</div>
              <code className="mt-1 block overflow-x-auto whitespace-pre rounded-md bg-ink px-2 py-1.5 font-mono text-[11px] text-[#d6d6ff]">{'curl -F "file=@trivy.json" \\\n     -F "asset_id=2" \\\n     http://nexus:8000/api/imports'}</code>
            </div>
          </div>
        </div>
      </div>

      <h2 className="mb-3 text-lg font-light">Histórico de importações</h2>
      {!history ? <Loading /> : (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[700px] text-sm">
            <thead className="border-b border-line text-left text-xs text-muted">
              <tr>
                <th className="px-4 py-3 font-normal">Data</th><th className="font-normal">Scanner</th><th className="font-normal">Ativo</th>
                <th className="font-normal">Arquivo</th><th className="font-normal">Brutos</th><th className="font-normal">Novas</th>
                <th className="font-normal">Consolidadas</th><th className="px-4 font-normal">Corrigidas</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id} className="border-b border-line/60">
                  <td className="px-4 py-2.5 text-muted">{fmtDate(h.imported_at)}</td>
                  <td className="text-white">{SCANNER_LABEL[h.scanner]}</td>
                  <td>{h.asset}</td>
                  <td className="font-mono text-xs text-muted">{h.filename}</td>
                  <td className="font-mono">{h.raw_count}</td>
                  <td className="font-mono">{h.new_findings}</td>
                  <td className="font-mono">{h.merged_findings}</td>
                  <td className="px-4 font-mono text-emerald-300">{h.auto_resolved || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
