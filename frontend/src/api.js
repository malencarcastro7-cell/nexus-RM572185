// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Equipe NEXUS
// NEXUS - Application Security Posture Management orientado por IA.
// Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.

const BASE = import.meta.env.VITE_API_URL || ''

async function request(path, options = {}) {
  const res = await fetch(BASE + path, options)
  if (res.status === 204) return null
  const isJson = res.headers.get('content-type')?.includes('application/json')
  const body = isJson ? await res.json() : await res.text()
  if (!res.ok) {
    const detail = isJson ? body.detail : body
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return body
}

const json = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export const api = {
  dashboard: () => request('/api/dashboard'),
  findings: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== '' && v != null && v !== false))
    return request(`/api/findings?${q}`)
  },
  finding: (id) => request(`/api/findings/${id}`),
  setStatus: (id, status) => request(`/api/findings/${id}`, json('PATCH', { status })),
  explain: (id, force = false) => request(`/api/findings/${id}/explain${force ? '?force=true' : ''}`, { method: 'POST' }),
  exportCsvUrl: (includeFp) => `${BASE}/api/findings/export.csv${includeFp ? '?include_fp=true' : ''}`,
  assets: () => request('/api/assets'),
  createAsset: (data) => request('/api/assets', json('POST', data)),
  updateAsset: (id, data) => request(`/api/assets/${id}`, json('PATCH', data)),
  deleteAsset: (id) => request(`/api/assets/${id}`, { method: 'DELETE' }),
  dependencies: () => request('/api/dependencies'),
  addDependency: (data) => request('/api/dependencies', json('POST', data)),
  deleteDependency: (id) => request(`/api/dependencies/${id}`, { method: 'DELETE' }),
  attackPaths: () => request('/api/attack-paths'),
  scanners: () => request('/api/scanners'),
  imports: () => request('/api/imports'),
  upload: (file, assetId, scanner) => {
    const form = new FormData()
    form.append('file', file)
    form.append('asset_id', assetId)
    if (scanner && scanner !== 'auto') form.append('scanner', scanner)
    return request('/api/imports', { method: 'POST', body: form })
  },
  executiveSummary: () => request('/api/ai/executive-summary', { method: 'POST' }),
  resetDemo: () => request('/api/demo/reset', { method: 'POST' }),
  health: () => request('/api/health'),
}
