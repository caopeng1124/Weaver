'use client'

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { getApiBaseUrl } from '@/lib/api'
import { sandboxHeaders, sandboxRequest } from '@/lib/localSandbox'

type Session = { id: string; thread: string; profile: string; state: string; provider: string }
type Review = { approval_id: string; digest: string; expires_in: number; changes: {
  path: string; kind: string; diff: string; binary: boolean; sha256: string | null; before_sha256: string | null; size: number
}[] }

export function LocalSandboxPanel({ onSessionChange, chatBusy, threadId }: {
  onSessionChange: (thread: string | null) => void; chatBusy: boolean; threadId: string | null
}) {
  const [token, setToken] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [config, setConfig] = useState<any>(null)
  const [workspace, setWorkspace] = useState('')
  const [profile, setProfile] = useState('sandbox')
  const [session, setSession] = useState<Session | null>(null)
  const [review, setReview] = useState<Review | null>(null)
  const [files, setFiles] = useState<{ path: string; size: number }[]>([])
  const [events, setEvents] = useState<any[]>([])
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [acknowledged, setAcknowledged] = useState(false)

  useEffect(() => {
    setToken(sessionStorage.getItem('weaver.sandboxToken') || '')
    setApiKey(sessionStorage.getItem('weaver.internalApiKey') || '')
  }, [])

  useEffect(() => {
    let active = true
    setSession(null); setReview(null); setFiles([]); setEvents([])
    if (threadId && config && !chatBusy) {
      sandboxRequest(`/sessions?thread_id=${encodeURIComponent(threadId)}`).then(items => {
        if (active) setSession(items[0] || null)
      }).catch(error => { if (active) setMessage(String(error)) })
    }
    return () => { active = false }
  }, [threadId, config, chatBusy])

  async function perform(action: () => Promise<void>) {
    setBusy(true); setMessage('')
    try { await action() } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error))
    } finally { setBusy(false) }
  }

  async function connect() {
    sessionStorage.setItem('weaver.sandboxToken', token.trim())
    sessionStorage.setItem('weaver.internalApiKey', apiKey.trim())
    const next = await sandboxRequest('/config')
    setConfig(next); setProfile(next.default_profile)
  }

  async function create() {
    const next = await sandboxRequest('/sessions', 'POST', { workspace_id: workspace, profile, thread_id: threadId || "" })
    setSession(next); onSessionChange(next.thread); setReview(null); setFiles([])
    setMessage('沙箱已连接到本次聊天。直接描述任务，系统会按需使用导入的文件。')
  }

  async function download(path: string, snapshot?: Review) {
    if (!session) return
    const query = new URLSearchParams({ path })
    if (snapshot) { query.set('approval_id', snapshot.approval_id); query.set('digest', snapshot.digest) }
    const response = await fetch(`${getApiBaseUrl()}/api/local-sandbox/sessions/${session.id}/${snapshot ? 'review/download' : 'download'}?${query}`,
      { headers: sandboxHeaders() })
    if (!response.ok) throw new Error('下载失败')
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a'); link.href = url; link.download = path.split('/').pop() || 'artifact'
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const disabled = busy || chatBusy
  return <details className="mx-4 my-2 max-h-[50vh] shrink-0 overflow-y-auto rounded-lg border bg-background p-3 text-sm">
    <summary className="cursor-pointer font-medium">执行沙箱 · {session ? `${session.provider} · ${session.state}` : '未连接'}</summary>
    <div className="mt-3 space-y-3">
      {!config && <>
        <p className="text-muted-foreground">在项目终端运行 <code>make sandbox-token</code>，复制配对令牌。令牌仅保存在当前浏览器标签页。</p>
        <input aria-label="沙箱配对令牌" type="password" value={token} onChange={e => setToken(e.target.value)}
          className="w-full rounded border bg-background p-2" placeholder="沙箱配对令牌" autoComplete="off" />
        <input aria-label="后端 API key（可选）" type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
          className="w-full rounded border bg-background p-2" placeholder="后端 API key（仅配置了内部鉴权时填写）" autoComplete="off" />
        <Button size="sm" disabled={disabled || !token.trim()} onClick={() => perform(connect)}>连接并检查环境</Button>
      </>}
      {config && !session && <>
        <p>后端：{config.backend} · 网络：{config.network === 'disabled' ? '关闭' : '开启'}</p>
        {config.backend === 'e2b' && <p>当前由管理员选择 E2B。导入文件与执行内容会发送到云端。</p>}
        {!config.diagnostic.available && <p role="alert">{config.diagnostic.error}</p>}
        <label className="block">导入工作区
          <select value={workspace} onChange={e => setWorkspace(e.target.value)} className="ml-2 rounded border bg-background p-2">
            <option value="">空白工作区</option>
            {config.workspaces.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </label>
        <p className="text-xs text-muted-foreground">工作区由 SANDBOX_WORKSPACE_ROOTS 配置。导入副本会排除隐藏文件、凭据、依赖目录和数据库。</p>
        <label className="block">权限
          <select value={profile} onChange={e => setProfile(e.target.value)} className="ml-2 rounded border bg-background p-2">
            <option value="sandbox">沙箱开发：允许执行和修改副本</option>
            <option value="read_only">只读分析：禁止执行和修改</option>
          </select>
        </label>
        <Button size="sm" disabled={disabled || !config.diagnostic.available} onClick={() => perform(create)}>创建沙箱</Button>
        <Button size="sm" variant="ghost" disabled={disabled} onClick={() => perform(async () => setConfig(await sandboxRequest('/config')))}>重新检查</Button>
      </>}
      {session && <>
        <p>权限：{session.profile === 'read_only' ? '只读分析' : '沙箱开发'} · 网络：{config.network === "disabled" ? "关闭" : "开启"} · 文件：独立副本</p>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" disabled={disabled} onClick={() => perform(async () => {
            setFiles(await sandboxRequest(`/sessions/${session.id}/files`))
          })}>查看产物</Button>
          <Button size="sm" disabled={disabled || session.profile === 'read_only' || session.state !== 'active'} onClick={() => perform(async () => {
            setAcknowledged(false); setReview(await sandboxRequest(`/sessions/${session.id}/review`, 'POST'))
          })}>审阅写回本地的更改</Button>
          <Button size="sm" variant="outline" disabled={disabled} onClick={() => perform(async () => {
            setEvents(await sandboxRequest(`/sessions/${session.id}/audit`))
          })}>查看审计记录</Button>
          <Button size="sm" variant="destructive" disabled={busy} onClick={() => perform(async () => {
            await sandboxRequest(`/sessions/${session.id}`, 'DELETE')
            setSession({ ...session, state: 'stopped' }); setReview(null)
            setMessage('沙箱已停止。最近成功保存的产物可在保留期内下载；继续执行请新建聊天。')
          })}>停止并清理</Button>
        </div>
        <p className="text-xs text-muted-foreground">空闲沙箱自动停止。最近保存的产物默认保留 24 小时；切回此聊天可继续下载。</p>
        {files.map(file => <div key={file.path} className="flex justify-between gap-2">
          <span className="break-all">{file.path} · {file.size} bytes</span>
          <button className="underline" onClick={() => perform(() => download(file.path))}>下载</button>
        </div>)}
        {review && <div className="space-y-2 rounded border p-3">
          <p className="font-medium">将影响 {review.changes.length} 个本地文件 · 本次授权 5 分钟内有效</p>
          {review.changes.map(change => <details key={change.path} open className="rounded border p-2">
            <summary>{change.kind} · {change.path} · {change.size} bytes</summary>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">{change.diff}</pre>
            {change.binary && <>
              <p className="break-all text-xs">SHA-256：{change.sha256 || change.before_sha256}</p>
              <button className="underline" disabled={disabled} onClick={() => perform(() => download(change.path, review))}>
                下载本次审阅文件{change.kind === 'delete' ? '（待删除的原文件）' : ''}
              </button>
            </>}
          </details>)}
          <label className="flex gap-2"><input type="checkbox" checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)} />
            我已审阅全部更改，包括删除和二进制文件，允许将它们写回本地。</label>
          <div className="flex gap-2">
            <Button size="sm" disabled={disabled || !acknowledged || !review.changes.length} onClick={() => perform(async () => {
              const result = await sandboxRequest(`/sessions/${session.id}/apply`, 'POST', { approval_id: review.approval_id, digest: review.digest })
              setReview(null); setMessage(`已写回 ${result.applied.length} 个文件。`)
            })}>允许本次写回</Button>
            <Button size="sm" variant="outline" disabled={disabled} onClick={() => perform(async () => {
              await sandboxRequest(`/sessions/${session.id}/reject`, 'POST', { approval_id: review.approval_id, digest: review.digest })
              setReview(null)
            })}>拒绝</Button>
          </div>
        </div>}
        {events.length > 0 && <div className="max-h-48 overflow-auto text-xs">
          {events.map(event => <p key={event.id}>{new Date(event.at * 1000).toLocaleTimeString()} · {event.action} · {event.decision} · {event.reason}</p>)}
        </div>}
      </>}
      {message && <p role="status" className="break-words">{message}</p>}
    </div>
  </details>
}
