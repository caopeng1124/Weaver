'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { ApprovalDecision, securityApprovalFrom, securityLabel } from '@/lib/securityApproval'

export function SecurityApprovalCard({ pending, busy, onDecision }: {
  pending: any
  busy: boolean
  onDecision: (decision: ApprovalDecision, editedJson?: string) => Promise<void>
}) {
  const approval = securityApprovalFrom(pending)
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(JSON.stringify(approval?.args || {}, null, 2))
  const expired = approval && approval.expires_at * 1000 <= Date.now()
  return (
    <div className="mx-4 mb-3 flex flex-col gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4 text-amber-950 dark:bg-amber-950 dark:text-amber-100" role="region" aria-label="工具安全审批">
      <div className="font-semibold">操作需要审批</div>
      {approval ? <>
        <div className="break-all text-sm">工具：{approval.tool}<br />目标：{approval.resource || '已配置的外部服务'}<br />原因：{securityLabel(approval.reason)}</div>
        <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-black/5 p-2 text-xs">{JSON.stringify(approval.args, null, 2)}</pre>
        <p className="text-xs">审批仅适用于这次操作。编辑参数后将重新检查并请求审批。</p>
        {editing && <textarea aria-label="编辑工具参数 JSON" className="min-h-32 rounded border bg-background p-2 font-mono text-xs text-foreground" value={text} onChange={event => setText(event.target.value)} />}
        {expired && <p role="alert">审批已过期，请重新发起操作。</p>}
      </> : <p className="text-sm">{pending.message || pending?.prompts?.[0]?.message || '请确认是否执行待处理操作。'}</p>}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" disabled={busy || !!expired} onClick={() => onDecision('approve')}>批准这次操作</Button>
        <Button size="sm" variant="outline" disabled={busy || !!expired} onClick={() => onDecision('reject')}>拒绝</Button>
        {approval && <Button size="sm" variant="ghost" disabled={busy || !!expired} onClick={() => editing ? onDecision('edit', text) : setEditing(true)}>{editing ? '提交修改并重新检查' : '编辑参数'}</Button>}
      </div>
    </div>
  )
}
