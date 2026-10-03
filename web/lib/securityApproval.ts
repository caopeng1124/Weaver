export type ApprovalDecision = 'approve' | 'reject' | 'edit'

const securityLabels: Record<string, string> = {
  policy_decision: '权限检查', execution_started: '开始执行', execution_completed: '执行完成',
  approval_consumed: '审批已处理', injection_detected: '发现可疑指令', redacted: '敏感信息已脱敏', blocked: '已拦截',
  workspace_write: '此操作将修改工作区文件', configured_mcp: '此操作将调用已配置的外部工具',
  sensitive_arguments: '参数包含敏感信息', sensitive_content: '内容包含敏感信息', sensitive_file: '文件包含敏感信息',
  file_unavailable: '文件不可用', file_too_large: '文件超出大小限制', file_scope_denied: '文件超出允许范围',
  destination_denied: '网络地址不在允许范围内', scoped_read: '允许范围内的读取',
  untrusted_content_write_restricted: '检测到可疑外部指令，已限制文件修改',
  untrusted_content_mcp_restricted: '检测到可疑外部指令，已限制外部工具',
  tool_not_authorized: '工具未获得授权', invalid_mcp_policy: '外部工具策略配置无效',
  allow: '允许', deny: '拒绝', require_approval: '等待审批', approve: '已批准', reject: '已拒绝', edit: '已修改',
  quarantined: '已隔离', flagged: '已标记风险',
  instruction_override: '要求覆盖原有指令', role_spoofing: '冒充系统或开发者',
  credential_exfiltration: '要求泄露凭据', persistent_instruction: '试图植入长期指令',
}

export function securityLabel(value: unknown): string {
  const code = typeof value === 'string' ? value : ''
  return securityLabels[code] || code
}

export interface SecurityApproval {
  type: 'security_approval'
  approval_id: string
  tool: string
  args: Record<string, unknown>
  resource?: string
  reason: string
  expires_at: number
}

export function securityApprovalFrom(pending: any): SecurityApproval | undefined {
  return pending?.prompts?.find((item: any) => item?.type === 'security_approval')
}

export function buildApprovalPayload(pending: any, decision: ApprovalDecision, editedJson?: string) {
  const security = securityApprovalFrom(pending)
  if (security) {
    if (security.expires_at * 1000 <= Date.now()) throw new Error('审批已过期，请重新发起操作。')
    const payload: Record<string, unknown> = { approval_id: security.approval_id, decision }
    if (decision === 'edit') {
      const args = JSON.parse(editedJson || '{}')
      if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('参数必须是 JSON 对象。')
      payload.args = args
    }
    return payload
  }
  if (decision === 'edit') throw new Error('此审批不支持编辑。')
  const prompt = pending?.prompts?.[0]
  if (Array.isArray(prompt?.action_requests)) {
    return { decisions: prompt.action_requests.map(() => ({ type: decision })) }
  }
  return { tool_approved: decision === 'approve', tool_calls: prompt?.tool_calls }
}
