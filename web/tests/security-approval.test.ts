import assert from 'node:assert/strict'
import test from 'node:test'
import { buildApprovalPayload } from '../lib/securityApproval'

const pending = { prompts: [{ type: 'security_approval', approval_id: 'a1', tool: 'str_replace', args: {}, expires_at: Date.now() / 1000 + 300 }] }

test('security decisions bind to the pending approval and edits are explicit', () => {
  assert.deepEqual(buildApprovalPayload(pending, 'approve'), { approval_id: 'a1', decision: 'approve' })
  assert.deepEqual(buildApprovalPayload(pending, 'reject'), { approval_id: 'a1', decision: 'reject' })
  assert.deepEqual(buildApprovalPayload(pending, 'edit', '{"path":"note.txt"}'), { approval_id: 'a1', decision: 'edit', args: { path: 'note.txt' } })
  assert.throws(() => buildApprovalPayload(pending, 'edit', '[]'))
  assert.throws(() => buildApprovalPayload(pending, 'edit', '{bad'))
})

test('expired approvals cannot be submitted', () => {
  assert.throws(() => buildApprovalPayload({ prompts: [{ ...pending.prompts[0], expires_at: 1 }] }, 'approve'))
})

test('official HITL decisions remain compatible', () => {
  assert.deepEqual(buildApprovalPayload({ prompts: [{ action_requests: [{}, {}] }] }, 'reject'), { decisions: [{ type: 'reject' }, { type: 'reject' }] })
})
