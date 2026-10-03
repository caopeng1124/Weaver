import assert from 'node:assert/strict'
import test from 'node:test'
import { toSearchMode } from '../lib/chatMode'

test('normal chat asks the backend router to select search and tools', () => {
  assert.deepEqual(toSearchMode('auto'), { autoRoute: true })
})

test('Deep Research keeps an explicit deep research request', () => {
  assert.deepEqual(toSearchMode('ultra'), { useAgent: true, useDeepSearch: true })
})
