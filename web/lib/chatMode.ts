export type ChatMode = 'auto' | 'ultra'

export function toSearchMode(mode: ChatMode) {
  return mode === 'ultra'
    ? { useAgent: true, useDeepSearch: true }
    : { autoRoute: true }
}
