import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { deriveRelays } from '../src/lib/agentPipeline.ts'
import { pickThoughtEventId } from '../src/lib/thoughtChain.ts'

function evt(type: string, data: Record<string, unknown>, ts = 1, id = 1) {
  return { id, seq: id, kind: 'event' as const, type, data, ts }
}

describe('deriveRelays', () => {
  it('puts phase=end-only relays into recent, not active', () => {
    const buffer = [
      evt('agent_stage', { event_id: 2712, stage: 'reviewer', phase: 'end', status: 'success' }, 40, 4),
      evt('agent_stage', { event_id: 2712, stage: 'executor', phase: 'end', status: 'success' }, 30, 3),
      evt('agent_stage', { event_id: 2712, stage: 'tool_builder', phase: 'end', status: 'success' }, 20, 2),
      evt('agent_stage', { event_id: 2712, stage: 'decomposer', phase: 'end', status: 'success' }, 10, 1),
    ]
    const { active, recent } = deriveRelays(buffer)
    assert.equal(active.length, 0)
    assert.equal(recent.length, 1)
    assert.equal(recent[0].eventId, 2712)
    assert.equal(recent[0].stages.decomposer, 'success')
    assert.equal(recent[0].done, true)
  })

  it('puts a running stage into active', () => {
    const buffer = [
      evt('agent_stage', { event_id: 9, stage: 'executor', phase: 'start' }, 20, 2),
      evt('agent_stage', { event_id: 9, stage: 'decomposer', phase: 'end', status: 'success' }, 10, 1),
    ]
    const { active, recent } = deriveRelays(buffer)
    assert.equal(active.length, 1)
    assert.equal(recent.length, 0)
    assert.equal(active[0].stages.executor, 'running')
    assert.equal(active[0].done, false)
  })

  it('ignores self-play rows without event_id', () => {
    const buffer = [
      evt('selfplay_match', { match_id: 'sp-e65adc59145b', phase: 'end' }, 5, 1),
    ]
    const { active, recent } = deriveRelays(buffer)
    assert.equal(active.length, 0)
    assert.equal(recent.length, 0)
  })
})

describe('pickThoughtEventId', () => {
  it('prefers audit_complete over agent_stage', () => {
    const buffer = [
      evt('agent_stage', { event_id: 1, stage: 'executor', phase: 'end' }, 30, 3),
      evt('audit_complete', { event_id: 88 }, 20, 2),
      evt('selfplay_round', { match_id: 'sp-x' }, 10, 1),
    ]
    assert.equal(pickThoughtEventId(buffer), 88)
  })

  it('returns 0 when only self-play rows exist', () => {
    const buffer = [evt('selfplay_match', { match_id: 'sp-e65adc59145b', phase: 'end' })]
    assert.equal(pickThoughtEventId(buffer), 0)
  })
})
