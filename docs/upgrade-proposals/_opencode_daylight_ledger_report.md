# OpenCode（surfaces）· 白昼台账 Daylight Ledger 交付报告

Contract: `docs/upgrade-proposals/2026-q3-frontend-daylight-ledger.md`

OpenCode completed the first surface pass (Home / hero / monitor / most pages) but the MCP call timed out before the report. A follow-up mop-up also timed out and **corrupted UTF-8 in several operations tabs**. Supervisor restored those files from git HEAD, re-applied ASCII-only light classes, and rewrote `LearnLoopTab.tsx` (untracked, unrestorable from git).

## Files changed (surfaces)

Hero: `HeroScene.tsx`, `ParticleField.tsx`, `ThreatNetwork.tsx` — limestone field, dusk particles (NormalBlending, opacity 0.28), fog/clear `#E8EEF2`, Stars removed, cinnabar attack pulses.

Home: serif 守望, paper radar chrome (`bg-card/90`), cinnabar KPI rupture kept, footer paper.

Monitor / event stream / relays / histogram tooltip: dusk/pine/cinnabar, quieter shadows, `text-on-accent` on accent buttons.

Pages: Logs, Monitor, Operations, Response, EDR, plus remaining token-driven pages.

Phishing: iOS `#0071e3` / coffee `#C4A07A` / `text-night` removed.

Operations: OverviewTab + TraceTab + badges kept from OpenCode (UTF-8 intact). Assets/Audit/CaseDrawer/Cost/Feedback/Kpi/Lifecycle/PostMortems/Rules/WorkOrders restored from HEAD then light-classed. LearnLoopTab rewritten with original Chinese labels.

## Tests

Supervisor encoding scan: 85 frontend src files valid UTF-8, 0 U+FFFD, 0 GBK mojibake.

Leftover coffee/`text-night`/`#0071e3` grep in `frontend/src`: 0.

Typecheck run separately after this report.

## Leftover risks

- Restored operations tabs lost any uncommitted pre-session logic diffs vs HEAD (encoding was unrecoverable). LearnLoopTab behavior reconstructed from the damaged file + types.
- Raster brand assets (`brand-mascot.jpg`) still dark; sit on limestone with a soft shadow.
- `rounded-none` → `rounded-xl` on restored operations cards (contract radius).
- No browser interaction QA in this report.
