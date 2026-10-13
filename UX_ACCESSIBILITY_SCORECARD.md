# VaultX UX and accessibility scorecard

## Scope

Reviewed the current Next.js App Router UI after the transfer, guest-link, MFA, workspace-context, and token-system changes. This is an engineering scorecard, not a WCAG conformance certificate; browser, screen-reader, zoom, keyboard-only, and device testing still need to be performed against a deployed build.

## Scorecard

| Area | Rating | Evidence | Remaining validation |
|---|---:|---|---|
| Visual hierarchy | 4/5 | Slate/ink foundation, emerald reserved for secure states, 1px borders, no elevation-dependent meaning, dense transfer and link summaries | Review at 200% zoom and on real 320px/768px layouts |
| Information scannability | 4/5 | Transfer grid exposes percent, bytes, measured average speed and ETA; status text is separate from controls; guest links expose lifecycle, limits, expiry and access-code state | Validate very long filenames, locales and 10+ simultaneous transfers |
| Responsive behavior | 4/5 | Responsive shell/sidebar, wrapping control groups, full-width mobile actions, bounded URL fields, dense two-column-to-one-column workspace hub | Manual browser review at 320, 375, 768, 1024 and 1440 CSS px |
| Keyboard access | 4/5 | Skip link, visible focus, semantic single-input OTP deck, button targets at least 44px, keyboard file drop trigger, labeled icon controls | Run a full keyboard journey through Radix dialogs/dropdowns and guest-link revocation |
| Screen-reader structure | 4/5 | Live status regions, `role=meter` allocation states, descriptive labels, error alerts, one semantic OTP input instead of six competing fields | Test NVDA/Firefox, VoiceOver/Safari and JAWS/Chrome; validate announcement frequency during transfers |
| Color and contrast | 4/5 | Token tests cover body text at 7:1 and control/focus boundaries at 3:1 in light/dark themes | Verify rendered anti-aliasing and non-text status cues in browser screenshots |
| Motion | 4/5 | Motion is constrained to 150–200ms cubic-bezier transitions with reduced-motion overrides | Validate Radix/third-party animation paths and OS preference in browser |
| Error/empty/loading states | 4/5 | Auth, upload preparation, transfer failure/abort, guest-link load/create/revoke, allocation unavailable/over-quota states are explicit | Add product-specific recovery copy review and network/offline simulation |
| Truthfulness | 5/5 | Unsupported passkeys, tenant switching and quotas are explicitly unavailable; speed/ETA remain unavailable until measured; no fabricated Acme/usage data | Connect authoritative backend adapters before exposing organization features |

## Design gaps and layout risks

1. **WCAG AAA is a target, not a completed claim.** Automated contrast and semantic tests pass, but AAA includes more than color contrast. Browser/device and assistive-technology validation is still required.
2. **Backend capability gaps are visible by design.** There are no WebAuthn endpoints, tenant membership APIs, or quota APIs. The UI shows a truthful unavailable state rather than a non-functional control or invented allocation.
3. **Transfer controls stop at safe boundaries.** Upload pause takes effect at a chunk boundary; download pause/abort waits for the current response/read because the existing raw API does not accept an abort signal. The UI states this rather than implying instant cancellation.
4. **Guest link secrets are operationally sensitive.** The complete URL contains the client-side decryption secret in its fragment and is intentionally unavailable after reload/logout. Copy fallback selects the entire URL; users must store it in an approved secure channel.
5. **Large-file decryption remains buffered in the browser.** The interface is dense and honest about telemetry, but a production-grade large-file experience should move decrypt/save work to a dedicated worker and stream where browser APIs allow it.
6. **The current app has no real tenant scope.** The Personal vault context is a presentation boundary only. A future adapter must authorize membership server-side and invalidate scoped caches before changing context.
7. **One effect dependency warning remains in the guest access screen.** It does not block the build, but needs lifecycle review before a strict release gate.
8. **Workspace changed during integration.** Additional crypto and tenant-related sources appeared after the initial capability audit. Their presence does not prove usable tenant isolation or quota enforcement, and the workspace adapter remains deliberately unwired. Three upload callback regression cases currently fail to reach their expected request boundary; this is an unresolved release blocker, not a passed check.

## Acceptance evidence

- Initial `node --test tests/*.test.cjs`: 43 passed at the earlier checkpoint; superseded by subsequent workspace changes.
- Latest focused `auth-ui`, `design-system`, `share-ui`, `transfer-ui`, and `security` suites: 34 passed.
- Latest `node --test tests/upload-modal.test.cjs`: 2 passed, 3 failed (expected request boundary not reached). The whole suite is not currently green.
- `npm run lint`: 0 errors, 1 effect dependency warning in `app/shared/[token]/page.tsx`.
- `node node_modules/typescript/bin/tsc --noEmit --incremental false`: passed.
- `npm run build`: passed with warnings.
- Repository-wide `git diff --check`: failed on whitespace in concurrent backend and crypto edits. No claim of a clean repository-wide diff.

## Implementation files

- Design foundation: `frontend/app/globals.css`, `frontend/components/ui/{button,input,checkbox,switch,dialog}.tsx`.
- Transfer centre: `frontend/components/{upload-modal,file-manager,file-list,file-grid,transfer-stats}.tsx`, `frontend/lib/transfer-ui.ts`.
- Guest links: `frontend/components/{share-modal,guest-link-panel}.tsx`, `frontend/lib/guest-link.ts`.
- Authentication: `frontend/components/{login-form,mfa-settings,otp-deck,passkey-gateway}.tsx`, `frontend/lib/auth-ui.ts`.
- Workspace context: `frontend/components/{dashboard-layout,sidebar,workspace-context}.tsx`, `frontend/lib/workspace-context.ts`.
- Focused verification: `frontend/tests/{auth-ui,design-system,share-ui,transfer-ui}.test.cjs`.

These are complete workspace implementation files, not illustrative snippets. Passkey and enterprise workspace adapters require authoritative server integration before their unavailable states can be removed. No browser visual or assistive-technology certification has been performed.
