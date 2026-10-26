# AI SOC Dashboard Implementation Plan

## Goal
Add a dedicated AI SOC Dashboard section inside the existing Wazuh Dashboard while preserving the existing Threat Hunting AI Analysis and report-generation workflow.

## Repository boundaries
- Dashboard integration belongs in `Albinthomas2005/wazuh-dashboard-plugins`.
- The AI analysis service and privacy-filtering work is documented separately in `Albinthomas2005/soc-home-lab`.
- Keep this work on `feature/ai-soc-dashboard`; do not modify `main` directly.

## First release scope
1. Dedicated AI SOC Dashboard navigation entry and overview page.
2. Alert triage using real Wazuh alert evidence.
3. Investigation view with event context and a timeline.
4. Incident notes and analyst report drafts.
5. L1/L2/L3 workflow guidance and escalation suggestions.
6. Clear loading, empty, permission-denied, and AI-provider-error states.

## Integration and safety requirements
- Reuse the existing Threat Hunting AI Analysis integration; do not remove or replace it.
- Call the AI service through a server-side backend adapter. Never expose provider API keys in browser code.
- Redact or minimize sensitive fields before sending alert content to an AI provider.
- Display the Wazuh alert evidence used by the AI explanation; distinguish evidence from AI-generated hypotheses.
- Require analyst confirmation before any disruptive response action. The first release should be analysis and recommendations, not autonomous remediation.
- Handle unavailable Wazuh/API services gracefully and log security-relevant errors without storing secrets.

## Implementation sequence
1. Inspect the actual plugin/app registration and existing Threat Hunting AI code paths.
2. Add the dashboard navigation registration and a minimal overview page without changing existing Threat Hunting behavior.
3. Connect the overview and alert triage to the existing AI backend contract.
4. Add investigation, case/report workflow, and analyst-level guidance incrementally.
5. Run repository lint/build/tests and verify the existing Threat Hunting path still works.

## Current status
- Feature branch created from `main`.
- Code-level integration has not yet been changed or verified. The next step is to locate the actual plugin registration and AI integration files before implementing UI changes; do not treat this plan as proof that features are implemented.
