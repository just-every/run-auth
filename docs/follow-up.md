# Follow-up

Activity records unresolved enrollment, recovery, provisioning, app setup and delegated assignment work independently of reminder delivery. The source action decides completion, cancellation or expiry. A sent reminder never proves that access was granted or removed.

App setup completes only after the actual link callback confirms it. A human-approved proposal remains visible if its callback fails; revoking a preparer key does not end a proposal already entrusted to people. Delegated assignment follow-up tracks employee consent, independent approval and exact execution, and stops with the task’s authority. It never claims downstream access from local assignment completion.

The current slice sends escalation email only to explicitly approved, currently active organization owners and administrators. It does not yet send employee, decider or help-desk reminders. Slack, Teams, Oncall, chat decisions, generic access requests and reviews remain unfinished under AUTH-FOLLOWUP-001.

An owner or administrator signs in with a hardware passkey and confirms their email in the same browser within ten minutes before enabling email, selecting recipients, or changing schedules. Without saved consent, the work is visible and nothing is sent. Recipients are organization person IDs selected from current administrators; arbitrary addresses and people outside the organization are refused. Current authority is checked before each dispatch.

Choose the employer timezone, business weekdays, holiday dates, local reminder time, business-day delay and deadline. Each obligation retains its calendar; explicitly rescheduling applies the current calendar to that item. A repeated daylight-saving minute uses its first occurrence; a skipped minute advances to the first real minute after the gap. Escalation repeats until the source resolves or stops reminders at the deadline, according to the saved policy. Stopping reminders leaves the unresolved work visible.

The recorded history distinguishes dispatch begun, transport accepted, delivery failure and source completion. History survives restart and is available through cursor pages at `GET /api/auth/followup`; `historyCursor` and `obligationCursor` retrieve earlier records. An interrupted outbound call remains recorded as dispatching; Auth does not claim delivery or access success from an uncertain result.

The complete CT policy additionally requires a published manage-follow-up permission, role-derived employee/decider/help-desk recipients with owner/admin escalation, and an authorized holder's early-send action. These are not offered by this slice. Existing sign-in and source-action proof still applies to every link in a reminder. Retention and authorized erasure govern stored follow-up data.
