# Mail delivery operations

Configure a Base mail adapter with a verified sender identity. Keep the API key
in private installation configuration. The local development outbox is private
and sends no external mail.

Auth journals each email attempt before submission. The journal contains an
opaque reference, a keyed recipient digest, transport, timestamps and fixed
outcome codes. It never records the message body, subject, usable sign-in link,
provider error body or credential. Mail journals, event records and suppression
digests are excluded from installation archives. Restores establish mail
configuration again; they never replay an old attempt.

Administrators signed in with a hardware passkey can inspect **Mail delivery**
on Sign-in methods and at the private diagnostics endpoint
`GET /api/auth/delivery`. Queued, provider accepted, delivered, bounced, deferred,
suppressed, rate limited and uncertain states remain distinct. A local outbox
entry is labelled separately. A submission interrupted after dispatch is
uncertain. Auth never automatically resends an uncertain submission.

## SendGrid events

For a SendGrid installation, set MAIL_SENDGRID_WEBHOOK_KEY to the public
verification key from that account's signed Event Webhook configuration. The
account operator must configure its event destination as
`POST /api/auth/delivery/sendgrid` on the Auth issuer. For an isolated employer,
use that employer's issuer prefix. A shared account's existing webhook must
remain under its account operator's control; configure an authorized relay
rather than replacing another product's destination.

Auth verifies the signature over the original bytes and timestamp before
parsing. It accepts only events matching a locally journaled SendGrid attempt,
the exact recipient and Auth's opaque custom arguments. Unknown claims have no
effect. Event IDs are durable duplicate keys; reusing one with different
evidence refuses the batch. The implementation also supports delayed bounce
events without a provider message ID. See the
[SendGrid event reference](https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/event).

Delivered evidence does not complete an enrollment, recovery or access
obligation. A bounce, dropped message or complaint suppresses further mail to
the same recipient in that employer. Suppression has no automatic expiry or
self-service bypass. The common transport also limits submissions per recipient
and installation; provider throttling is separately recorded. Authentication
proof still requires the original browser-bound, one-use confirmation door.

SES and Twilio setup and live enrollment and recovery qualification remain
unproved. A signed provider-edge test is not evidence of a live bounce or
delivery through the shared SendGrid relay.
