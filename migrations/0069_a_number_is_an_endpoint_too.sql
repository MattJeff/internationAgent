-- 0069_a_number_is_an_endpoint_too: the second wired ingest.
--
-- `0053_webhook_endpoints` wrote this migration's brief and left it unwritten:
--
--     `check (provider = 'email')` is therefore not a placeholder, it is the
--     pair of the one unconditional `.on(received_event("email"), on_webhook)`
--     in `main::handlers`. […] Telephony has a verifier
--     (`providers::telephony::verify_twilio_signature`) and no reader on the
--     other end of the queue. Widening this CHECK is a migration, and it
--     belongs in the same commit as the handler that makes it true.
--
-- This is that commit. The handler is `main::on_telephony_webhook`, registered
-- unconditionally under `webhook.twilio.received`, and it calls
-- `agentos_app::inbound::land_inbound_text` — which until now had exactly one
-- caller in the workspace and it was a test.
--
-- ---------------------------------------------------------------------------
-- WHAT THE CHECK IS AND IS NOT
-- ---------------------------------------------------------------------------
--
-- It is not a taxonomy of providers we like. It is the assertion that every
-- value in this column names an `event_type` some handler in `main::handlers`
-- is registered for, because the outbox does not skip an event with no
-- handler — it retries it eight times and dead-letters it, which is a silent
-- way to stop receiving a customer's messages. Two wired ingests, two values.
--
-- `'twilio'` and not `'sms'` or `'telephony'`, because the column names the
-- adapter whose signature scheme verifies the delivery, not the channel the
-- delivery is on. One Twilio endpoint carries SMS and WhatsApp both — the
-- `whatsapp:` prefix on `From` is the only thing that tells them apart, and
-- that decision belongs to `TelephonyRoute::read`, downstream of here. It is
-- the same string as `agentos_providers::telephony::PROVIDER`, which is what
-- `employee_resources.provider` already stores for a number.
--
-- ---------------------------------------------------------------------------
-- WHY THIS IS A WIDENING AND NOT A REPLACEMENT
-- ---------------------------------------------------------------------------
--
-- Every existing row says `'email'` — the old CHECK permitted nothing else —
-- so this cannot fail on live data, and it cannot orphan a row. The old
-- constraint is dropped by name and recreated by the same name, so a database
-- that has run 0053 and a database that has not both end with exactly one
-- constraint of that name and the same definition. `drop constraint if exists`
-- rather than a bare drop for the same reason every other statement in this
-- tree is idempotent: a partially applied migration must be re-runnable.
--
-- No RLS, no grants, no index: this touches one CHECK on a table 0053 already
-- forced RLS on and granted `app_role` nothing at all. Read 0053 for both.

alter table webhook_endpoints
  drop constraint if exists webhook_endpoints_provider_is_wired;

alter table webhook_endpoints
  add constraint webhook_endpoints_provider_is_wired
  check (provider in ('email', 'twilio'));
