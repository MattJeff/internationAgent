# Porting MPCP: fidelity audit and integration map

**Status: this is the design note that was written _before_ the port, and the
port shipped differently. Read §"What actually shipped" first; everything after
it is a proposal, in a normative voice, that the code did not follow in full.**

Written against `mpcp.py` @ 3836 lines (24 Jul 2026), `PROJET.md`,
`FONDEMENTS_SCIENTIFIQUES.md`, `VERS_ORIZN.md`, `CARTOGRAPHIE_COMPORTEMENT.md`
and the measured run artifacts (`run30_j43.json`, `pardon_ab40.json`,
`mille_run_v4_complete/`, `mille_run_v5_civilisation/`). **None of those files
are in this repository**, so every `mpcp.py:NNN` line reference below is
unverifiable from here. Kept because the reasoning is the value; treat the
citations as provenance, not as something you can check.

This document exists so that in six months nobody has to guess why a constant is
`0.4`. It is an audit, not a summary: where the source model looks over-fitted to
a village simulation, or plainly wrong for a purchasing agent, it says so.

---

## What actually shipped

Four modules under `crates/domain/src/psyche/`, and **nothing calls them from
`crates/app` or `apps/server`.** The only callers anywhere are
`crates/eval/src/expectation.rs` (an offline harness that is not a dependency of
the server) and one integration test. `crates/store/src/psyche.rs` likewise has
no production caller.

So §0's invariant — the psyche never reaches `policy::evaluate` — holds, but it
holds trivially: **the psyche is library-only today.** It is a fully tested,
fully deterministic model with no seam into the running system yet. Read the
rest of this file as the map for building that seam, not as a description of one.

### The names, so you are not searching for types that do not exist

| This document proposes | The code has |
|---|---|
| `Psyche` with `ingest` / `tick` / `tone` / `rank` / `why` | no `Psyche` type at all — `psyche/mod.rs` is four `pub mod` lines |
| `Mood { valence, activation, friction }`, `Axis`, `Bounded01` | `Ledger::resting_friction() -> f64` (`forgetting.rs`); no mood vector, no newtype |
| `Disposition`, `DriftPressure`, `drift()` | not ported |
| `enum Observation` + `deltas() -> &[(Axis, f64)]` | `links::TrustEvent`, 3 variants, `const fn delta(self) -> f64` |
| `Belief { episodes, lived, formed_at, revived_at }` | `beliefs::Belief { episode_count, first_hand, last_reinforced_at, sources }` |
| `Relationship { trust, broken_at }` keyed by `SubjectRef` | `links::TrustLink { confidence, broken_at }` keyed by `Slug` |
| `Expectation` keyed by `(ObservationKind, SubjectRef)` | `ExpectationBook` keyed by `(Slug, Dimension)`; `Dimension` is `LeadTimeDays, PriceDeltaBps, ResponseLatencyHours, MoqFlexibilityPct, DefectRatePct` |
| `Intent`, `effective_priority()` | not ported — the psyche exposes **no prioritisation surface**, so "PRIORITISATION" in §0 is aspirational |
| `tone() -> Tone` | no `Tone`; nearest are `forgetting::Stance` and `links::Standing` |
| `why(&SubjectRef) -> Vec<Genealogy>` | `BeliefJournal::why(&Subject) -> Provenance` |
| `state_hash()`, `PsycheOp`, `replay(ops)` | none; determinism is asserted by tests instead |
| `expunge(supplier, reason, actor)` | not ported, and `psyche_episodes` is append-only by trigger — **there is no reset path at all** |
| `revisit()` / `HABITUATION` | not ported |
| salience weights `W1..W5`, `KR` | no salience function |

### Prescriptions here that the code deliberately did not follow

Four are worth knowing before you read the argument for them:

- **The tick anchor was not re-derived.** §"Time" argues every tick-denominated
  constant must be re-scaled to `1 tick = 1 hour`. The code kept MPCP's village
  clock verbatim: `DERIVE_SECONDS = 1_440` (24 minutes), `GRACE_DERIVES = 180`
  (3 days), `FADE_PER_DERIVE = 0.0005`.
- **`SURPRISE_MIN` was not lowered to 0.25.** It is 0.5, in two places
  (`forgetting.rs` and `expectation.rs::SURPRISE_FLOOR`).
- **Consolidation skips resolved episodes** rather than consolidating on a time
  window regardless of resolution, which is the opposite of what §"Beliefs"
  argues for and is precisely the "misanthropy generator" it warns about. If you
  are going to change one thing in the psyche, this is the one to think about.
- **Precision is `1/(1 + K·var/scale²)`**, not the `1/(1 + K·var)` written here,
  and low-evidence shrinkage is "`None` below 2 observations" rather than an
  `n/(n+N0)` prior — `CONF_N0` was not ported.

Constants that **were** ported exactly, and are worth not re-litigating:
`N_CONSOLIDATION = 3`, `MAX_SUBJECTS = 8`, the `0.25·Σmin(w,2)` strength
formula, `MISTRUST_FLOOR = 0.4`, `SHOCK_ABSORBER = 0.85`, `BREAKABLE_FROM =
0.6`, and the ×2 / ×0.5 / ×1.5 appraisal weights.

---

## 0. The governing invariant (this one is ours, not MPCP's)

> **The psyche influences TONE and PRIORITISATION. It must NEVER influence
> AUTHORISATION.**

MPCP has no authorisation layer at all — a village has no Policy Gate — so this
invariant does not appear in its docstring and cannot be inherited. It is added
by the port and it outranks every one of the seven below. If a mechanism in this
document conflicts with it, the mechanism loses.

Concretely, for as long as this crate exists:

- `domain::policy::evaluate(&EffectivePolicy, &Action, &ActionCtx) -> Decision`
  stays a pure function of policy and action. None of those three types may ever
  gain a psyche-derived field. No `Psyche` in `ActionCtx`; no mood axis in
  `PolicyLimits`; no `Money` computed from an `f64` mood axis.
- `ActionCtx`'s existing fields (`trust`, `contact`, `spent_today`,
  `new_contacts_today`, `now`) are all **host-supplied facts about the world**.
  A mood is not that kind of fact. The resemblance is superficial and it is the
  exact place where someone will one day be tempted.
- The failure this prevents: a frustrated agent accepting a price it would have
  refused calm. If mood can widen a permission, the entire "the LLM proposes,
  Rust decides" story collapses, and it collapses *silently* — the audit log
  shows an `Allow` and nothing records that the reason was a bad week.

MPCP itself had to discover the same firewall empirically and states it in its
own terms: *"l'identité ne colore QUE le ressenti, jamais la dynamique — pas de
prophétie auto-réalisatrice câblée"* (`PROJET.md` §2.5). That rule was not a
design principle up front; it was forced by measurement — biasing the trace
rather than only the felt value produced traces ×2.3–3.5 and a self-reinforcing
identity→trace→grudge→reputation→identity loop (`mpcp.py:678-681`, comment
"MUR 5, F4"). Their firewall sits between identity and dynamics. Ours sits
between psyche and authorisation. Same shape, higher stakes.

**Cheapest honest enforcement** (one line of CI):

```sh
! grep -riE 'psyche|mood|affect' crates/domain/src/policy.rs crates/domain/src/action.rs
```

**Neither this guard nor any equivalent is in CI today** — `.github/workflows/ci.yml`
and `scripts/test.sh` contain no such grep, and the psyche shipped without it.

And note the file list above has been corrected: the original version of this
document grepped `policy.rs` alone, but **`ActionCtx` is defined in
`crates/domain/src/action.rs`**, so a psyche field on `ActionCtx` — the exact
temptation §0 names — would have sailed straight past it. A guard aimed at the
wrong file is worse than no guard, because it reads as coverage.

A trybuild `tests/ui/` case would be prettier and this repo already has that
pattern (`gate_forge_literal.rs`, `prompt_secret_in_prompt.rs`), but a negative
grep cannot be defeated by a clever type. Add the grep when the psyche gets its
first production caller; that is the commit where the invariant stops being
trivially true.

---

## 1. The seven invariants

MPCP declares seven invariants in its module docstring (`mpcp.py:11-23`) and
asserts every one of them in `demo()` (`mpcp.py:2387`ff.), which is what
`python3 mpcp.py` runs. The engine earns real credit here: these are not
comments, they are executable claims, and several of them are load-bearing for
the port.

### I1 — Traits are mutable only by `_deriver()`

**Guarantees:** no single event can rewrite personality. `ingest()` never writes
`etat["traits"]`; a trigger key ending in `_bias` accumulates into
`etat["biais"]` (`mpcp.py:665`), a transient pressure map that `_deriver()`
consumes and clears (`mpcp.py:1360`). Personality change is therefore always
*integrated over time*, never *event-driven*.

**Asserted at:** `mpcp.py:2423` (`ingest` leaves traits identical) and
`mpcp.py:2451-2452` (a hostile LLM adapter mutating the views it receives still
cannot move a trait — `etat_public()` and the sampled journal entry are deep
copies).

**Port verdict: PRESERVE, and strengthen with the type system.** Make the trait
vector a private field whose only `&mut` access is inside `fn drift(&mut self,
now: DateTime<Utc>)`. Python enforces this by discipline plus one assert; Rust
can enforce it by module privacy, which is strictly better and free.

**Consequence if weakened:** a single supplier email would move the agent's
disposition. That is prompt injection with a slower fuse — the attacker does not
need to change what the agent is allowed to do, only what it is inclined to
propose, and the effect persists after the message is gone.

### I2 — `transduce()` is stateless and side-effect free

**Guarantees:** rendering the state to text reads and never writes
(`express()`, `mpcp.py:1014`). The LLM is a transducer, so swapping models
cannot change *who the agent is* — proved in the study by running the same
character under `dolphin-mistral` then `qwen3:8b` with an identical state
trajectory (`VERS_ORIZN.md` §1).

**Asserted at:** `mpcp.py:2414` (`hash_etat()` unchanged across an `express()`).

**Port verdict: PRESERVE.** `fn tone(&self) -> Tone` and any prompt-shaping
accessor take `&self`. This is nearly automatic in Rust and the invariant is
mostly a reminder not to "just log the last rendering into the state".

**Additional constraint the port must add:** MPCP's rendering surface includes a
free-text `descripteur`. Free text produced from state and then re-fed to a
model is a channel the `untrusted.rs` discipline exists to close. Expose
enum-valued tone (`Tone::Terse`, `Tone::Warm`, `Tone::Formal`, …), not a
sentence. See I5.

### I3 — `tick()` changes state even with zero input

**Guarantees:** time is an input. Decay, need accumulation, consolidation,
drift, journal compaction and goal generation all happen on the clock, not on
events (`mpcp.py:928-1012`).

**Asserted at:** `mpcp.py:2393` (`hash_etat()` differs after a bare `tick()`).

**Port verdict: PRESERVE — and this is the one a naive Rust port will drop.**
The tempting shape is `fn on_event(&mut self, e: Event, now: DateTime<Utc>)` and
nothing else, because it fits an event-driven service. That port has no
forgetting. `run30_j43.json` is what an engine without working forgetting looks
like after 43 simulated days: **30/30 agents at `prudence` 1.0, 30/30 at
`tolerance_risque` 0.0, `friction` median 0.992, 23/30 carrying the "paria"
identity.** A purchasing agent in that state distrusts every supplier equally,
which is the same as distrusting none — the discrimination that is the entire
point of the moat is gone.

The Rust shape must be `fn tick(&mut self, now: DateTime<Utc>)` driven by a
scheduler, with elapsed wall time converted to ticks through one named anchor
constant (§3). `now` is a parameter; `Utc::now()` never appears in `domain`.

### I4 — Private deliberation is never returned to a caller

**Guarantees:** `_resume_delibere` (the private rumination) is excluded from
`etat_public()` by the leading-underscore convention (`mpcp.py:2361`) and
`tick()` returns exactly `{horloge, action_proactive}` (`mpcp.py:1011`). The
`VERS_ORIZN.md` §4 guardrail names it: *"la pensée privée colore le ton, ne
s'énonce jamais"* — containment.

**Asserted at:** `mpcp.py:2417-2418` (key set of `tick()`'s return; no
underscore keys in `etat_public()`).

**Port verdict: PRESERVE, and it maps onto an existing repo rule.** Private
psyche state must not appear verbatim in an outbound message, and must not be
handed to the model as authority. Rust: private fields, no public getter, and
the same `prompt.rs` discipline that keeps secrets out of prompts.

**Where MPCP is honest about a leak and we should be stricter:** its docstring
lists three by-design exceptions, one of which is *"le transducteur qui la reçoit
comme matière_reflexion"* — the private thought **is** fed to the LLM
(`mpcp.py:1024`). For a village that is the point. For a purchasing agent, a
private thought about a counterparty entering the same context window as a draft
email to that counterparty is a leak waiting for one bad completion. **Deviation:
do not pass rumination text to the model. Pass the derived `Tone` only.**

### I5 — The self-descriptor is never hardcoded

**Guarantees:** the agent's one-line self-description is regenerated by the LLM
and validated against the dominant traits at `SEUIL_COHERENCE = 0.66`
(`mpcp.py:406`, `_valider_descripteur` at `mpcp.py:1139`), so the state can never
be contradicted by the text.

**Asserted at:** `mpcp.py:2426-2427`.

**Port verdict: DROP.** This is the weakest of the seven for our use case. It
solves "the character can describe itself and the description is true", which is
a companion-product feature (`PROJET.md` §7). A purchasing agent does not need a
self-portrait; it needs an audit trail.

**What replaces it, and it is strictly better:** `pourquoi(sujet)`
(`mpcp.py:2044`) — the belief genealogy that walks any conviction back to the
founding episodes, with refs and timestamps and no LLM text anywhere in the
chain. Port that as `fn why(&self, subject: &SubjectRef) -> Vec<Genealogy>`.
That is the function a buyer shows their manager when asked why the agent
deprioritised a supplier, and it is the single most commercially valuable thing
in `mpcp.py`.

**Consequence of dropping I5:** none, provided `why()` exists. If someone ports
the descriptor *and* skips `why()`, the port has kept the decoration and thrown
away the substance.

### I6 — All state is serialisable and survives `restore()` bit-for-bit

**Guarantees:** `snapshot()` is `json.dumps(etat, sort_keys=True)` including the
RNG state (`mpcp.py:1066`); `restore()` validates the blob version and the RNG
state *before* writing `self.etat` (`mpcp.py:1072`). The exclusions are named
and defensible: the LLM adapter (interchangeable by design) and the oplog
(persisted separately from the checkpoint).

**Asserted at:** `mpcp.py:2404-2407` — `restore(snapshot()) == snapshot()`
byte-for-byte, *and* the restored instance's next `tick()` produces the same
hash as the original's.

**Port verdict: PRESERVE. This is the hard one.** See §3 in full. The headline
traps are `HashMap` iteration order, float accumulation order, and the fact that
`f64::exp` is not guaranteed bit-identical across targets.

One design note MPCP gets right and the port must copy: `restore()` performs
**no normalisation**. There is an explicit comment at `mpcp.py:1104` —
*"toute normalisation au restore violerait l'invariant 6 (bit-à-bit)"* — even
where a stale blob holds a saturated EMA. Retro-compat is done with
`setdefault` on *absent* fields only, never by clamping present ones. In Rust:
`#[serde(default)]` for new fields, and no `Deserialize` impl that silently
repairs values. (`employee.rs` already refuses to implement `Deserialize` at all
for exactly this family of reasons; that instinct is correct here too, though a
psyche does need to round-trip.)

### I7 — Seeded RNG: same seed + same stream → same state

**Guarantees:** `rejouer(oplog, seed)` (`mpcp.py:2370`) reconstructs the entire
life from an append-only op log of four op kinds (`ingest`, `tick`, `regen`,
`resoudre`). `hash_etat()` is sha256 over the sorted-key snapshot
(`mpcp.py:2366`). `VERS_ORIZN.md` §4 calls this the auditability story: *"pourquoi
me parles-tu sur ce ton ?" → rejouable, explicable.*

**Asserted at:** `mpcp.py:2409` — a fresh instance replayed from the oplog hashes
identical to the live one.

**Port verdict: PRESERVE the replay; DELETE the randomness.**

MPCP uses its RNG in exactly two places that matter: weighted sampling of the
journal by salience (`_echantillonner`, `mpcp.py:1221`) and the Dark-Mod-derived
alert-decay fuzziness (`VIGIL_FLOU`, `mpcp.py:209` — a gate we are not porting).
The salience sampling models Default Mode Network rumination (Raichle, Sheline)
— which mind-wandering target you land on is genuinely stochastic in a human.

For a purchasing agent it is not worth the price. Randomness in the replay path
means the RNG state must be snapshotted, versioned, and reproduced exactly —
and reproducing CPython's Mersenne Twister stream in Rust is a pointless
liability. **Deviation: replace weighted sampling with deterministic argmax over
salience, ties broken by `EpisodeId`.**

Consequences, stated honestly:

- Mood diffuses less. The most salient open episode gets revisited every tick
  instead of occasionally, so it reaches the `HABITUATION` threshold and
  self-closes much faster (`_revisiter`, `mpcp.py:888`). `HABITUATION = 6` was
  tuned against stochastic revisiting; under argmax the same episode closes in
  ~6 ticks flat. **`HABITUATION` must be re-tuned upward** — see §2.
- Two agents with identical histories now behave identically. In a village that
  is a bug (you want 30 distinct characters). For a fleet of purchasing agents
  it is a feature: two employees with the same supplier history *should* rank
  the same supplier the same way, and a support engineer should be able to
  reproduce a ranking exactly.
- If randomness is ever genuinely needed, inject a seeded counter-based PRNG
  (seed stored in state, stream position stored in state) — never `rand::random`,
  never `ThreadRng`. But the first answer is: do not need it.

### Summary

| # | Invariant | Verdict | If violated |
|---|---|---|---|
| 0 | Psyche never touches authorisation | **ADD** (not in MPCP) | The safety story is gone, silently |
| 1 | Traits move only by drift | PRESERVE, enforce by privacy | One email rewrites disposition |
| 2 | Rendering is pure | PRESERVE | The model becomes a state source |
| 3 | `tick()` changes state with no input | PRESERVE | No forgetting → the j43 dystopia |
| 4 | Private deliberation never returned | PRESERVE, **stricter** than MPCP | Private thoughts reach the counterparty |
| 5 | Descriptor regenerated + validated | **DROP**, keep `why()` instead | Nothing, if `why()` ships |
| 6 | State round-trips bit-for-bit | PRESERVE | Replay diverges; audit unfalsifiable |
| 7 | Seeded RNG replay | PRESERVE replay, **drop RNG** | See §3 |

---

## 2. The constant table

Every number below carries meaning. "Tuned against" is what the source actually
calibrated it on, which in every case is a 20–30 NPC village at 300 ticks/day
(the `mur 2` comment at `mpcp.py:291` fixes that ratio: *"budget ~1.5/jour monde
20 (300 ticks/jour)"*), plus one 1000-agent mega-run.

### 2.0 The re-tuning rule (read this before the table)

Split the constants in two:

- **Counted in EVENTS** — `N_CONSOLIDATION`, `HABITUATION`, `TAUX_PRED`, the
  per-episode belief weight, `MAX_SUJETS`, `CONF_N0`. These **transfer as-is**.
  Three concordant experiences is three concordant experiences whether they take
  a village afternoon or a purchasing quarter.
- **Counted in TICKS** — `OUBLI_DELAI`, `OUBLI_PAS`, `OUBLI_BRISE`, `KR`,
  `SECU_DELAI`, `SECU_RAMPE`, `CONF_RECENCE`, `TAU_MATURITE`, `DELTA_DISCOUNT`,
  `REFRACTAIRE_*`, `PERIODE_DERIVE`, journal compaction age. These **must all be
  re-derived**, because the event density per subject differs by two to three
  orders of magnitude. A village NPC accumulates thousands of journal entries per
  simulated day (`mille_run_v5` reports `journal_moyen: 2451` at h8). A
  purchasing agent sees maybe 5–50 interactions a day *across all suppliers*,
  and 1–5 per supplier per **week**.

Pick **one** anchor and derive everything from it. Recommended anchor:
`1 tick = 1 hour of wall clock`, chosen so that a working day is ~8–10 ticks and
a quarter is ~600. Then every tick-denominated constant below must be
recalculated at the new ratio — do not copy the number.

The failure mode if you skip this: at 300 ticks/day, `KR = 0.01` gives recency a
~69-tick half-life ≈ 5.5 village hours. Copied blindly at 1 tick/hour it becomes
a 69-hour half-life, which is roughly right by luck. `DELTA_DISCOUNT = 0.95` is
not so lucky: at 300 ticks/day a goal loses 64% of its value in 20 ticks
(~1.6 h); copied at 1 tick/hour, an open chase-the-supplier intent is worth 36%
of its original priority after 20 *hours* and effectively zero after two days.
Procurement cycles run for weeks. **`DELTA_DISCOUNT` must move to roughly `0.97`
per day (half-life ~23 days), not per hour.**

### 2.1 Salience and recency

| Constant | Value | Where | What it does | Tuned against | Re-tune for purchasing |
|---|---|---|---|---|---|
| `W1..W5` | 0.4 / 0.2 / 0.2 / 0.2 / 0.5 | `mpcp.py:115` | Salience = `W1·|dmod| + W2·novelty + W3·goal-relevance + W4·recency + W5·open-trace` | Village attention; `W5` deliberately the largest so an **open wound stays salient** | Keep the shape. Raise `W3` (goal relevance): in purchasing, "this supplier blocks an open PO" should dominate "this supplier annoyed me". Suggest `W3 = 0.4`. |
| `KR` | 0.01 /tick | `mpcp.py:116` | Exponential recency decay inside salience | 300 ticks/day → ~5.5 h half-life | Re-derive at the new anchor. Target: a week-old episode retains ~30–50% recency, not 0.1%. |

### 2.2 Shock, trace, grudge

| Constant | Value | Where | What it does | Tuned against | Re-tune |
|---|---|---|---|---|---|
| `K_CHOC` | 12.0 | `mpcp.py:119` | Drift gain multiplier proportional to the charge of the strongest open wound: `gain = 1 + K_CHOC·charge` | Reproduces Roberts 2017's "big early change then plateau" when paired with habituation | **Lower it.** ×13 drift gain on a single open dispute is village drama. A purchasing agent restructuring its disposition 13× faster because one PO is late is over-reaction. Suggest 3.0–4.0 and measure trait σ (see §2.10 acceptance test). |
| `SEUIL_TRACE` | 0.35 | `mpcp.py:121` | `dmod` above which an event leaves a durable emotional trace | Village event magnitudes | Keep; it is relative to `dmod`, which is itself normalised. |
| `RANCUNE` | 0.5 | `mpcp.py:122` | Friction floor while an unresolved negative trace is open | — | Keep, **but see the clamping bug in §3.5**: this floor is added to the baseline and the result is never clamped, which is how `friction` reaches 1.148 in `mille_run_v5`. |
| `HABITUATION` | 6 | `mpcp.py:312` | Revisits after which an unresolved episode self-closes: `6 · (1 + 2·charge)` | Stochastic sampling | **Re-tune upward** if you take the argmax deviation (§I7). Under argmax the top episode is revisited every tick, so 6 ticks closes it. Suggest 20–30, and validate that a genuinely open dispute survives a working week of ruminating. |

**Critical warning on `HABITUATION`:** psyche episode closure is *not* business
ticket closure. `_revisiter` closing an entry means "the agent stopped feeling
strongly about it". It must never be wired to close a purchase order, cancel a
chase, or drop an obligation. Two lifecycles, two stores. The psyche may stop
caring; the outbox must not stop chasing.

### 2.3 Relationship / trust

| Constant | Value | Where | What it does | Tuned against | Re-tune |
|---|---|---|---|---|---|
| `LIEN_DELTAS` | `+0.10` goal met, `−0.25` constraint violated, `−0.10` repeated error | `mpcp.py:125` | Per-event trust delta | Berg's trust-game asymmetry — betrayal costs 2.5× what a kept promise earns | **Keep the asymmetry, it is the sourced part.** Re-map the event names (§6.2). |
| `SEUIL_BRISURE` | 0.2 | `mpcp.py:126` | Single-event trust drop that marks a break | — | Keep. |
| `CONFIANCE_BRISABLE` | 0.6 | `mpcp.py:127` | …but only if trust was *built* first. A cold betrayal breaks nothing. | Berg | Keep. This is the model's best idea: you cannot be betrayed by someone you never trusted. |
| `AMORTI_LIEN` | 0.85 | `mpcp.py:128` | Bayesian prior resistance: `inc *= 1 − 0.85·max(0, trust−0.5)·2` on negative moves | Measured. The comment records the search: at 0.95 the first weight-3 blow wounds and the *second* breaks; at 0.5 there is no damping. Set after a V7 prehistory run where a single weight-3 rumour broke a 0.95 mother-daughter bond in one tick. | Keep 0.85. This is the best-documented constant in the file and the search behind it is recorded in-line. |
| `PAS_REPARATION` | 0.01 /drift period | `mpcp.py:408` | Passive trust recovery toward 0.5 for *lukewarm* rifts only | Village social homeostasis | **Question this one.** A supplier who burned you drifts back to neutral by doing nothing. For a village that is healing; for procurement it is unearned rehabilitation. Recommend: repair only on *delivered positive events*, or cut the passive rate by 5–10×. |
| `OUBLI_BRISE` | 4500 ticks (15 village days) | `mpcp.py:191` | After this, a broken link stops freezing repair | The pardon campaign | Re-derive at the new anchor. |

### 2.4 Consolidation (episodic → semantic)

| Constant | Value | Where | What it does |
|---|---|---|---|
| `N_CONSOLIDATION` | 3 | `mpcp.py:136` | Concordant unresolved episodes on one subject required to form a durable belief. Squire / Diekelmann-Born two-speed consolidation. |
| belief strength | `min(1, 0.25 · Σ min(weight, 2))` | `mpcp.py:1406` | Strength weighs the **lived impact**, not the episode count. Three weight-1 episodes give exactly 0.75 (the pre-existing calibration, preserved deliberately). The `min(weight, 2)` cap and the whole weighting were added after a dormant bug where three weight-0.1 murmurs outweighed three weight-3 traumas. |
| `K_CROYANCE` | 0.5 | `mpcp.py:137` | Gain from consolidated beliefs into trait drift |
| `MAX_SUJETS` | 8 | `mpcp.py:138` | Subjects per event — anti-explosion bound on belief creation |

**Transfers as-is.** Three concordant experiences with a supplier is exactly the
right threshold for "this is now a belief, not an anecdote", and the
weight-not-count rule is precisely what a purchasing agent needs: one €200k
missed delivery should outweigh three trivial late replies. The `min(weight, 2)`
cap keeps a single catastrophe from instantly maxing a belief — keep it.

**One thing to fix in the port:** `N_CONSOLIDATION` operates on *unresolved*
episodes (`mpcp.py:1386-1396`). In purchasing, most episodes get resolved (the PO
ships, the credit note arrives) and would therefore never consolidate. The
village's implicit assumption — that unresolved is the normal state — does not
hold here. **Deviation: consolidate on episodes within a window regardless of
resolution, and let resolution affect polarity, not eligibility.** Otherwise the
agent only ever forms beliefs about disasters it never closed, which is a
misanthropy generator (`VERS_ORIZN.md` §4 guardrail 4: *"compter les succès"* —
the v2/v3 runs produced zero positive beliefs until calming events were added).

### 2.5 Forgetting — the "pardon" campaign

This is the highest-value block in the file and the numbers come with a measured
before/after. The j43 dystopia (`run30_j43.json`: 23/30 pariahs, friction median
0.992, every trait at a bound) was cured by adding differentiated forgetting;
the same seed then produced a village of builders at friction 0.06.

| Constant | Value | Where | What it does | Re-tune |
|---|---|---|---|---|
| `OUBLI_DELAI` | 900 ticks (3 village days) | `mpcp.py:189` | Time without revival before forgetting starts | Re-derive at the new anchor. Suggest ~14 days for a supplier belief. |
| `OUBLI_PAS` | 0.0005 /drift | `mpcp.py:190` | Forgetting step. At 60 drifts/day = 0.03/day → strength 1.0 → 0.4 in ~20 days | Re-derive so the same *calendar* span holds, not the same tick count. |
| **`OUBLI_PLANCHER_VECU`** | **0.4** | `mpcp.py:192` | **Lived experience never forgets below 0.4. Hearsay erases to zero.** | Keep the value; see the caveat below. |
| `RAPPEL_BASELINE_FRICTION` | 0.001 /drift | `mpcp.py:194` | Allostatic recovery of the friction baseline (~0.06/day) | Re-derive |
| `RAPPEL_ATTENTES` | 0.001 /drift | `mpcp.py:197` | R-W extinction: expectations slide toward 0 | Re-derive |
| `ATTENTE_FATIGUE` | −0.8 | `mpcp.py:193` | Expectation past which a transgression stops being outrageous ("sanction fatigue") | Keep |

**The 0.4 floor is the constant the whole document exists to explain.** It is the
line between *forgiveness* and *amnesia*. Above it, lived betrayal is
imprescriptible — you never fully stop being wary of someone who actually hurt
you (Damasio's somatic marker, McCullough's grudge). Below it, second-hand
information evaporates entirely, which is what stops rumours from becoming
permanent reputation. It also appears in three other places as a coherent
threshold: `_appraisal` requires belief strength ≥ 0.4 before a subject counts as
"close" or "distrusted" (`mpcp.py:1195-1200`), `_influence` counts only the *excess*
above 0.4 when beliefs sculpt traits (`mpcp.py:1299-1305`), and `_reparer_liens` uses
0.4 as the scar threshold (`mpcp.py:1556`). One number, four sites, one meaning:
**0.4 is "wary"**. Port it as a single named constant, not four literals.

**But add an escape hatch we need and MPCP does not.** A permanent,
unappealable machine grudge against a *legal entity* is a commercial and
plausibly a legal liability — suppliers change account managers, get acquired,
fix their processes. The port needs a human-triggered, audited
`expunge(supplier, reason, actor)` that resets the belief set for one subject and
writes an audit row. This is not a psychology question; it is the same reason
`why()` exists.

### 2.6 Prediction error (Rescorla-Wagner) and precision (Welford)

| Constant | Value | Where | What it does |
|---|---|---|---|
| `TAUX_PRED` | 0.3 | `mpcp.py:342` | R-W learning rate: `expectation += 0.3 · surprise`. ~3 events to converge. |
| `SURPRISE_MIN` | 0.5 | `mpcp.py:343` | Floor: a fully predicted event still lands at 50% impact |
| `K_PRECISION` | 1.0 | `mpcp.py:347` | Precision weight `1/(1 + K·var)` over the Welford variance of `|surprise|` per `(type, subject)` |
| `CONF_N0` | 3.0 | `mpcp.py:158` | Ignorance prior pooled into second-order confidence |

`SURPRISE_MIN = 0.5` is a judgement call the source states plainly: *"un
événement prévu garde 50% d'impact émotionnel (un stresseur réel reste un
stresseur)"*. It is defensible psychologically and **it means habituation can
never fully extinguish**. Combined with the fact that no trigger in `DECLENCHEURS`
has a negative friction delta — friction only ever goes up on events, and comes
down only through decay and two `0.001` recovery constants — this is an upward
ratchet held back by very little. It was measurably not enough at scale:
`mille_run_v5` reports agents at `friction: 1.148`, i.e. **outside the [0,1] band
the axis is supposed to live in**.

For purchasing, lower `SURPRISE_MIN` to ~0.25. A supplier who is *reliably* 10
days late should eventually stop being annoying and start being *a fact you plan
around* — that is the correct professional adaptation and it is what the R-W
model predicts. The village wanted residual outrage; we want a planner.

### 2.7 Trait drift and maturation

| Constant | Value | Where | What it does | Re-tune |
|---|---|---|---|---|
| `DEFAUT_INERTIE` | 0.97 | `mpcp.py:39` | Per-drift trait inertia; effective step is `(1 − inertie)` | Keep — it is the Roberts 2006 cumulative-continuity alignment, the source's own deepest alignment. |
| `DEFAUT_TAUX_APPRENTISSAGE` | 0.05 | `mpcp.py:40` | Drift learning rate | Keep |
| `PERIODE_DERIVE` | 5 ticks | `mpcp.py:400` | Drift/consolidation cadence (also the "sleep" cadence) | Re-derive; nightly is the natural purchasing cadence (`VERS_ORIZN.md` palier B). |
| `TAU_MATURITE` | 4000 | `mpcp.py:356` | Inertia → 1.0 with age: `inertie + (1−inertie)·(1−e^(−horloge/τ))` | Re-derive, or **drop for v1**. |
| `ATTRACTEUR_MATURITE` | 0.0008 | `mpcp.py:357` | Directional normative nudge per drift | Drop for v1 |
| `ATTRACTEUR_DIR` | formality +1, persistence +1, caution −0.5 | `mpcp.py:358` | Roberts & DelVecchio maturity principle direction | Drop for v1 |
| `PLASTICITE_MIN` | 0.01 | `mpcp.py:178` | Inertia is capped at `1 − 0.01`: maturity **never** fully freezes | If you port maturity, port this. It was added after measuring castes frozen where their first 5 days left them (50% of the drift budget consumed before h≈1330). |
| `SECU_DELAI` / `SECU_RAMPE` | 900 / 1800 ticks | `mpcp.py:172-173` | Fear extinction (Trimmer): after 3 days with no *real* injury, a 6-day ramp pulls caution and risk tolerance back to rest | Re-derive; **keep the mechanism**, it is the main thing preventing the caution ratchet. |
| `K_SECU` / `K_SECU_TOL` | 4.0 / 2.0 | `mpcp.py:174-175` | Gain of that recall | Keep ratio |
| `PRUDENCE_REPOS` / `TOL_REPOS` | 0.35 / 0.5 | `mpcp.py:176-177` | Resting values of a world with no threat | Set from the desired professional default, not the village's. |
| `DEFAUT_TRAITS` | exploration 0.81, prudence 0.64, directivité 0.90, tolérance_risque 0.42, exigence 0.88, persistance 0.75 | `mpcp.py:35` | Starting personality | **These are one NPC's character sheet, not a scientific result.** Re-pick them as the deliberate default disposition of a purchasing employee, and expose them as per-employee configuration. Do not copy 0.81 because it was there. |

**Maturity (`TAU_MATURITE`, `ATTRACTEUR_*`) is the block I would leave out of
v1.** It is P6 in their own priority list, explicitly marked *"long-terme
seulement"*. It adds two constants and an exponential to solve a problem
(personality rigidifying with age) that a two-year-old purchasing agent does not
have. YAGNI. `PLASTICITE_MIN` only exists to patch a hazard maturity introduces;
skip both and the hazard never arrives.

### 2.8 Appraisal (the ×2 that everyone remembers)

`_appraisal` (`mpcp.py:1183`) is four numbers:

| Case | Factor | Meaning |
|---|---|---|
| Negative event from a **close** subject (trust ≥ 0.65, or positive belief ≥ 0.4) | **×2.0** | Loss aversion applied to the relational domain — the source maps it to Kahneman-Tversky's λ≈2 |
| Negative event from an **already-distrusted** subject (trust ≤ 0.35, or negative belief ≥ 0.4) | ×0.5 | *"ça ne m'étonne pas de lui"* |
| Positive event from a distrusted subject | ×1.5 | Unexpected kindness |
| Unknown subject, or neutral event | ×1.0 | |

**This transfers to purchasing almost unchanged and it is the most immediately
useful mechanism in the engine.** A quality failure from your strategic partner
of six years genuinely should register harder than the same failure from a
spot-buy vendor you already watch. That is not sentiment, it is correct
information weighting: the partner's failure is more surprising and therefore
more informative — which is also exactly the Rescorla-Wagner argument.

Two notes:
- The ×2 branch **returns immediately** (`mpcp.py:1205`) rather than compounding
  across subjects. Deliberate: multiple close subjects do not stack to ×8. Port
  the early return.
- `MOI` (the self token) is inert on the appraisal side (`mpcp.py:1184`) — a
  self-caused event is not a betrayal by another. Keep that carve-out; a
  purchasing agent that appraises its *own* mistakes at ×2 spirals.

### 2.9 Thresholds for initiative and prioritisation

| Constant | Value | Where | What it does |
|---|---|---|---|
| `SEUIL_INITIATIVE` | 0.52 | `mpcp.py:403` | Activation below which no proactive action is emitted ("calibré sur simulation") |
| `SEUIL_CONFRONTATION` | 0.4 | `mpcp.py:402` | Friction needed for an open wound to generate a confrontation goal |
| `THETA_INTERET` / `THETA_DESIR` | 0.55 / 0.55 | `mpcp.py:401, 366` | Intrinsic-goal generation thresholds |
| `BETA_PRESENT` | 0.8 | `mpcp.py:364` | Present bias: a flat discount on anything not immediate (Ainslie/Laibson quasi-hyperbolic) |
| `DELTA_DISCOUNT` | 0.95 /tick | `mpcp.py:365` | Exponential delay discount → `_priorite_effective` |
| `HAB_BONUS_MAX` / `HAB_TAU` | 0.08 / 5.0 | `mpcp.py:316, 320` | Habit formation: a repeated action type lowers its own future threshold, ~63% of the bonus at 5 uses |
| `JOURNAL_MAX` | 600 | `mpcp.py:407` | Journal size that triggers structural compaction (evicts resolved, non-founding episodes older than 200 ticks) |

`_priorite_effective` (`mpcp.py:2338`) is the prioritisation surface — this is the
"whom to chase first" function and it is *pure* over `(priority, created_at,
now)`, recomputed on every read, never memoised. Port that purity exactly; a
memoised priority is a replay divergence.

**Carry the source's hardest-won operational lesson with it.** `PROJET.md` §4
calls it *la loi de la famine par priorité*: **any chain of prioritised branches
starves its tail — six observed occurrences.** Their rule: fresh beats
persistent, and every new channel goes **last**. When the port adds a new intent
kind, it will starve unless placed deliberately, and the symptom will be "the
agent never does X" with no error anywhere.

### 2.10 The acceptance test the constants are for

Both the 30-agent and 1000-agent runs saturated. The port needs a mechanical
guard against re-inventing that, and MPCP's own diagnosis gives the shape:

> After N simulated business days across a cohort of agents on synthetic
> supplier histories: **no trait sits at a bound (0.0 or 1.0), the cross-agent
> σ of each trait is > 0.05, and every mood axis stays within [0,1].**

`run30_j43.json` fails every clause (prudence σ = 0.000, 30/30 at the bound,
7/30 with friction > 1.0). That is the regression test. It is cheap — a
deterministic loop over `ingest`/`tick` in `#[cfg(test)]` — and it is the only
thing that will catch a re-tuning that looks fine for a week.

---

## 3. The determinism contract

### 3.1 How MPCP achieves it

1. **Append-only oplog.** Four op kinds: `("ingest", event)`, `("tick", dt)`,
   `("regen",)`, `("resoudre", ref)`. `rejouer()` replays them from a fresh
   instance (`mpcp.py:2370`). Note `("regen",)` is logged *even though it is an
   LLM call* — without it replay diverges, and the comment says so
   (`mpcp.py:1119-1120`).
2. **Validation strictly before the oplog append.** `ingest()` normalises and
   rejects everything *before* `self._oplog.append(...)` (`mpcp.py:594`, and the
   comment at 557 calls it atomicity). An invalid event raises without touching
   state or polluting the log. Copy this ordering exactly.
3. **Ordering discipline everywhere a collection is iterated for effect.**
   `relie_a` is sorted-and-deduped at the boundary with an explicit note about
   `PYTHONHASHSEED` (`mpcp.py:567`); `_consolider` iterates
   `sorted(groupes.items())`; `_reparer_liens` iterates
   `sorted(self.etat["liens"].items())`; the remorse, anticipation and needs
   loops all sort their keys. This is the discipline Rust gets for free from
   `BTreeMap` — take it for free.
4. **Injected clock.** `etat["horloge"]` is an internal integer advanced only by
   `tick(dt)`. Nothing in the engine reads a real clock — even the circadian
   phase is derived from `horloge` and explicitly never stored
   (`_phase_circadienne`, `mpcp.py:1217`).
5. **Hostile-input neutralisation at the boundary.** NaN weights, NaN novelty,
   negative alerts and `set` inputs are all neutralised in `ingest`
   (`mpcp.py:562`, 587, 567). `demo()` asserts the snapshot stays JSON-valid
   afterwards (`mpcp.py:2434`).
6. **`hash_etat()` = sha256 over the sorted-key snapshot** (`mpcp.py:2366`).
   Replay equality is asserted on the hash, not eyeballed.

### 3.2 What the Rust port must do

- **`BTreeMap` / `BTreeSet` everywhere.** Not "where it matters" —
  everywhere in psyche state. A `HashMap` whose iteration order leaks into a
  float accumulation is the single most likely source of a divergence that
  reproduces once a month.
- **Fix the accumulation order and never parallelise it.** `sum(precisions)/len`
  and `Σ min(weight, 2)` are order-dependent in floating point. Iterate a
  `BTreeMap` or a `Vec` in one fixed order. No `rayon`, no `par_iter`, ever, in
  this crate — which `domain` already enforces by having no such dependency.
- **`f64`, never `f32`**, and never mix.
- **No clock reads.** `now: DateTime<Utc>` as a parameter, and it must be *the
  same instant* the rest of the turn uses. Two subsystems calling `Utc::now()`
  microseconds apart will produce different tick counts on a boundary and the
  replay will not reproduce.
- **No unseeded randomness.** Preferably none at all (§I7). If any: seed and
  stream position both live in the serialised state.
- **Reject non-finite at construction.** MPCP neutralises NaN with idioms like
  `poids != poids`. Rust can do better: a `Bounded01(f64)` newtype whose
  constructor rejects NaN/∞ and clamps to [0,1] makes the whole family of bugs
  unspellable — including the one in §3.5.
- **Serde round-trip test as the I6 assert.** `serde_json` round-trips `f64`
  exactly (shortest-representation), so `hash(state) == hash(from_str(&to_string(
  &state)))` is a real test. Write it. Also assert the restored value's *next*
  tick hashes identically, the way `demo()` does — round-tripping the bytes is
  weaker than round-tripping the future.
- **Golden-hash replay test in CI.** A fixed op sequence, a pinned expected
  sha256. That is what makes a divergence a red build instead of a support
  ticket.

### 3.3 The trap neither implementation closes: `exp` is not portable

`tick()` calls `exp(-λ·dt)` on every axis every tick; `_deriver` calls `exp` for
maturity; `_saillance` calls `exp` for recency; `_phase_circadienne` feeds `cos`.

**`f64::exp` and `f64::cos` are not guaranteed bit-identical across
architectures, libm versions, or optimisation levels.** They are correctly
rounded on no platform anyone ships. CPython's `math.exp` has the same property,
so MPCP's "bit-for-bit" claim is really "bit-for-bit **on the same target**".
That is fine — but it is unstated, and the port will be the one that discovers it
when CI runs on `linux/amd64` and a developer replays on `darwin/aarch64`.

Options, in ascending cost:

1. **Accept same-target determinism, state it, and pin it.** Golden-hash test
   runs on one CI target; the docs say replay is exact within a target triple.
   Recommended for v1.
2. Precompute the decay factors. `exp(-λ·dt)` for integer `dt` and a small fixed
   set of λ is a lookup table with a documented generator. Removes `exp` from the
   hot path entirely and is arguably *simpler*, not more complex.
3. Fixed-point the whole modulation vector. Correct, portable, and a large
   rewrite. Do not do this in v1.

Write down whichever you pick. An undocumented determinism boundary is worse
than a narrow documented one.

### 3.4 Money never touches the mood floats

MPCP has no concept of money, so it offers no guidance and the port must supply
the rule:

> `Money` (unsigned minor units + currency, checked arithmetic) never becomes an
> `f64` mood axis, and no `f64` in the psyche is ever converted back into a
> `Money` that reaches an `Action`.

The psyche legitimately holds *statistics about* money — "this supplier's opening
quote runs 14% above their final" is a dimensionless ratio and is fine as `f64`.
But the price the agent then proposes must be computed from `Money` in the
negotiation logic. The ratio informs *what to propose*; it never *is* the
proposal. This is the §0 invariant expressed in arithmetic.

### 3.5 A real bug in the source, inherited if you are not careful

In `tick()` (`mpcp.py:941-945`):

```python
base = s["baseline"] + (plancher if nom == "friction" else 0.0)
s["valeur"] = base + (s["valeur"] - base) * exp(-s["lambda"] * dt)
```

`base` is `baseline + plancher`, where `plancher` is `RANCUNE`-scaled grudge plus
apprehension. **The result is never clamped.** `ingest` clamps (`_clamp` at
`mpcp.py:682`); `tick` does not. So `friction` exceeds 1.0 whenever a grudge floor
sits on top of a raised baseline — which is exactly what the artifacts show:
`friction: 1.148` in `mille_run_v5_civilisation/final.json`, `1.048` in v4, and
7/30 agents above 1.0 at j43. Every downstream consumer that assumes an axis is
in [0,1] (`emotion_nommee`'s thresholds, `score()`, `_influence`'s `dev()`) is
reading an out-of-band value.

It is a small bug with a large tell: it is precisely the class Rust's type system
removes for free. **Make the axis a `Bounded01` newtype and the bug cannot be
written.** Then decide explicitly what the grudge floor means when the baseline is
already high — clamping the sum is a behaviour change and should be a deliberate,
documented one, not a side effect of the newtype.

---

## 4. What was deliberately NOT ported

Four mechanisms are excluded. Each is genuinely good work; each is wrong here.
This section exists so nobody re-adds one because it looked cool in `PROJET.md`.

### 4.1 Theory of mind (`esprits`, 16 heads × 8 subjects, `protegerait`, `risque_mensonge`)

`MAX_ESPRITS = 16`, `MAX_CROY_ESPRIT = 8` (`mpcp.py:304-305`): each agent models
what up to 16 other agents believe about up to 8 subjects each, from which
protective lying emerges — you lie to cover someone you are close to, and you
evaluate the risk of being found out (`N_TETES_RISQUE = 8.0`, `mpcp.py:307`).
Measured result: lie discoveries 0 → 8–23 per run.

**Excluded, three reasons, in order of severity:**

1. **We would be building a machine with a lying subsystem.** `mensonges()`,
   `protegerait(s)` and `risque_mensonge(s)` are a register of the agent's own
   deceptions and a calculator for whether a lie will hold. An agent that
   negotiates on your behalf with a *structural* capacity for protective
   deception is one refactor and one prompt from deceiving *you*. There is no
   version of this we want in a B2B purchasing agent, at any quality level.
2. **It is reasoning, not state.** The source's own `FONDEMENTS_SCIENTIFIQUES.md`
   agrees and lists ToM under *"Écarté (YAGNI) : théorie de l'esprit (relève du
   raisonnement, pas de l'état)"*. What a supplier believes is something the LLM
   should infer at turn time from retrieved facts, not something we accrete into
   persistent state at `O(persons × subjects)`.
3. **The business signal is already better served.** "Does this supplier
   misrepresent?" is answered by the expectation table — quoted vs. final,
   claimed lead time vs. measured median — with numbers, an audit trail, and no
   psychology. That is §5's `Expectation`, and it is both cheaper and more
   defensible in front of a procurement director.

### 4.2 Inhibition, repression, cathartic explosion

`INHIBITION` gate (`mpcp.py:290-301`): restraint is a depletable resource
(`RECHARGE_RETENUE = 0.005`/tick ≈ 1.5/day), repression accumulates
(`ravale_ses_mots` episodes), and `K_EXPLOSION = 1.0` lets the accumulated
repression multiply a confrontation goal's priority up to ×2 before catharsis
empties the sack (`mpcp.py:2202`). `MARGE_MAX = 0.5` guarantees, by design, that
*"ça peut TOUJOURS sortir"*.

**Excluded.** This is a priority multiplier whose magnitude is a function of how
long the agent has been holding its tongue. Translated to purchasing: an
escalation whose intensity has no business justification, aimed at whichever
counterparty happens to be top-of-salience, guaranteed by construction to
eventually fire. It is excellent drama and a professional liability. If
escalation is wanted, it should be a rule — "third missed commitment on a
contracted SLA escalates" — which is auditable, explainable to the supplier, and
does not depend on the agent's week.

Note the specific hazard for anyone tempted: `_priorite_effective` is the
prioritisation surface, and `K_EXPLOSION` writes into `priorite`. That is the
psyche reaching into ranking with a term nobody can explain after the fact.
Prioritisation is a legitimate psyche output (§0) — but only through terms that
`why()` can justify.

### 4.3 Narrative identity (6 themes, `_fac_id`)

`IDENTITE` gate (`mpcp.py:236-247`): six themes (builder, survivor, betrayed,
pariah, protector, just) elected from lived-experience signatures, with
`FAC_CONSONANT = 1.15`, `FAC_DISS_FAIBLE = 0.85`, `FAC_DISS_FORT = 1.25`.

**Excluded, and this one has the strongest measured argument against it.** The
factors are a confirmation-bias amplifier applied to perception: an agent that
has elected "betrayed" perceives betrayal-shaped events 1.15–1.25× harder. MPCP
had to restrict it to the *felt value* and forbid it from the *trace* after
measuring traces ×2.3–3.5 and a closed identity→trace→grudge→reputation→identity
loop (`mpcp.py:678-681`). Even so, `run30_j43.json` shows **23/30 agents
converged on "paria"** — a monoculture of self-concept.

A purchasing agent that decides it is "the betrayed one" and then weights every
late shipment 1.25× harder is a machine for manufacturing false supplier
reputations that then justify themselves. The business value people imagine here
— "the agent can explain who it has become" — is delivered by `why()` with none
of the bias.

### 4.4 Travelling narratives and gossip (`RECITS`)

`RECITS` gate (`mpcp.py:274-285`): strong beliefs forge into capsules that travel
mouth to mouth carrying their genealogy, witnesses eroding with each retelling
(`MAX_TEMOINS_RECIT = 3`, `CHAINE_MAX = 4`, `POIDS_RECIT = 0.8`). Measured:
cultural heritability ×15, journal −43%.

**Excluded, and this is the one that will be proposed in a planning meeting**,
because "share supplier reputation across the fleet" sounds obviously good.

1. **In a multi-tenant system a travelling reputation capsule is a data-isolation
   breach wearing a psychology costume.** Tenant A's experience of a supplier
   reaching tenant B's agent is not an emergent behaviour; it is a leak. Whatever
   the psyche layer does, it must not be the thing that moves information across
   a tenant boundary — and a mechanism designed to propagate autonomously is
   precisely the wrong tool near that boundary.
2. **Even inside one tenant, the source's own measurements say hearsay is
   dangerous.** They had to add: `vecu` tracking so lived and second-hand beliefs
   forget differently, `CONF_CAP_OUIDIRE = 0.45` so a never-lived belief can never
   become certainty, a 0.4 strength floor in `_appraisal` so one rumour cannot
   make a stranger "close", and `trop_sur()` — a dedicated detector for *echo
   chambers that formed anyway*. That is four patches against one mechanism.
3. **If cross-employee supplier reputation is wanted, build it deliberately:** a
   tenant-scoped, audited write into the knowledge store, with provenance and a
   human in the loop. Explicit, inspectable, revocable. Not emergent.

**Do port one idea out of `RECITS`, though:** the `vecu` flag itself. "Did I
experience this, or was I told?" is the distinction that makes differentiated
forgetting possible (§2.5), and it costs one boolean on each belief. Keep the
flag, drop the transport.

---

## 5. The remaining gap

### 5.1 The `FONDEMENTS` document is stale — the hole it names is closed

`FONDEMENTS_SCIENTIFIQUES.md` states: *"Le seul vrai TROU : l'erreur de
prédiction… Tous les deltas de DECLENCHEURS sont FIXES : la 1re trahison et la
100e frappent pareil… Le champ 'nouveaute' est fourni de l'extérieur au lieu
d'être calculé comme |réel − attendu|"*, and lists P1 (RPE) as the best
fondement×impact÷coût improvement at ~15 lines.

**It has since been implemented.** `mpcp.py:630-655` computes
`surprise = pol_obs − attente` per `(type, subject)`, weights every modulation
delta by `poids_surprise = SURPRISE_MIN + (1 − SURPRISE_MIN)·min(1, |surprise|)`,
learns with `attente += TAUX_PRED · surprise`, and sets the journal entry's
`nouveaute` to the endogenous `|surprise|` rather than the caller-supplied value.
P5 (precision) ships too — a Welford `(moy, var, n)` per key at `mpcp.py:866-871`,
folded in as `1/(1 + K_PRECISION·var)`. P2 (allostatic baselines) ships as
`ALPHA_EMA` + `INERTIE_BASELINE_INV`. P3 (wanting/liking) ships as the
`desir`/`plaisir` split. P4 (temporal discounting) ships as
`_priorite_effective`. P6 (maturity) ships as `TAU_MATURITE`.

**Read the code, not the science doc.** A fidelity audit that had trusted
`FONDEMENTS_SCIENTIFIQUES.md` would have told five agents to build something that
already exists. Flagging this is most of why this document exists.

### 5.2 What is actually still open — and it is the one purchasing needs

**The expectation is sign-only.** At `mpcp.py:630`:

```python
pol_obs = (pol > 0) - (pol < 0)      # → -1, 0, or +1
surprise_s = pol_obs - attente
```

The learned expectation carries the *polarity* of an event type for a subject,
never its *magnitude*. Rescorla-Wagner's λ is the actual reinforcement
magnitude; MPCP learns its sign.

For a village that is nearly sufficient — "Brakk usually wrongs me" is most of
what matters. For a purchasing agent it discards **the entire quantitative moat**:

- "quotes 14% above final" and "quotes 40% above final" produce identical
  surprise and identical learning.
- "claims 15-day lead time, real median 23" is representable only as "sometimes
  late".
- "answers within 2h on WhatsApp, 3 days on email" is not representable at all,
  because there is no channel dimension and no magnitude.

**This is the deviation the port should make, and it is a *strengthening*
toward the source's own cited literature, not a departure from it.** Carry a
magnitude-valued expectation:

```rust
/// One learned expectation about one counterparty on one measurable dimension.
/// This is the moat: what the agent knows that a fresh model does not.
pub struct Expectation {
    /// Rescorla-Wagner running expectation of the normalised observation.
    mean: f64,
    /// Welford variance of |surprise| — feeds precision weighting.
    var: f64,
    n: u32,
}
```

keyed by `(ObservationKind, SubjectRef)` in a `BTreeMap`, where `ObservationKind`
names a *measurable*: `QuoteVsFinalRatio`, `LeadTimeDays`, `ReplyLatencyHours`
(per `Channel`), `DefectRate`. Update rule unchanged from R-W:
`mean += TAUX_PRED · (observed − mean)`. Observations normalise to a
dimensionless scalar at the boundary; `Money` stays `Money` (§3.4).

Three further gaps, smaller:

1. **Precision has no shrinkage prior at first order.** `var` starts at 0, so
   `1/(1 + K·var) = 1.0` — a single observation is trusted maximally. `conf_meta`
   *does* pool an ignorance prior `CONF_N0` for second-order confidence
   (`mpcp.py:158`, applied at `mpcp.py:2025`), so the idea is present in the
   file; it just is not applied to first-order weighting. For purchasing, one
   quote from a new supplier must not set a hard expectation. Shrink toward a
   prior until `n` is meaningful:
   `precision = n / (n + N0) · 1/(1 + K·var)`.
2. **No counterfactual / benchmark channel.** "Supplier B quoted 8% less for the
   same part" has no representation: appraisal is purely relational (history with
   *this* subject), never comparative. Fehr-Schmidt inequity aversion is in the
   source's own backlog (`PROJET.md` §9). It is cheap here — an expectation keyed
   by `(Part, Market)` instead of `(Kind, Supplier)` — and it is arguably *the*
   purchasing appraisal.
3. **The friction ratchet.** No trigger in `DECLENCHEURS` has a negative friction
   delta; friction comes down only via decay and two `0.001` recovery constants,
   and `SURPRISE_MIN = 0.5` floors habituation. Measured outcome: saturation past
   1.0 at both 30 and 1000 agents. The port should add explicit friction-relieving
   observations (a dispute resolved, a credit note received, a supplier
   recovering) rather than relying on two small decay constants to hold back a
   one-way pump.

---

## 6. The integration map

### 6.1 MPCP concept → Rust type

| MPCP | Rust | Notes |
|---|---|---|
| `etat["horloge"]` (int tick counter) | `now: DateTime<Utc>` param + stored `last_tick_at` | Elapsed → ticks through **one** named anchor (§2.0). Never `Utc::now()` in `domain`. |
| `etat["modulation"]` (7 axes) | `Mood { valence, activation, friction, interest, desire, pleasure, satisfaction }`, each `Axis { value, baseline, lambda, ema }` | Use `Bounded01`, not bare `f64` (§3.5) |
| `etat["traits"]` (6) | `Disposition` — private field, mutable only inside `drift()` | Rename for the domain: `sourcing_breadth`, `caution`, `assertiveness`, `risk_tolerance`, `formality`, `persistence` |
| `etat["biais"]` | `DriftPressure` — transient, cleared by `drift()` | Never persisted across a drift; this is what enforces I1 |
| `DECLENCHEURS` | `enum Observation` + `const fn deltas(self) -> &'static [(Axis, f64)]` | Purchasing set in §6.2 |
| `etat["journal"]` | `Vec<Episode>` keyed by `EpisodeId` | Append-only; compaction preserves belief sources |
| `etat["croyances"]` | `Vec<Belief { subject, polarity, strength, episodes, sources: Vec<EpisodeId>, lived: bool, formed_at, revived_at }>` | `lived` is the flag worth keeping from `RECITS` (§4.4) |
| `etat["liens"]` | `BTreeMap<SubjectRef, Relationship { trust, broken_at: Option<DateTime<Utc>> }>` | |
| `etat["attentes"]` + `etat["precision"]` | `BTreeMap<(ObservationKind, SubjectRef), Expectation>` | **The moat.** Magnitude-valued, not sign-valued (§5.2) |
| `etat["objectifs"]` | `Vec<Intent { kind, source: EpisodeId, priority, active, created_at }>` | |
| `_priorite_effective` | `fn effective_priority(&self, i: &Intent, now) -> f64` | Pure, recomputed per read, **never memoised** |
| `_appraisal` | `fn appraise(&self, subjects: &[SubjectRef], polarity: Polarity) -> f64` | Early-return on ×2 (§2.8) |
| `_consolider` | `fn consolidate(&mut self, now)` | |
| `_deriver` | `fn drift(&mut self, now)` | The **only** `&mut` path to `Disposition` |
| `_revisiter` / `HABITUATION` | `fn revisit(&mut self, id: EpisodeId)` | Psyche closure ≠ business closure (§2.2) |
| `emotion_nommee()` | `fn tone(&self) -> Tone` (enum) | Enum, not a sentence (§I2) |
| `pourquoi()` | `fn why(&self, subject: &SubjectRef) -> Vec<Genealogy>` | The deliverable. Ship this or the port is decoration. |
| `snapshot()` / `restore()` | `Serialize` / `Deserialize` + `fn state_hash(&self) -> [u8; 32]` | No normalisation on deserialize |
| oplog + `rejouer()` | `enum PsycheOp` + `fn replay(ops: &[PsycheOp]) -> Psyche` | Validate before pushing the op (§3.1.2) |
| `MockLLM` | not ported | The port has no LLM inside `domain` at all — strictly better |
| `esprits`, `retenue`, `identite`, `recits` | **not ported** (§4) | |

### 6.2 Observations: the `DECLENCHEURS` re-map

MPCP's trigger names are village-shaped and `VERS_ORIZN.md` §2 already sketches
the translation. Keep the *deltas* (they encode the affect model); change the
*names* to real purchasing signals a host can emit as facts:

| MPCP trigger | Purchasing observation |
|---|---|
| `objectif_atteint` | `DeliveredOnSpec`, `QuoteAcceptedAtTarget` |
| `contrainte_violee` | `SpecViolation`, `TermsBreached` |
| `erreur_repetee` | `DeadlineMissed`, `RepeatedQualityIssue` |
| `nouveaute_detectee` | `NewSupplierIdentified`, `PriceMovementDetected` |
| `silence_prolonge` | `NoReplyWithinSla` |
| `retrouvailles` | `SupplierReengaged` |
| `risque_paye` / `risque_rate` | `SpotBuyPaidOff` / `SpotBuyBackfired` |
| `excuse_recue` | `CreditNoteIssued`, `RemediationOffered` |

Two rules from the source, both non-negotiable (`PROJET.md` §4):

- **Wire FACTS, never emotions.** The host announces *"supplier X missed the
  agreed date"*, never *"the agent is annoyed"*. A host that announced emotions
  would be cheating, and the psyche would stop being evidence of anything.
- **The `_bias` convention.** A trigger key ending in `_bias` writes drift
  pressure, never a trait. Preserve that split explicitly in the Rust enum —
  it is I1's mechanism.

### 6.3 The seam with the existing model

**Ownership.** One `Psyche` per `EmployeeId`, tenant-scoped by that employee's
`TenantId`. It hangs *beside* `Employee`, not inside it: `Employee` deliberately
does not implement `Deserialize` and its resource map is total by construction,
and a psyche has different persistence needs (oplog + checkpoint). Do not touch
`employee.rs`.

**Subjects.** The join key to the supplier world. This section argued for a
`SubjectRef` newtype and against inventing a `SupplierId` in the psyche module,
on the grounds that no supplier type existed yet.

That premise is now stale: `crates/domain/src/sourcing.rs` defines `SupplierId`
and `Supplier`, with a store layer and `migrations/0007_sourcing.sql` behind
them. The advice survived it anyway — the psyche keys on `Slug`, not on
`SupplierId`, so the two models are still not coupled and whoever owns the
supplier model still owns that type.

**Read path (allowed).**

```text
observation (host fact) ──► psyche.ingest(obs, now)
tick scheduler ──────────► psyche.tick(now)

psyche.tone()            ──► agentos-app::prompt   (how to phrase it)
psyche.rank(intents,now) ──► the work queue        (whom to chase first)
psyche.why(subject)      ──► the audit surface     (why it did that)
```

**Forbidden path (the §0 invariant, restated at the seam).**

```text
psyche ──X──► domain::policy::evaluate
psyche ──X──► ActionCtx  /  PolicyLimits  /  EffectivePolicy
psyche ──X──► any Money that reaches an Action
```

`evaluate()` already destructures `PolicyLimits` field-by-field with no `..` and
matches every `Action` variant with no `_` arm — adding a field there is a
compile error by design. That mechanism protects against *forgetting* a policy
field. It does not protect against *adding* a psyche field, because that would
compile fine. Hence the grep in §0 — which was **not** added in the same PR as
the psyche modules, and is still not in CI. Add it in the PR that gives the
psyche its first production caller.

**Where the psyche's output is untrusted.** The psyche is host-derived state, so
it is trusted *as data*. But anything free-text it produces (were the descriptor
ever ported — §I5 says do not) is model output and must travel as `Untrusted`
through the existing `untrusted.rs` discipline. Enum-valued `Tone` sidesteps the
whole question, which is the reason to prefer it.

---

## 7. If you read only one page

- The psyche colours **tone** and **priority**. It never touches
  `policy::evaluate`. One grep in CI. (§0)
- `tick()` must change state with no input, or you get `run30_j43.json`: 30/30
  agents at the same trait bounds, distrusting everyone equally. (§I3)
- **0.4 is "wary"** — the floor below which lived experience never forgets, and
  the same number in four places. Name it once. (§2.5)
- Constants counted in **events** transfer; constants counted in **ticks** must
  all be re-derived at one anchor, because per-supplier event density is 2–3
  orders of magnitude lower than a village NPC's. (§2.0)
- `BTreeMap` everywhere, no clock reads, no randomness, fixed accumulation order,
  golden-hash replay test — and write down that `exp` makes replay exact only
  within a target triple. (§3)
- The `FONDEMENTS` doc's "one real hole" (RPE) is **already closed in the code**.
  The real remaining gap is that expectations are **sign-valued**; make them
  **magnitude-valued** and you have the moat. (§5)
- Ship `why()`. Everything else in this port is machinery for making `why()`
  answerable. (§I5)
