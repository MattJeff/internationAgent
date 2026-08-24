//! The agent's psyche: what it accumulates about the people it deals with.
//!
//! This is a port of a subset of MPCP (*Moteur de Psyché de PNJ Déterministe*),
//! retargeted from a village of NPCs to a single international purchasing
//! employee whose counterparties are suppliers.
//!
//! # The governing invariant
//!
//! **The psyche influences TONE and PRIORITISATION. It never influences
//! AUTHORISATION.** [`crate::policy::evaluate`] stays a pure function of the
//! policy and the action; nothing in this module is ever an input to it. A
//! frustrated agent must accept exactly the prices a calm one would. MPCP
//! states the same rule for itself — *"l'identité ne colore QUE le ressenti,
//! jamais la dynamique"*.
//!
//! Read the psyche to decide *what to propose*, *whom to chase first* and *how
//! to phrase it*. Never to decide *what is allowed*.
//!
//! # Determinism
//!
//! Nothing here reads the clock or a random source: instants arrive as
//! parameters and collections are ordered maps, so the same event sequence
//! replays to the same state, bit for bit.

pub mod beliefs;
pub mod expectation;
pub mod forgetting;
pub mod links;
