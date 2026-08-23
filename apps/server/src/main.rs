//! One binary: the HTTP control plane plus three tokio loops
//! (provisioning, outbox, inbound). No separate worker binaries.

mod auth; // U30
mod config; // U30
mod error; // U30
mod loops; // U35 U36 U37
mod routes; // U31 U32 U33 U34

fn main() {
    // filled by U30
}
