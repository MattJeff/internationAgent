//! Approaching a prospect without a reproduced finding must not compile.

use agentos_app::revenue::Outreach;
use agentos_app::vertical::Approach;

fn pitch_with_nothing_behind_it() -> Approach {
    // `Approach::new` takes an `&Evidence`, and `Evidence` can only be built by
    // `Prober::check` after the prospect's own flow said the same thing twice.
    // Wrapping a hand-written message is the way round that, so the fields are
    // private and this is the error.
    //
    // Both fields, deliberately. `known_good_at` is what `follow_up` re-checks
    // against `MAX_TRUTH_AGE`, so a forgery that could set it would not merely
    // invent a finding — it would invent one that never expires.
    Approach {
        message: Outreach {
            subject: "your booking flow is wrong".to_owned(),
            body: "trust me".to_owned(),
        },
        known_good_at: chrono::Utc::now(),
    }
}

fn main() {
    let _ = pitch_with_nothing_behind_it();
}
