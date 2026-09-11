//! Every migration's first line names the file it is in, and every line in the
//! workspace that names a migration names one that exists.
//!
//! Two tests, one subject: **a migration's filename is its identity, so a claim
//! about that filename is a claim about which migration you are looking at.**
//! [`every_migration_header_names_its_own_file`] is the claim the migration
//! makes about itself; [`every_migration_a_comment_cites_is_a_migration_that_exists`]
//! is the claim two hundred comments and documents make about it. Both cost a
//! directory walk and no database.
//!
//! # The bug this exists to stop coming back
//!
//! Migration files get renumbered. Two units developed in parallel both claim
//! `0025`, one of them is renamed on the way in, and the header — which opens
//! `-- 0025_positions: what a team is for` and is the first thing anyone reads
//! — keeps announcing the number the file no longer has. Ten files in this
//! workspace drifted that way before anybody counted, and two Rust modules
//! pointed at a `migrations/0023_model_usage.sql` that has never existed.
//!
//! Nothing breaks. That is the problem: a header is load-bearing exactly when
//! somebody is lost, and being lost is when a wrong signpost costs the most.
//! A migration is also the one kind of file whose *name* is its identity —
//! `sqlx` keys `_sqlx_migrations` on the version prefix — so a header and a
//! filename that disagree are two different claims about which migration this
//! is.
//!
//! A pass was already done by hand once and missed nine of the ten, which is
//! the argument for a test rather than a second pass: this costs a directory
//! walk and no database, and it cannot be half-done.
//!
//! # What counts as naming the file
//!
//! The first line is `-- <stem>` followed by anything: a colon and a sentence,
//! a dash, or nothing. `<stem>` is the filename without `.sql`, verbatim. The
//! prose after it is the author's and this test has no opinion about it.

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn every_migration_header_names_its_own_file() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above this crate")
        .join("migrations");

    let mut checked = 0usize;
    let mut wrong = Vec::new();

    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    entries.sort();

    for path in entries {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a .sql file has a UTF-8 stem")
            .to_owned();
        let body = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {stem}: {err}"));
        let first = body.lines().next().unwrap_or_default();
        checked += 1;

        // `-- <stem>` and then anything, or nothing. The delimiter after the
        // stem must not be a word character, or `0002_tenants` would be
        // accepted by a file called `0002_tenants_and_keys.sql`.
        let named = first.strip_prefix("-- ").is_some_and(|rest| {
            rest.strip_prefix(stem.as_str())
                .is_some_and(|tail| !tail.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
        });
        if !named {
            wrong.push(format!("{stem}.sql opens with {first:?}"));
        }
    }

    // A directory walk that finds nothing passes, and would keep passing after
    // somebody moves `migrations/`. The count is the guard against that, and
    // the number is deliberately a floor rather than an equality: adding a
    // migration must not turn this test red for the wrong reason.
    assert!(
        checked >= 25,
        "only {checked} migrations found in {} — this test walked the wrong directory",
        dir.display()
    );

    assert!(
        wrong.is_empty(),
        "a migration's first line must name its own file, because that line is \
         what somebody reads when they are lost:\n  {}",
        wrong.join("\n  ")
    );
}

/// **A comment that names a migration names one that is there.**
///
/// # Why this is the only prose in the workspace worth guarding
///
/// Six passes over this tree have each found the same kind of defect: a
/// sentence asserting a fact about the code that stopped being true. Most of
/// them cannot be guarded and should not be. "over all five packs" is wrong
/// because the table grew a sixth row, and no test can know that the "five" in
/// that sentence counts packs rather than fields, stages or currencies — a
/// checker for it would have to read English, and one that guesses would fire
/// on "Two rules carry the design" and be deleted inside a week. That argument
/// is `scoped_deletes.rs`'s and it is the right one.
///
/// A **citation** is different, and it is the exception that carries its own
/// proof: `0021_autonomy.sql` is not an opinion about the code, it is a
/// filename, and a filename is on disk or it is not. There is no judgement, no
/// natural language, and no false positive available.
///
/// It is also the class that keeps happening, because migrations are the one
/// kind of file here that gets **renumbered**: two units both claim `0025`, one
/// is renamed on the way in, and every comment pointing at the old number now
/// sends the next reader to a migration about something else entirely. When
/// this test was written it found nine, in seven modules, none of which any
/// previous pass had caught:
///
/// | said | meant |
/// |---|---|
/// | `0002_approvals.sql` | `approvals` is in `0001_core.sql`; `0002` is provisioning |
/// | `0013_identity.sql` ×2 | `0014_identity.sql` |
/// | `0013_proof_of_need.sql` ×2 | `0015_proof_of_need.sql` |
/// | `0017_initiative.sql` ×2 | `0020_initiative.sql` |
/// | `0021_autonomy.sql` ×2 | `0022_autonomy.sql` |
///
/// Every one of them points at a real file about a different subject, which is
/// the worst version of this: `0013` exists, so a reader who follows the
/// citation lands somewhere plausible and reads the wrong schema. Nothing
/// breaks. A wrong signpost costs the most exactly when somebody is lost.
///
/// # What is checked
///
/// Any `NNNN_something.sql` appearing anywhere in `crates/`, `apps/`, `docs/`,
/// `migrations/`, `scripts/` or the top-level markdown must be a file in
/// `migrations/`. Not "a migration with that number" — the whole name, because
/// the number is the half that survives a renumber and the description is the
/// half that says which one you meant.
///
/// # If this fails on something that is genuinely fine
///
/// One case is: a sentence that is *about* a migration that does not exist —
/// this file's own docs say `0023_model_usage.sql` has never existed, and the
/// header rule above is explained with an invented `0002_tenants_and_keys.sql`.
/// Both are in this file, and this file is skipped, the same self-exclusion
/// `scoped_deletes.rs` makes for the same reason. There is deliberately no way
/// to suppress it from anywhere else: a comment that needs to name a migration
/// that is not there is a comment that should name the one that is.
///
/// The other case is a citation **inside `migrations/` itself**, and it is the
/// one to think about before reaching for an editor: sqlx checksums the whole
/// file, comments and all, and `_sqlx_migrations` holds that checksum. Fixing a
/// comment in an applied migration turns every existing database — every
/// laptop, every deployment — into `VersionMismatch` on next boot. If this ever
/// fires there, the answer is a new migration that says the true thing, not a
/// one-word edit to the old one. `0019_mcp_operator_writes.sql` carries a stale
/// sentence about `db.rs` for exactly this reason and is deliberately left
/// alone; it names no filename, so this test does not see it.
#[test]
fn every_migration_a_comment_cites_is_a_migration_that_exists() {
    let root = workspace_root();
    let on_disk = migration_stems(&root.join("migrations"));
    let mut wrong = Vec::new();
    let mut checked = 0usize;

    for file in prose_files(&root) {
        // Not UTF-8 is not this test's business; every source file here is.
        let Ok(source) = fs::read_to_string(&file) else {
            continue;
        };
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();

        for (line, cited) in citations(&source) {
            checked += 1;
            if !on_disk.contains(&cited) {
                wrong.push(format!(
                    "{shown}:{line}: cites {cited}.sql, which is not there"
                ));
            }
        }
    }

    // A walk that finds nothing passes. Both numbers are floors: the workspace
    // cites migrations constantly and gains more of them, and neither growing
    // should turn this red for the wrong reason.
    assert!(
        checked >= 40,
        "only {checked} migration citations found under {} — the walk is wrong, \
         not the workspace",
        root.display()
    );

    assert!(
        wrong.is_empty(),
        "these lines send the next reader to a migration that does not exist, \
         and every one of them points somewhere plausible instead:\n  {}\n\n\
         Migrations get renumbered; the citations do not follow on their own.",
        wrong.join("\n  ")
    );
}

/// Every `NNNN_name` cited in `source`, with its line number.
///
/// Comments are not filtered out, deliberately, and it makes no difference: a
/// filename in a string literal — `include_str!`, a test fixture, an error
/// message — has to be right for exactly the same reason. What *is* excluded is
/// the number on its own: "migration 0025" names a slot rather than a file, and
/// the slot is always occupied, so checking it would pass while the sentence
/// stayed wrong. Only the full `NNNN_description.sql` says which migration.
fn citations(source: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();

    for (i, line) in source.lines().enumerate() {
        let bytes = line.as_bytes();
        for start in 0..bytes.len() {
            // Four digits, then `_`, and not preceded by a word character —
            // `v20240102_x.sql` is somebody else's naming scheme, not ours.
            if start + 5 > bytes.len()
                || !bytes[start..start + 4].iter().all(u8::is_ascii_digit)
                || bytes[start + 4] != b'_'
            {
                continue;
            }
            if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
                continue;
            }
            let rest = &line[start..];
            let Some(end) = rest.find(".sql") else {
                continue;
            };
            let stem = &rest[..end];
            // The description is `[a-z0-9_]`, which is what every migration in
            // this directory uses. Anything else is not one of ours.
            if stem[5..]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && stem.len() > 5
            {
                found.push((i + 1, stem.to_owned()));
            }
        }
    }

    found
}

/// The stems of every `.sql` in `dir`, e.g. `0014_identity`.
fn migration_stems(dir: &Path) -> Vec<String> {
    let mut stems: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .filter_map(|path| path.file_stem()?.to_str().map(str::to_owned))
        .collect();
    stems.sort();
    assert!(
        stems.len() >= 25,
        "only {} migrations in {}; this test walked the wrong directory",
        stems.len(),
        dir.display()
    );
    stems
}

/// Every file in the workspace that can carry a citation: Rust, markdown, SQL
/// and shell.
///
/// `target/` is skipped because it is a copy of the world, and this file is
/// skipped because its own docs are *about* migrations that do not exist.
fn prose_files(root: &Path) -> Vec<PathBuf> {
    const KINDS: [&str; 4] = ["rs", "md", "sql", "sh"];
    let mut out = Vec::new();
    let mut stack = vec![
        root.join("crates"),
        root.join("apps"),
        root.join("docs"),
        root.join("migrations"),
        root.join("scripts"),
    ];
    // The two at the root that carry the long-form claims.
    out.extend(
        ["README.md", "SPEC.md"]
            .into_iter()
            .map(|name| root.join(name))
            .filter(|path| path.is_file()),
    );

    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| KINDS.contains(&ext))
                && !path.ends_with("migration_headers.rs")
            {
                out.push(path);
            }
        }
    }

    assert!(
        out.len() > 100,
        "found only {} files under {}; the walk is wrong, not the workspace",
        out.len(),
        root.display()
    );
    out
}

/// `crates/app` is two levels below the workspace root.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/app is two levels down")
        .to_path_buf()
}

/// **Une migration appliquée ne se modifie plus, et ceci le prouve sans base.**
///
/// sqlx empreinte le fichier **entier**, prose comprise, et compare à ce qu'il a
/// enregistré le jour où il l'a appliquée. Un commentaire retouché dans un
/// fichier que la production a déjà joué fait donc refuser le démarrage :
/// `refusing to start: migration 11 was previously applied but has been
/// modified`. C'est arrivé le 2026-09-11, sur deux noms d'entreprise substitués
/// dans de la prose ; le retour arrière du déploiement a rattrapé, la
/// production n'a pas eu de trou.
///
/// # Pourquoi une liste d'empreintes et pas le garde qui existait
///
/// `scripts/test.sh` tient une base de référence entre deux exécutions et
/// attrape exactement ça. Elle a deux faiblesses, et les deux ont joué :
///
/// * **elle est locale** — la CI repart d'un conteneur vide à chaque fois, donc
///   toutes ses migrations sont neuves et rien ne peut rougir ;
/// * **elle se supprime** — et quand une vague ajoute trois migrations, la
///   supprimer est le geste juste. Il l'a été deux fois ce jour-là, et la
///   troisième fois il ne l'était plus.
///
/// Un fichier d'empreintes n'a ni l'une ni l'autre : il voyage avec le dépôt,
/// il rougit sur la machine de tout le monde, et il n'y a rien à supprimer pour
/// le faire taire. Ajouter une migration demande une ligne de plus, ce qui est
/// le prix — et c'est aussi le moment où l'on relit qu'on ajoute plutôt qu'on
/// édite.
#[test]
fn aucune_migration_deja_publiee_na_ete_modifiee() {
    use std::collections::BTreeMap;

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
    let manifest = std::fs::read_to_string(format!("{root}/EMPREINTES"))
        .expect("migrations/EMPREINTES : la liste des empreintes");
    let pinned: BTreeMap<&str, &str> = manifest
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (sum, name) = line.split_once("  ").expect("«<empreinte>  <fichier>»");
            (name, sum)
        })
        .collect();

    let mut seen = BTreeMap::new();
    for entry in std::fs::read_dir(root).expect("le dossier des migrations") {
        let path = entry.expect("une entrée").path();
        if path.extension().is_none_or(|e| e != "sql") {
            continue;
        }
        let name = path
            .file_name()
            .expect("un nom")
            .to_str()
            .expect("un nom lisible")
            .to_owned();
        let bytes = std::fs::read(&path).expect("lire la migration");
        seen.insert(name, sha256(&bytes));
    }

    for (name, sum) in &seen {
        match pinned.get(name.as_str()) {
            Some(expected) if *expected == sum => {}
            Some(_) => panic!(
                "{name} a changé depuis son empreinte. Si cette migration a déjà tourné quelque \
                 part — et la production en fait partie — la remettre **octet pour octet** depuis \
                 le commit qui l'a ajoutée, et mettre la correction dans une migration NEUVE : \
                 sqlx empreinte le fichier entier, un commentaire compte autant qu'une colonne, \
                 et toute base neuve continuera de passer pendant que les anciennes refusent de \
                 démarrer. Si elle n'a jamais été déployée, mettre son empreinte à jour dans \
                 `migrations/EMPREINTES` :\n  {sum}  {name}"
            ),
            None => panic!(
                "{name} n'a pas d'empreinte. Ajouter cette ligne à `migrations/EMPREINTES` dans le \
                 même commit :\n  {sum}  {name}"
            ),
        }
    }

    for name in pinned.keys() {
        assert!(
            seen.contains_key(*name),
            "{name} est empreint et n'existe plus : une migration ne se supprime pas, toute base \
             qui l'a jouée la porte encore"
        );
    }
}

/// SHA-256, écrit ici plutôt que tiré d'une dépendance : ce test n'a besoin que
/// d'une empreinte stable, et une caisse de plus dans `dev-dependencies` se
/// paie à chaque compilation de tout le monde.
fn sha256(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut message = bytes.to_vec();
    let bits = (bytes.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bits.to_be_bytes());

    let (blocks, _) = message.as_chunks::<64>();
    for block in blocks {
        let mut w = [0u32; 64];
        let (words, _) = block.as_chunks::<4>();
        for (i, word) in words.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(value);
        }
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}
