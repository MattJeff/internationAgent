//! `scripts/site-inscrits.py` ne range aucun domaine jetable dans un vivier :
//! le 2026-10-28, 1 428 inscrits @mailinator.com étaient entrés actifs dans le
//! CRM et nourrissaient accueil-gratuit. Pas de base : le script lit un PSV et
//! écrit quatre CSV.

#[test]
fn un_domaine_jetable_nentre_dans_aucun_vivier() {
    let dir = std::env::temp_dir().join(format!("site-inscrits-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dossier");
    let psv = dir.join("site-inscrits.psv");
    let row = |email: &str| format!("1|{email}|Ann Lee||free|0|50||2026-10-01|t||\n");
    let jetables = [
        "a@mailinator.com",
        "b@yopmail.com",
        "c@guerrillamail.com",
        "d@10minutemail.com",
        "e@trashmail.com",
        "f@maildrop.cc",
        "g@tempmail.net",
        "h@eu.mailinator.com",
    ];
    let mut text: String = jetables.iter().map(|e| row(e)).collect();
    text.push_str(&row("ann@agence.travel"));
    std::fs::write(&psv, text).expect("psv");

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/site-inscrits.py"
    );
    let out = std::process::Command::new("python3")
        .arg(script)
        .arg(&psv)
        .arg(&dir)
        .output()
        .expect("python3 doit être dans le PATH");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let all: String = ["quota", "actif", "dormant", "payant"]
        .iter()
        .map(|k| std::fs::read_to_string(dir.join(format!("site-{k}.csv"))).expect("csv"))
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(all.contains("ann@agence.travel"), "{all}");
    for e in jetables {
        assert!(!all.contains(e), "{e} est entré : {all}");
    }
}
