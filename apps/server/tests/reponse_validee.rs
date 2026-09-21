//! La boucle minimale du fondateur, prouvée de bout en bout : **un prospect
//! répond → le siège rédige → le fondateur valide → ça part.**
//!
//! « Je te dis réponds et tu réponds, et on valide aussi la réponse. » Chaque
//! maillon existe et est testé seul ; aucun test ne les faisait jouer ensemble
//! contre le vrai binaire. Celui-ci le fait, sur le harnais d'`end_to_end.rs`
//! (`common/harness.rs`) : un serveur réel, une base privée, un `claude` qui
//! est un script, et — la pièce que ce fichier ajoute — **le vrai adaptateur
//! Resend pointé sur `scripts/faux-resend.py`**, parce que c'est la seule
//! boîte aux lettres qu'on peut remplir *depuis l'extérieur du processus* :
//! `MockEmailProvider::seed_inbound` est un appel en mémoire, et l'autre test
//! de ce répertoire nomme ce trou plutôt que de le contourner. Le faux rend un
//! `email_id` sur `POST /_faux/inbound`, sert `GET /emails/{id}` comme le vrai,
//! et journalise chaque `POST /emails` — c'est la boîte mock dont on lit qu'elle
//! est vide, puis qu'elle contient la réponse.
//!
//! # Ce que ça prouve, dans l'ordre
//!
//! 1. une société d'un siège commercial, dont la couche de rôle dit
//!    `untrusted_email_needs_approval: true` — installée par l'opérateur, avec
//!    le document du fondateur retouché d'un seul champ ; un contact importé ;
//!    un premier mail parti par une séquence (`sequences_enroll` → promesse →
//!    réveil → `send_email`), et **compté** : une ligne au journal du faux, une
//!    ligne `messages` sortante avec son corps ;
//! 2. la réponse du prospect, déposée au faux puis livrée par le webhook signé
//!    (Standard Webhooks, comme `routes/webhooks.rs`) : elle atterrit
//!    `untrusted`, la séquence passe `replied`, aucune promesse ne reste à
//!    sonner ;
//! 3. le siège est réveillé par cette réponse, son tour écrit un `send_email`
//!    vers le prospect — la Gate le retient (`require_approval`,
//!    `untrusted_email`), le brouillon est attaché, `approvals_list` et
//!    `approvals_get` le montrent, **et rien n'est parti** ;
//! 4. la clé qui fait tourner la société ne peut pas approuver ; la clé
//!    approbatrice, en restituant l'action mot pour mot, fait partir la réponse
//!    : le faux la journalise avec le corps du brouillon, `messages` la porte
//!    avec son corps, l'approbation est `redeemed` et datée.
//!
//! # Ce que la preuve a coûté hors tests
//!
//! Voir le rapport de livraison : ce qui manquait entre « approuvé » et
//! « parti » est nommé là, pas ici.

mod common;

use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agentos_store::db::Db;
use chrono::Utc;
use serde_json::{Value, json};

use common::harness::{APPROVER_SECRET, FakeModel, SECRET, Server, WEBHOOK_SECRET};

/// Le prospect. Un domaine réservé (RFC 2606) : le résolveur qui accepte
/// l'import est un faux, et rien ici ne parle au DNS.
const PROSPECT: &str = "claire@prospect.example";
/// Le siège, à l'adresse que `POST /v1/org` lui donne sur le domaine par défaut.
const SEAT: &str = "sdr@agents.example.com";

/// Le premier mail — vingt mots au moins, sans lien, sans majuscules : le
/// contrôle de délivrabilité refuse un corps quasi vide, et ce test n'est pas
/// là pour le prouver.
const FIRST_SUBJECT: &str = "Votre flux de réservation et les exigences d'entrée";
const FIRST_BODY: &str = "Bonjour Claire, en testant votre flux de réservation pour un passager \
     brésilien vers Tokyo, la page de paiement n'a demandé aucun document alors qu'un visa est \
     exigé. Je peux vous envoyer la reproduction complète si cela vous est utile.";

/// Ce que Claire répond. C'est l'aiguille du faux modèle : quand ces mots sont
/// dans le prompt — encadrés, comme tout texte étranger — le siège rédige la
/// réponse ci-dessous et non l'approche.
const REPLY_TEXT: &str = "Oui, envoyez-moi la reproduction complète, notre équipe produit veut \
     la voir cette semaine.";
const REPLY_SUBJECT: &str = "Re: Votre flux de réservation et les exigences d'entrée";
const REPLY_BODY: &str = "Bonjour Claire, merci pour votre retour rapide. Voici la reproduction \
     pas à pas du parcours, avec les captures de chaque écran et la règle d'entrée que la page \
     de paiement aurait dû vérifier avant d'accepter le passager.";

// ---------------------------------------------------------------------------
// Le faux Resend
// ---------------------------------------------------------------------------

/// `scripts/faux-resend.py`, debout à côté du serveur, et son journal.
struct FauxResend {
    child: Child,
    base: String,
    journal: std::path::PathBuf,
}

impl FauxResend {
    fn start() -> Self {
        let dir =
            std::env::temp_dir().join(format!("agentos-faux-resend-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("a directory for the fake provider");
        let journal = dir.join("envois.jsonl");
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/faux-resend.py");
        let mut child = Command::new("python3")
            .args([script, "--port", "0", "--journal"])
            .arg(&journal)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect(
                "python3 must be on PATH: scripts/faux-resend.py is the mailbox this test reads",
            );
        // La seule ligne que le script écrit, avant de servir : son origine.
        let mut base = String::new();
        std::io::BufReader::new(child.stdout.take().expect("piped stdout"))
            .read_line(&mut base)
            .expect("the fake provider announces its origin");
        let base = base.trim().to_owned();
        assert!(
            base.starts_with("http://127.0.0.1:"),
            "not an origin: {base:?}"
        );
        Self {
            child,
            base,
            journal,
        }
    }

    /// Un appel au faux, avec le jeton qu'il exige — le même que
    /// `EMAIL_API_KEY` présente, ce qui prouve au passage que la clé part.
    fn post(&self, path: &str, body: &Value) -> Value {
        let (status, answer) = curl(
            &format!("{}{path}", self.base),
            &[("Authorization", "Bearer re_faux".to_owned())],
            Some(&body.to_string()),
        );
        assert_eq!(status, 200, "the fake provider refused {path}: {answer:#}");
        answer
    }

    /// Chaque envoi que le serveur a fait, dans l'ordre : c'est la boîte.
    fn sent(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.journal)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON object per sent mail"))
            .collect()
    }

    /// Attend que `n` envois soient au journal, ou dit lesquels y sont.
    fn await_sent(&self, n: usize, within: Duration) -> Vec<Value> {
        let deadline = Instant::now() + within;
        loop {
            let sent = self.sent();
            if sent.len() >= n {
                return sent;
            }
            assert!(
                Instant::now() < deadline,
                "expected {n} mail(s) to have left through the provider, {} did: {sent:#?}",
                sent.len()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for FauxResend {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(dir) = self.journal.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// `curl`, vers n'importe quelle origine — le harnais ne parle qu'au serveur.
fn curl(url: &str, headers: &[(&str, String)], body: Option<&str>) -> (u16, Value) {
    let mut args = vec![
        "-sS".to_owned(),
        "-X".to_owned(),
        if body.is_some() { "POST" } else { "GET" }.to_owned(),
        "-w".to_owned(),
        "\n%{http_code}".to_owned(),
        url.to_owned(),
    ];
    for (name, value) in headers {
        args.push("-H".to_owned());
        args.push(format!("{name}: {value}"));
    }
    if let Some(body) = body {
        args.push("-H".to_owned());
        args.push("Content-Type: application/json".to_owned());
        args.push("-d".to_owned());
        args.push(body.to_owned());
    }
    let output = Command::new("curl")
        .args(&args)
        .output()
        .expect("curl must be on PATH");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (body, status) = text
        .rsplit_once('\n')
        .expect("curl -w writes the status on its own line");
    eprintln!("--- {url} -> {status}\n{body}");
    (
        status.trim().parse().expect("an HTTP status"),
        serde_json::from_str(body).unwrap_or(Value::Null),
    )
}

/// Attend qu'un `count(*)` atteigne `want`, ou dit où il en est.
async fn await_count(server: &Server, sql: &str, want: i64, within: Duration, why: &str) {
    let deadline = Instant::now() + within;
    loop {
        let n = server.count(sql).await;
        if n >= want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{why}: wanted {want}, have {n} for `{sql}`"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Le webhook signé, tel que Resend le livre : Standard Webhooks, trois
/// en-têtes, le secret que ce déploiement a enregistré pour `email`.
fn deliver_signed(server: &Server, id: &str, delivery: &str) -> (u16, Value) {
    let timestamp = Utc::now().timestamp().to_string();
    let signature = agentos_app::inbound::sign_webhook(
        &agentos_app::inbound::Secret::new(WEBHOOK_SECRET),
        id,
        &timestamp,
        delivery.as_bytes(),
    );
    server.curl(
        "POST",
        "/v1/webhooks/email",
        &[
            ("webhook-id", id.to_owned()),
            ("webhook-timestamp", timestamp),
            ("webhook-signature", signature),
        ],
        Some(delivery),
    )
}

// ---------------------------------------------------------------------------
// La boucle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn un_prospect_repond_le_siege_redige_le_fondateur_valide_et_ca_part() {
    let provider = FauxResend::start();

    let model = FakeModel::new();
    // L'approche : ce que le siège écrit quand la séquence le réveille avec un
    // brief. Sur l'identité, parce qu'à ce moment-là rien d'étranger n'est
    // dans le prompt.
    model.answers(
        "sdr",
        &json!({"tool": "send_email", "input": {"to": PROSPECT, "subject": FIRST_SUBJECT, "body": FIRST_BODY}})
            .to_string(),
    );
    // La réponse : ce que le siège écrit quand les mots de Claire sont dans le
    // prompt. Une aiguille et pas l'identité, parce que c'est le même siège —
    // et c'est exactement la distinction que la Gate fera ensuite.
    model.answers_when(
        "reponse",
        REPLY_TEXT,
        &json!({"tool": "send_email", "input": {"to": PROSPECT, "subject": REPLY_SUBJECT, "body": REPLY_BODY}})
            .to_string(),
    );

    let Some(server) = Server::start_with(&[
        ("AGENTOS_LLM", "cli".to_owned()),
        ("PATH", model.path()),
        // Le vrai adaptateur, redirigé : `EMAIL_API_BASE` est refusé sans
        // `AGENTOS_ALLOW_MOCKS`, que le harnais pose déjà.
        ("EMAIL_API_KEY", "re_faux".to_owned()),
        ("EMAIL_API_BASE", provider.base.clone()),
    ])
    .await
    else {
        return;
    };

    // -- 1. la société ------------------------------------------------------
    //
    // Le plafond, puis la couche de rôle : le document du fondateur, un seul
    // champ retourné — ce qu'il vient de faire sur son instance. Par le
    // sous-commande de l'opérateur, comme `orizn.rs`, et jamais par le store.
    server.install_ceiling();
    let mut layer: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/orizn-roles/sales-development.json"
        ))
        .expect("the founder's sales-development layer"),
    )
    .expect("a JSON document");
    assert_eq!(
        layer["untrusted_email_needs_approval"], false,
        "the shipped document is what this test retouches; if it now says true, drop the retouch"
    );
    assert!(
        layer["max_new_contacts_per_day"]
            .as_u64()
            .is_some_and(|n| n >= 1),
        "the seat has to be allowed one approach: {layer:#}"
    );
    layer["untrusted_email_needs_approval"] = json!(true);
    let layer_file =
        std::env::temp_dir().join(format!("sales-development-{}.json", uuid::Uuid::now_v7()));
    std::fs::write(&layer_file, layer.to_string()).expect("write the retouched layer");
    let report = server.policy(&[
        "install",
        "--tenant",
        &server.tenant.as_uuid().to_string(),
        "--role",
        "sales-development",
        &layer_file.display().to_string(),
    ]);
    let _ = std::fs::remove_file(&layer_file);
    assert!(
        report.contains("installed role layer"),
        "the operator command did not install the role layer:\n{report}"
    );

    // Un siège, sur une équipe dont le slug est le nom du rôle : c'est le
    // pointeur `team_policy.role_name` que `POST /v1/org` pose, et donc la
    // seule façon pour un siège d'être sous une couche de rôle.
    let (status, applied) = server.post(
        "/v1/org",
        Some(SECRET),
        &json!({
            "domain": "agents.example.com",
            "rows": [{
                "team": "sales-development", "name": "Commercial",
                "mission": "Trouver un défaut d'exigence d'entrée dans le flux d'un prospect et le lui montrer.",
                "head": "sdr", "title": "Sales Development",
            }],
        })
        .to_string(),
    );
    assert_eq!(status, 202, "the chart did not take: {applied:#}");
    let seat = applied["chart"][0].clone();
    let sdr = seat["employee_id"]
        .as_str()
        .expect("an employee id")
        .to_owned();

    // Le domaine d'envoi : chez ce fournisseur un domaine naît `pending`, et
    // un siège n'a pas de boîte tant qu'il ne l'est plus. C'est l'opérateur
    // qui demande la vérification, par la route qu'il a — et qui réveille les
    // sièges qui attendaient.
    let (status, verified) = server.post("/v1/domain/verify", Some(SECRET), "{}");
    assert_eq!(
        status, 200,
        "the sending domain did not verify: {verified:#}"
    );
    assert_eq!(verified["status"], "verified", "{verified:#}");

    server.await_provisioned(&sdr);
    let employee = server.await_active(&sdr);
    let email_step = employee["resources"]
        .as_array()
        .expect("resources")
        .iter()
        .find(|r| r["step"] == "email")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        email_step["state"], "ready",
        "the seat has no mailbox at the real adapter, so nothing below could leave: {employee:#}"
    );

    // La charte, **avant** d'inscrire qui que ce soit : la promesse d'une
    // séquence sonne tout de suite, et un siège sans charte la consomme en
    // `no_charter` sans que rien ne la rejoue (répétition générale du
    // 2026-09-19). La cadence est posée un jour plus loin : ce qui réveille
    // ici est la séquence, pas l'horloge.
    let (status, charter) = server.put(
        &format!("/v1/employees/{sdr}/initiative"),
        &json!({
            "interval_secs": 86400,
            "objective": {
                "role": "sales-development", "segment": "airline", "market": "FR",
                "target_accounts": ["Prospect Air"],
            },
        })
        .to_string(),
    );
    assert_eq!(status, 200, "the charter did not take: {charter:#}");

    // Le contact, par l'importeur du produit — en process, avec le résolveur
    // faux, parce que le serveur résout les MX contre le vrai DNS et qu'un
    // domaine réservé n'y a pas de boîte. Le CSV est celui du fondateur, huit
    // colonnes, en-tête compris.
    let db = Db::connect(&server.database_url).await.expect("connect");
    {
        use agentos_app::prospects::{List, import};
        let mx = agentos_app::mocks::MockMailDomains::accepting(&["prospect.example"]);
        let csv = format!(
            "email,first_name,last_name,company_name,phone_number,website,linkedin_profile,location\n\
             {PROSPECT},Claire,Martin,Prospect Air,,https://prospect.example,,Paris\n"
        );
        let mut tx = db.tenant_tx(server.tenant).await.expect("tenant tx");
        let report = import(
            &mut tx,
            &List {
                segment: "airline",
                country: "FR",
                employee_id: None,
                source: Some("reponse_validee"),
            },
            &mx,
            &csv,
            Utc::now(),
        )
        .await
        .expect("import one prospect");
        tx.commit().await.expect("commit the import");
        assert_eq!(report.contacts_created, 1, "{:?}", report.refused);
    }
    let (status, contacts) = server.get(&format!("/v1/contacts?email={PROSPECT}"), Some(SECRET));
    assert_eq!(status, 200, "{contacts:#}");
    let contact = contacts["contacts"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the imported contact is not listed: {contacts:#}"))
        .to_owned();

    // La séquence : un mail, deux jours, un mail. Trois pas et pas un, parce
    // que la preuve du point 2 est qu'une réponse **arrête** ce qui restait à
    // faire — et un run d'un pas n'a plus rien à arrêter une fois le premier
    // mail parti.
    let (status, sequence) = server.post(
        "/v1/sequences",
        Some(SECRET),
        &json!({
            "name": "reproduction",
            "steps": [
                {"kind": "email", "brief": "Écrire à ce prospect pour lui signaler le défaut trouvé dans son flux."},
                {"kind": "wait", "hours": 48},
                {"kind": "email", "brief": "Relancer si rien n'est revenu."},
            ],
        })
        .to_string(),
    );
    assert_eq!(status, 201, "{sequence:#}");
    let sequence_id = sequence["id"].as_str().expect("a sequence id").to_owned();
    let (status, run) = server.post(
        &format!("/v1/sequences/{sequence_id}/enroll"),
        Some(SECRET),
        &json!({"contact_id": contact, "employee_id": sdr}).to_string(),
    );
    assert_eq!(status, 201, "the enrolment was refused: {run:#}");

    // -- le premier mail part, par un tour -----------------------------------
    //
    // Rien ici ne l'envoie : la boucle des séquences joue le pas, réserve une
    // promesse, la boucle d'initiative la voit sonner, réveille le siège avec
    // le brief, le modèle — notre script — demande `send_email`, la Gate
    // l'autorise (un tour qui n'a rien lu d'étranger) et le vrai adaptateur le
    // poste au faux. Chaque étape est dans le binaire ; ce test regarde.
    let prompt = model.await_prompt("You are sdr,", Duration::from_secs(180));
    assert!(
        !prompt.contains(REPLY_TEXT),
        "the first turn already carried the prospect's words, which have not been written yet"
    );
    let sent = provider.await_sent(1, Duration::from_secs(120));
    assert_eq!(sent.len(), 1, "one approach, exactly: {sent:#?}");
    assert_eq!(sent[0]["to"], json!([PROSPECT]), "{sent:#?}");
    assert_eq!(
        sent[0]["subject"], FIRST_SUBJECT,
        "what left is not what the model wrote: {sent:#?}"
    );
    let first_id = sent[0]["id"]
        .as_str()
        .expect("the provider's id")
        .to_owned();

    // Et le produit s'en souvient : la ligne sortante, **avec son corps**,
    // écrite par `Effects::chase` après l'envoi. `LIKE` parce que le pied de
    // page d'opt-out est ajouté au corps envoyé, pas au corps enregistré.
    //
    // `provider_message_id IS NOT NULL` partout où ce test compte ce qui est
    // **parti** : le tour dépose aussi sa propre prose (« noted. ») sur le fil,
    // en ligne sortante sans identifiant fournisseur — c'est le journal de la
    // conversation, pas un envoi, et le compter ferait rougir « rien n'est
    // parti » sur une phrase que personne n'a reçue.
    const LEFT: &str =
        "direction = 'outbound' AND channel = 'email' AND provider_message_id IS NOT NULL";
    let outbound_with = |body: &str| {
        format!(
            "SELECT count(*) FROM messages WHERE {LEFT} AND body LIKE '{}%'",
            body.replace('\'', "''")
        )
    };
    let left = format!("SELECT count(*) FROM messages WHERE {LEFT}");
    await_count(
        &server,
        &outbound_with(FIRST_BODY),
        1,
        Duration::from_secs(30),
        "the approach left through the provider and `messages` never recorded it",
    )
    .await;
    assert_eq!(
        server
            .count("SELECT count(*) FROM sequence_runs WHERE state = 'active'")
            .await,
        1,
        "the run has two steps left and must still be active, or there is nothing for a reply to stop"
    );

    // -- 2. le prospect répond ------------------------------------------------
    //
    // Déposé au faux (`seed_inbound`, vu de l'extérieur), puis livré par le
    // webhook signé — métadonnées seulement, comme Resend : le corps, c'est la
    // boucle entrante qui ira le chercher sur `GET /emails/{id}`.
    let seeded = provider.post(
        "/_faux/inbound",
        &json!({
            "from": PROSPECT, "to": [SEAT], "subject": REPLY_SUBJECT, "text": REPLY_TEXT,
            "created_at": Utc::now().to_rfc3339(),
        }),
    );
    let reply_id = seeded["id"]
        .as_str()
        .expect("the provider's id for the reply")
        .to_owned();
    let delivery = json!({
        "type": "email.received", "created_at": Utc::now().to_rfc3339(),
        "data": {"email_id": reply_id, "from": PROSPECT, "to": [SEAT]},
    })
    .to_string();
    let (status, accepted) = deliver_signed(&server, "msg_rv_reply", &delivery);
    assert_eq!(status, 202, "a correctly signed delivery: {accepted:#}");

    // Atterrie **non fiable** : tout ce que l'expéditeur a choisi l'est, et
    // c'est ce label qui, deux étapes plus loin, fait de la réponse du siège
    // une demande d'approbation plutôt qu'un envoi.
    await_count(
        &server,
        &format!(
            "SELECT count(*) FROM messages WHERE direction = 'inbound' \
               AND provider_message_id = '{reply_id}' AND trust_label = 'untrusted'"
        ),
        1,
        Duration::from_secs(60),
        "the signed delivery never landed as an untrusted inbound message",
    )
    .await;
    // La relance est annulée, des deux côtés qu'elle a : le run passe
    // `replied` (sa relance à 48 h n'est plus due), et aucune promesse ne
    // reste à sonner sur ce fil.
    assert_eq!(
        server
            .count("SELECT count(*) FROM sequence_runs WHERE state = 'replied' AND next_at IS NULL")
            .await,
        1,
        "the prospect answered and the sequence would have chased them anyway"
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM appointments WHERE rang_at IS NULL")
            .await,
        0,
        "a promise to write again is still pending after the person wrote back"
    );

    // -- 3. le siège rédige, et la Gate retient -------------------------------
    //
    // Le réveil est celui de `inbound::land` ; le prompt porte les mots de
    // Claire, encadrés ; le script y répond par un `send_email`. La couche de
    // rôle dit qu'un mail écrit après avoir lu du texte étranger attend un
    // humain — et le tour attache le brouillon, sinon la file ne montrerait
    // que « peut-on écrire à claire@… ».
    let prompt = model.await_prompt(REPLY_TEXT, Duration::from_secs(120));
    assert!(
        prompt.contains("You are sdr,"),
        "the reply woke somebody else:\n{prompt}"
    );

    let deadline = Instant::now() + Duration::from_secs(60);
    let pending = loop {
        let (status, queue) = server.get("/v1/approvals", Some(SECRET));
        assert_eq!(status, 200, "{queue:#}");
        let found = queue["approvals"]
            .as_array()
            .expect("approvals")
            .iter()
            .find(|row| row["state"] == "pending" && row["action"]["action"] == "email_send")
            .cloned();
        if let Some(row) = found {
            break row;
        }
        assert!(
            Instant::now() < deadline,
            "the turn answered with `send_email` and no approval was filed: the role layer's \
             `untrusted_email_needs_approval` did not reach the gate, or `read_outside` is \
             false on a turn that read a stranger's mail: {queue:#}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let approval_id = pending["id"].as_str().expect("an approval id").to_owned();
    assert_eq!(pending["action"]["to"], PROSPECT, "{pending:#}");
    assert_eq!(
        pending["draft"]["body"], REPLY_BODY,
        "the queue shows the address and not the words the founder is asked to approve: {pending:#}"
    );
    assert_eq!(pending["draft"]["subject"], REPLY_SUBJECT, "{pending:#}");
    assert_eq!(pending["draft"]["to"], PROSPECT, "{pending:#}");

    let (status, shown) = server.get(&format!("/v1/approvals/{approval_id}"), Some(SECRET));
    assert_eq!(status, 200, "{shown:#}");
    assert_eq!(shown["state"], "pending", "{shown:#}");
    assert_eq!(
        shown["action"], pending["action"],
        "the single read and the queue disagree"
    );
    assert_eq!(
        shown["draft"], pending["draft"],
        "the single read and the queue disagree"
    );

    // **Rien n'est parti.** La boîte du fournisseur n'a que l'approche, et
    // `messages` aussi.
    assert_eq!(
        provider.sent().len(),
        1,
        "a mail left while its approval was pending: {:#?}",
        provider.sent()
    );
    assert_eq!(
        server.count(&left).await,
        1,
        "an outbound row exists for a letter nobody approved"
    );

    // -- 4. le fondateur valide -----------------------------------------------
    //
    // La clé qui a créé le siège, importé le contact et lu la file ne peut pas
    // approuver : elle ne porte pas le rôle. (Le demandeur est le siège, et un
    // siège n'a pas de clé — `self_approval` est l'autre garde, pour une clé
    // qui demanderait et accorderait ; celle-ci tombe avant.)
    let approve_body = json!({"action": shown["action"]}).to_string();
    let (status, refused) = server.post(
        &format!("/v1/approvals/{approval_id}/approve"),
        Some(SECRET),
        &approve_body,
    );
    assert_eq!(
        status, 403,
        "the operator key that runs the company approved the seat's own letter: {refused:#}"
    );
    assert_eq!(refused["code"], "role_required", "{refused:#}");
    assert_eq!(
        provider.sent().len(),
        1,
        "a refused approval sent the letter anyway"
    );

    // La clé approbatrice, avec l'action restituée telle que `approvals_get`
    // la rend — c'est ce qui est re-haché, et un mot changé serait
    // `approval_action_mismatch`.
    let (status, redeemed) = server.curl(
        "POST",
        &format!("/v1/approvals/{approval_id}/approve"),
        &[("Authorization", format!("Bearer {APPROVER_SECRET}"))],
        Some(&approve_body),
    );
    assert_eq!(
        status, 200,
        "the approver could not spend the approval: {redeemed:#}"
    );
    assert_eq!(redeemed["state"], "redeemed", "{redeemed:#}");
    let provider_id = redeemed["email"]["provider_message_id"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("the reply was approved and no provider id came back: {redeemed:#}")
        })
        .to_owned();

    // **Ça part** — et ce qui part est le brouillon, mot pour mot, en réponse
    // au message de Claire et non en message neuf.
    let sent = provider.await_sent(2, Duration::from_secs(30));
    let letter = sent
        .iter()
        .find(|mail| mail["id"] == provider_id)
        .unwrap_or_else(|| {
            panic!("the provider id the route reported is not in the box: {sent:#?}")
        });
    assert_eq!(letter["to"], json!([PROSPECT]), "{letter:#}");
    assert_eq!(letter["subject"], REPLY_SUBJECT, "{letter:#}");
    assert!(
        letter["text"]
            .as_str()
            .is_some_and(|text| text.starts_with(REPLY_BODY)),
        "the letter that left is not the draft the founder read: {letter:#}"
    );
    assert_eq!(
        letter["headers"]["In-Reply-To"],
        json!(format!("<{reply_id}>")),
        "the validated reply left as a new message: the prospect sees a stranger writing twice, \
         not an answer to what they wrote: {letter:#}"
    );
    assert_ne!(letter["id"], first_id, "{sent:#?}");

    // Et le produit s'en souvient, comme du premier : la ligne sortante avec
    // son corps. Sans elle le fil s'arrête à la question de Claire, et le
    // prochain réveil relit une conversation où personne n'a répondu.
    await_count(
        &server,
        &outbound_with(REPLY_BODY),
        1,
        Duration::from_secs(30),
        "the validated reply left through the provider and `messages` never recorded it",
    )
    .await;
    assert_eq!(
        server.count(&left).await,
        2,
        "the approach and the reply, and nothing else"
    );

    // L'approbation est décidée : `redeemed`, par la clé approbatrice, datée.
    let (status, decided) = server.get(&format!("/v1/approvals/{approval_id}"), Some(SECRET));
    assert_eq!(status, 200, "{decided:#}");
    assert_eq!(decided["state"], "redeemed", "{decided:#}");
    assert!(
        decided["decided_at"].as_str().is_some(),
        "a redeemed approval carries no decision time: {decided:#}"
    );

    // La piste : la retenue, puis l'autorisation qui l'a levée — et l'approche
    // du début, autorisée sans question.
    let trail = server.audit_summary().await;
    let happened = |line: &str| trail.iter().any(|row| row.starts_with(line));
    for ruling in [
        "email_send/require_approval/untrusted_email",
        "email_send/allow",
        "message_received/-",
    ] {
        assert!(happened(ruling), "{ruling} is not in the trail: {trail:#?}");
    }

    server.shutdown();
}
