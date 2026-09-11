//! Les outils que le serveur MCP annonce, un module par domaine.
//!
//! Trois modules, découpés le 2026-09-10 pour que trois chantiers avancent en
//! parallèle sans se marcher dessus, et gardés ensuite parce que le découpage
//! est aussi celui d'un lecteur : ce que la société **est**, ce qu'elle
//! **vend**, ce qu'elle **exploite**.
//!
//! Chaque module rend ses lignes et rien d'autre. L'assemblage est ici, et
//! [`registry`] est le seul endroit qui connaît la liste entière — c'est lui
//! que les tests d'unicité et de couverture des routes interrogent.
//!
//! # La convention de nommage, et pourquoi elle est écrite ici
//!
//! Le `name`, le `title` et la `description` d'un outil ne sont pas de la
//! documentation : ce sont **l'interface**. C'est littéralement ce qu'un modèle
//! lit pour décider quel outil appeler, et ce qu'un humain lit dans la liste de
//! son terminal. Les 116 lignes ont été écrites en un jour par trois mains
//! parallèles, chacune dans son fichier ; elles marchaient toutes et elles ne
//! se ressemblaient pas. La convention ci-dessous a été **relue sur la table
//! entière** le 2026-09-11 plutôt qu'inventée, puis appliquée partout.
//!
//! ## `name` : `domaine[_objet]_verbe`
//!
//! **Le domaine d'abord, le verbe toujours en dernier.** Le domaine d'abord
//! parce qu'un client trie la liste et qu'un modèle la parcourt : les lignes
//! d'un même sujet doivent se toucher, et `company_health_get` se lit à côté de
//! `company_create` là où `health_company` tombait entre `halt_` et
//! `interview_`. Le verbe en dernier parce que c'est la seule position où on
//! peut le **vérifier** — `the_naming_convention_holds` refuse un
//! dernier segment qui n'est pas un verbe, ce qui aurait attrapé `domain_dns`,
//! `work_board`, `browser_task` et `integrations_catalog`. Un verbe placé avant
//! son complément est donc faux : `booking_set_open` est devenu
//! `booking_open_set`, `domain_set_cap` est devenu `domains_cap_set`.
//!
//! **Le domaine est au pluriel si la société en possède plusieurs**
//! (`employees`, `teams`, `quotes`, `domains`), au singulier si elle n'en a
//! qu'un (`org`, `halt`, `window`, `model`, `company`). Il ne **varie jamais
//! avec le verbe** : la paire `teams_members_list` / `teams_member_add`, qui
//! mettait le pluriel pour lire et le singulier pour écrire, n'apprenait rien à
//! personne et coûtait un aller-retour à chaque appel d'écriture ; c'est
//! `teams_members_add`. Même raison pour `domain_get` / `domain_list` /
//! `domain_register`, qui décrivaient tantôt le domaine principal, tantôt la
//! collection : la collection gagne (`domains_*`) et le singulier redevient ce
//! qu'il désigne vraiment, `domains_primary_get`.
//!
//! **Les verbes sont une liste fermée** (`VERBS`, dans les tests) : `list` rend
//! plusieurs lignes, `get` en rend une — une ligne, un document, ou un rapport
//! calculé sur une fenêtre ; `set` **remplace en entier**, `create` et `add`
//! ajoutent sans remplacer, `remove` retire. Partout ailleurs, le verbe du
//! métier, parce qu'il dit ce qu'aucun verbe générique ne dirait :
//! `approvals_approve`, `sequences_enroll`, `employees_terminate`. Deux
//! conséquences voulues : `policy_role_put` est devenu `policy_role_set` (un
//! `PUT` est une méthode HTTP, pas un verbe qu'un modèle comprend) et
//! `files_put` est devenu `files_create`, parce que cette route ne remplace
//! rien — un nom déjà pris est un 409, et `put` promettait le contraire.
//!
//! ## `title` : le résultat, pas l'acte
//!
//! Une ligne, sans point final, majuscule initiale. Le titre s'affiche dans une
//! liste, à côté de cent autres : il doit dire **ce qu'on obtient**, pas
//! répéter le nom en français. « Le plafond quotidien d'une équipe, ce qu'elle
//! a déjà réservé, et ce qui reste » fait choisir ; « Lire le budget » ne fait
//! rien choisir. Pas de point final parce que ce n'est pas une phrase — et
//! parce qu'un point final est la première chose qui diverge entre trois mains.
//!
//! ## `description` : trois temps, dans cet ordre
//!
//! 1. **Ce que ça fait**, et ce que ça rend — la seule partie qu'un nom de
//!    route laisse deviner.
//! 2. **Quand celui-ci plutôt qu'un autre**, en nommant l'autre. C'est la
//!    partie qui manquait le plus souvent, et c'est celle qui décide : un
//!    modèle qui hésite entre `pnl_get`, `billing_get` et `usage_get` choisit
//!    mal si aucun des trois ne dit ce que les deux autres font.
//! 3. **Le piège que le code documente**, celui qu'aucun schéma ne porte : un
//!    `set` qui efface les champs omis, une séquence qui ne poste rien
//!    elle-même, un message qui réveille un siège et lui coûte un tour, un
//!    domaine qu'il faut vérifier avant qu'un siège s'y asseye, un plafond
//!    journalier qui s'épuise, un corps plafonné à 1 Mio pour un fichier en
//!    base64.
//!
//! Et une règle de chaînage, qui vaut dix lignes de schéma : **toute
//! description qui réclame un identifiant nomme l'outil qui le fournit**.
//! « L'`id` vient d'`employees_list` » est ce qui évite l'UUID inventé et le 404
//! que le modèle prend pour une erreur de sa part.
//!
//! ## Le `risk` suit la même lecture
//!
//! [`crate::mcp_server::Risk::Destructive`] dès qu'un appel retire, annule, ou
//! engage la société devant un tiers — **un `PUT` de remplacement qui efface
//! les champs omis en fait partie**. La relecture en a trouvé trois qui
//! disaient `Write` en décrivant un remplacement total : `work_items_amend`,
//! `invoices_issuer_set` et `browser_proxy_set`.

use crate::mcp_server::ToolDef;

pub mod appels;
pub mod commerce;
pub mod contenu;
pub mod croissance;
pub mod exploitation;
pub mod social;
pub mod societe;

/// Tous les outils de ce déploiement, dans l'ordre où un lecteur les découvre.
#[must_use]
pub fn registry() -> Vec<ToolDef> {
    let mut all = societe::tools();
    all.extend(commerce::tools());
    all.extend(exploitation::tools());
    // Les quatre domaines de la croissance, ouverts le 2026-09-11 : ce qui
    // fait passer une entreprise au niveau au-dessus plutôt que ce qui la fait
    // tourner. Un module par levier, pour la même raison que les trois
    // premiers — un chantier par fichier.
    all.extend(contenu::tools());
    all.extend(social::tools());
    all.extend(appels::tools());
    all.extend(croissance::tools());
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deux outils du même nom, et le client en appelle un au hasard.
    #[test]
    fn no_two_tools_share_a_name() {
        let all = registry();
        let mut names: Vec<&str> = all.iter().map(|t| t.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "deux outils portent le même nom");
    }

    /// La règle de `mcp_server`, appliquée à toute la table : un trou du
    /// chemin que le schéma ne nomme pas est une URL qui part avec `{id}` en
    /// toutes lettres.
    #[test]
    fn every_hole_of_every_tool_is_a_property() {
        for tool in registry() {
            let properties = tool.properties();
            for hole in tool.placeholders() {
                assert!(
                    properties.contains(&hole),
                    "{}: le chemin demande {hole:?} et le schéma ne le nomme pas",
                    tool.name
                );
            }
        }
    }

    /// **Le test qui répond à « est-ce que j'ai vraiment tout ? »**
    ///
    /// Les trois domaines prouvent chacun que leurs chemins existent. Personne
    /// ne prouvait l'inverse — qu'aucune route montée n'a été oubliée — et
    /// c'est pourtant la seule direction qui compte pour la promesse faite au
    /// fondateur : *toutes* les fonctionnalités du site, atteignables depuis un
    /// terminal. Sans ce test, une route ajoutée demain reste invisible et
    /// personne ne s'en aperçoit.
    ///
    /// Les exclusions sont nommées une par une, avec leur raison. Une liste
    /// d'exclusions sans raisons est une liste où l'on range ce qu'on n'a pas
    /// eu le temps de faire.
    #[test]
    fn every_mounted_route_is_reachable_or_excluded_by_name() {
        /// Ce qui n'est délibérément pas un outil, et pourquoi.
        const EXCLUDED: &[(&str, &str)] = &[
            (
                "/v1/mcp/server",
                "c'est ce serveur : un outil qui l'appellerait serait une boucle",
            ),
            (
                "/v1/browser/live/{employee_id}",
                "un flux SSE ; s'y abonner allume la capture d'écran et rendre l'éteindrait",
            ),
        ];
        /// Les préfixes qui ne sont pas des verbes de locataire.
        const NOT_A_TENANT_VERB: &[(&str, &str)] = &[
            ("/v1/platform", "surface de déploiement, pas d'un locataire"),
            ("/v1/accounts", "identifiants d'une personne, pas un verbe"),
            ("/v1/webhooks", "porte d'un tiers qui signe, pas un verbe"),
            (
                "/v1/mcp/oauth",
                "moitié publique d'un passage OAuth, un navigateur y arrive",
            ),
        ];

        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../apps/server/src/routes");
        let mut mounted: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(dir).expect("les routes du serveur") {
            let path = entry.expect("entrée").path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("lire un module de routes");
            let mut rest = source.as_str();
            while let Some(at) = rest.find(".route(") {
                rest = &rest[at + ".route(".len()..];
                let trimmed = rest.trim_start();
                let Some(quoted) = trimmed.strip_prefix('"') else {
                    continue;
                };
                let Some(end) = quoted.find('"') else {
                    continue;
                };
                let route = &quoted[..end];
                if route.starts_with("/v1/") {
                    mounted.push(route.to_owned());
                }
            }
        }
        mounted.sort_unstable();
        mounted.dedup();
        assert!(
            mounted.len() > 50,
            "l'extraction n'a trouvé que {} routes : le format a changé",
            mounted.len()
        );

        let declared: Vec<&str> = registry().iter().map(|tool| tool.path).collect();
        let mut forgotten: Vec<&str> = Vec::new();
        for route in &mounted {
            if declared.contains(&route.as_str())
                || EXCLUDED.iter().any(|(path, _)| path == route)
                || NOT_A_TENANT_VERB
                    .iter()
                    .any(|(prefix, _)| route.starts_with(prefix))
            {
                continue;
            }
            forgotten.push(route);
        }
        assert!(
            forgotten.is_empty(),
            "ces routes sont montées et aucun outil ne les déclare — ajoutez-les à un \
             domaine, ou à EXCLUDED avec la raison : {forgotten:#?}"
        );

        // Et l'autre sens, pour toute la table d'un coup : un outil qui
        // déclare un chemin que le serveur ne monte pas rend 404 à un modèle
        // qui croit avoir bien appelé.
        for tool in registry() {
            assert!(
                mounted.iter().any(|route| route == tool.path),
                "{} déclare {}, que le serveur ne monte pas",
                tool.name,
                tool.path
            );
        }
    }

    /// Les seuls derniers segments qu'un nom d'outil peut porter.
    ///
    /// Fermée exprès. Une liste ouverte — « le dernier segment doit être un
    /// verbe » — se vérifierait à l'œil, c'est-à-dire jamais : `catalog`,
    /// `board`, `diary` et `dns` ont tous passé une relecture humaine avant
    /// celle-ci. Ajouter un verbe ici est un geste conscient, et c'est le but.
    pub(super) const VERBS: &[&str] = &[
        // lire
        "list",
        "get",
        "search",
        "check",
        "discover",
        // écrire sans reprendre
        "create",
        "add",
        "set",
        "declare",
        "import",
        "export",
        "apply",
        "post",
        "send",
        "book",
        "ingest",
        "enroll",
        "answer",
        "decide",
        "verify",
        "register",
        "publish",
        "record",
        "connect",
        "start",
        "resume",
        // retirer, ou engager la société devant quelqu'un d'autre
        "remove",
        "disconnect",
        "archive",
        "suspend",
        "terminate",
        "approve",
        "deny",
        "accept",
        "decline",
        "credit",
        "place",
        "release",
        "reassign",
        "amend",
    ];

    /// `domaine[_objet]_verbe` : au moins deux segments, et le dernier est un
    /// verbe de [`VERBS`].
    fn name_is_domain_then_verb(name: &str) -> bool {
        let mut segments = name.rsplit('_');
        let verb = segments.next().unwrap_or_default();
        segments.next().is_some() && VERBS.contains(&verb)
    }

    /// Une ligne, une majuscule, pas de point final : un titre nomme un
    /// résultat, il ne raconte pas une phrase.
    fn title_is_one_line_without_a_full_stop(title: &str) -> bool {
        !title.is_empty()
            && title == title.trim()
            && !title.contains('\n')
            && !title.ends_with('.')
            && title.starts_with(char::is_uppercase)
    }

    /// Le nombre de phrases : un terminateur suivi d'une espace ou de la fin.
    /// « E.164 » et « 0.3 » n'en sont donc pas.
    fn sentences(description: &str) -> usize {
        description
            .match_indices(['.', '!', '?'])
            .filter(|(at, _)| {
                description[at + 1..]
                    .chars()
                    .next()
                    .is_none_or(char::is_whitespace)
            })
            .count()
    }

    /// **La convention du module, tenue sur les 116 lignes.**
    ///
    /// Une phrase de description ne prouve rien : c'est celle qu'on écrit en
    /// recopiant le nom de la route. Deux obligent à dire *quand* s'en servir,
    /// ce qui est la seule partie qui fait choisir un modèle.
    #[test]
    fn the_naming_convention_holds() {
        for tool in registry() {
            assert!(
                name_is_domain_then_verb(tool.name),
                "{}: le dernier segment n'est pas un verbe de VERBS",
                tool.name
            );
            assert!(
                title_is_one_line_without_a_full_stop(tool.title),
                "{}: {:?} n'est pas un titre d'une ligne sans point final",
                tool.name,
                tool.title
            );
            assert!(
                sentences(tool.description) >= 2,
                "{}: une description d'une phrase ne dit pas quand s'en servir",
                tool.name
            );
        }
    }

    /// **La garde, désarmée.** Sans ces lignes, les trois assertions ci-dessus
    /// passeraient sur des prédicats toujours vrais — et les cinq premiers
    /// noms sont ceux que cette table portait vraiment le 2026-09-10.
    #[test]
    fn the_convention_guard_bites_on_what_this_pass_had_to_rename() {
        for wrong in [
            "domain_dns",       // un nom de protocole en guise de verbe
            "work_board",       // un nom de meuble
            "browser_task",     // le singulier d'une liste, et pas un verbe
            "health_company",   // le domaine à la fin
            "booking_set_open", // le verbe avant son complément
            "prospects",        // un seul segment : un domaine sans verbe
        ] {
            assert!(!name_is_domain_then_verb(wrong), "{wrong}");
        }
        for right in [
            "domains_dns_publish",
            "work_items_list",
            "company_health_get",
        ] {
            assert!(name_is_domain_then_verb(right), "{right}");
        }

        assert!(!title_is_one_line_without_a_full_stop("Lire le budget."));
        assert!(!title_is_one_line_without_a_full_stop("deux\nlignes"));
        assert!(!title_is_one_line_without_a_full_stop(""));
        assert!(!title_is_one_line_without_a_full_stop(
            "le budget d'une équipe"
        ));
        assert!(title_is_one_line_without_a_full_stop(
            "Est-ce que cette société travaille encore ?"
        ));

        assert_eq!(sentences("Rend les employés du locataire."), 1);
        assert_eq!(
            sentences("Rend les sièges. L'`id` va dans `employees_get`."),
            2
        );
        // Ce qui ne doit pas compter pour une phrase.
        assert_eq!(
            sentences("Le numéro est au format E.164 et rien d'autre"),
            0
        );
    }

    /// Un nom d'outil est lu par un modèle et tapé par un humain.
    #[test]
    fn every_name_is_lower_snake_case() {
        for tool in registry() {
            assert!(
                tool.name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{}",
                tool.name
            );
            assert!(!tool.description.is_empty(), "{}", tool.name);
        }
    }
}
