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
