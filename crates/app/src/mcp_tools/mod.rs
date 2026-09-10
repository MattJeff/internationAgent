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

pub mod commerce;
pub mod exploitation;
pub mod societe;

/// Tous les outils de ce déploiement, dans l'ordre où un lecteur les découvre.
#[must_use]
pub fn registry() -> Vec<ToolDef> {
    let mut all = societe::tools();
    all.extend(commerce::tools());
    all.extend(exploitation::tools());
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
