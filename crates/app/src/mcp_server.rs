//! Ce que ce déploiement expose **comme serveur MCP**, et pourquoi c'est une
//! table plutôt que du code.
//!
//! Décidé le 2026-09-10. Le fondateur ne peut pas — et n'a pas le droit de —
//! poser son abonnement Claude sur le VPS : les conditions d'Anthropic
//! interdisent à un service hébergé d'intermédier l'usage de Claude au nom d'un
//! utilisateur. Ce qui est parfaitement permis, en revanche, c'est l'inverse :
//! **son** Claude Code, sur **sa** machine, sous **ses** identifiants, qui se
//! connecte à un serveur MCP tiers. C'est ce que fait Lumail, et c'est ce que
//! ce module rend possible — la société entière pilotable depuis un terminal.
//!
//! # Un outil est une ligne, pas une fonction
//!
//! La tentation était d'écrire un gestionnaire par outil. Ç'aurait été une
//! deuxième implémentation de chaque fonctionnalité, à côté de la route HTTP
//! qui la porte déjà, et deux implémentations d'une même règle divergent le
//! jour où l'une est corrigée. Donc : **un outil déclare une route**, et un
//! exécuteur unique la joue *en interne* sur le `Router` d'axum déjà construit
//! (`tower::Service`, aucun aller-retour réseau, aucune socket). Les
//! conséquences sont exactement celles qu'on veut :
//!
//! * **Tout ce que le site sait faire est atteignable** — une fonctionnalité
//!   qui a une route a un outil, et le test le vérifie chemin par chemin.
//! * **Les permissions ne sont pas réinventées** : l'en-tête `Authorization`
//!   du client MCP est recopié dans la requête interne, donc la Gate, les
//!   rôles et l'isolation par locataire s'appliquent sans une ligne de plus.
//! * **Rien ne dérive** : corriger la route corrige l'outil.
//!
//! # Ce qu'une ligne dit
//!
//! `path` porte des trous `{ainsi}` ; chaque trou est une propriété du schéma.
//! `query` nomme les propriétés qui partent en chaîne de requête. **Tout le
//! reste du schéma devient le corps JSON** — et un corps vide n'est pas envoyé,
//! ce qui distingue un `DELETE` sans corps d'un `POST {}`.
//!
//! # Le risque est déclaré, et il sert à deux choses
//!
//! [`Risk`] n'est pas un commentaire : il devient l'annotation MCP
//! `readOnlyHint` / `destructiveHint`, que les clients lisent pour décider
//! quoi confirmer. Une ligne qui ment ici fait cliquer « oui » sans lire.

use serde_json::Value;

/// Ce qu'un outil fait au monde, tel que le client MCP doit l'annoncer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Ne change rien. `readOnlyHint: true`.
    Read,
    /// Écrit, crée, met à jour. Rien ne disparaît.
    Write,
    /// Retire, annule, ou engage la société devant un tiers (un envoi, un
    /// paiement, une signature). `destructiveHint: true`.
    Destructive,
}

impl Risk {
    #[must_use]
    pub const fn read_only(self) -> bool {
        matches!(self, Risk::Read)
    }

    #[must_use]
    pub const fn destructive(self) -> bool {
        matches!(self, Risk::Destructive)
    }
}

/// La méthode HTTP de la route qu'un outil joue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// Un outil du serveur MCP : une route, un schéma, un risque.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// Le nom que le client affiche et appelle. `domaine_verbe`, en anglais
    /// comme le reste du protocole, sans tiret (certains clients les refusent).
    pub name: &'static str,
    /// Une ligne, en français, pour un humain qui lit la liste.
    pub title: &'static str,
    /// Ce que l'outil fait **et quand s'en servir** — c'est ce que le modèle
    /// lit pour choisir, donc la deuxième moitié compte autant que la première.
    pub description: &'static str,
    pub method: Method,
    /// Le chemin de la route, trous compris : `/v1/employees/{id}/desk`.
    pub path: &'static str,
    /// JSON Schema de l'entrée. Les propriétés qui nomment un trou du chemin
    /// le remplissent ; celles listées dans [`Self::query`] partent en chaîne
    /// de requête ; le reste forme le corps.
    pub schema: Value,
    pub query: &'static [&'static str],
    /// Quand la route ne prend pas du JSON : le type MIME, et le **nom de la
    /// propriété** dont la valeur — une chaîne — part telle quelle comme corps.
    ///
    /// Une seule route de ce déploiement en a besoin, et c'est elle qui a
    /// imposé le champ : `POST /v1/prospects/import` lit des octets et refuse
    /// en 415 tout ce qui n'est pas `text/csv`. Sans ce champ, la seule façon
    /// d'importer une liste de prospects depuis un terminal aurait été de ne
    /// pas l'exposer du tout — ce que le chantier du commerce a fait, en le
    /// disant, plutôt que d'annoncer un outil qui échoue à chaque appel.
    ///
    /// La propriété nommée ici est retirée du corps JSON par construction : un
    /// outil à corps brut n'a pas d'autre corps.
    pub raw_body: Option<(&'static str, &'static str)>,
    pub risk: Risk,
}

impl ToolDef {
    /// Les trous du chemin, dans l'ordre où ils apparaissent.
    #[must_use]
    pub fn placeholders(&self) -> Vec<&str> {
        let mut out = Vec::new();
        let mut rest = self.path;
        while let Some(open) = rest.find('{') {
            let Some(close) = rest[open..].find('}') else {
                break;
            };
            out.push(&rest[open + 1..open + close]);
            rest = &rest[open + close + 1..];
        }
        out
    }

    /// Les propriétés déclarées par le schéma, dans l'ordre du document.
    #[must_use]
    pub fn properties(&self) -> Vec<&str> {
        self.schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|map| map.keys().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(path: &'static str, schema: Value, query: &'static [&'static str]) -> ToolDef {
        ToolDef {
            name: "x_y",
            title: "…",
            description: "…",
            method: Method::Get,
            path,
            schema,
            query,
            raw_body: None,
            risk: Risk::Read,
        }
    }

    #[test]
    fn a_path_names_its_holes_in_order() {
        let t = tool("/v1/teams/{team_id}/members/{employee_id}", json!({}), &[]);
        assert_eq!(t.placeholders(), vec!["team_id", "employee_id"]);
        assert!(
            tool("/v1/employees", json!({}), &[])
                .placeholders()
                .is_empty()
        );
    }

    /// La règle que tout module d'outils doit tenir, et le test qui la dit
    /// une fois pour toutes : chaque trou du chemin est une propriété du
    /// schéma. Sans elle, l'exécuteur construirait une URL portant `{id}` en
    /// toutes lettres et le serveur répondrait 404 à un outil que le modèle
    /// croit avoir bien appelé.
    #[test]
    fn every_hole_is_a_property() {
        let good = tool(
            "/v1/employees/{id}/desk",
            json!({"properties": {"id": {"type": "string"}, "body": {"type": "string"}}}),
            &[],
        );
        for hole in good.placeholders() {
            assert!(good.properties().contains(&hole), "{hole}");
        }
        let bad = tool(
            "/v1/employees/{id}/desk",
            json!({"properties": {"body": {"type": "string"}}}),
            &[],
        );
        assert!(!bad.properties().contains(&bad.placeholders()[0]));
    }

    #[test]
    fn the_risk_says_what_a_client_must_confirm() {
        assert!(Risk::Read.read_only() && !Risk::Read.destructive());
        assert!(!Risk::Write.read_only() && !Risk::Write.destructive());
        assert!(!Risk::Destructive.read_only() && Risk::Destructive.destructive());
    }
}
