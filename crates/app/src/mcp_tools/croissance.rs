//! Les outils du domaine « croissance » : est-ce que l'entreprise **avance**,
//! et vers quoi.
//!
//! Trois lignes pour une seule route, et c'est délibéré. `commerce` rend les
//! sept nombres de l'entonnoir un par un — `outreach_summary_get` les approches,
//! `quotes_list` les devis, `invoices_list` les factures, `pnl_get`
//! ce que ça brûle — et un modèle qui veut répondre « est-ce qu'on y arrive »
//! doit aujourd'hui appeler quatre outils, aligner quatre fenêtres et faire six
//! divisions. `growth_get` fait les six divisions sur une seule fenêtre.
//!
//! # Ce que les descriptions portent
//!
//! Les deux pièges de cette route, parce qu'un modèle les commettrait sinon :
//!
//! * **`null` n'est pas zéro.** Un taux de passage dont le dénominateur est
//!   vide n'est pas nul, il n'existe pas ; un coût de modèle `null` est un prix
//!   qu'on n'a pas déclaré, pas un modèle gratuit ; une recette `null` est un
//!   registre à plusieurs monnaies, pas un registre vide.
//! * **Ce n'est pas une cohorte.** Les sept comptes mesurent la même fenêtre,
//!   pas les mêmes personnes. Citer un taux comme une probabilité de
//!   conversion est l'erreur que `unmeasured` existe pour empêcher.
//!
//! # Et le point mort n'est pas ici
//!
//! Il est sur `forecast_window` (`GET /v1/forecast`), qui le divise avec ses
//! opérandes nommés un par un. Les descriptions ci-dessous y renvoient plutôt
//! que de laisser croire que `growth_get` le calcule.

use serde_json::{Value, json};

use crate::mcp_server::{Method, Risk, ToolDef};

/// Un schéma d'entrée : des propriétés, et celles qui sont obligatoires.
fn schema(properties: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": properties, "required": required })
}

/// Les lignes de ce domaine.
#[must_use]
pub fn tools() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "growth_get",
            title: "L'entonnoir de bout en bout, contre la cible",
            description: "Rend, sur une fenêtre, les sept étapes qui mènent d'un inconnu à une facture \
                 réglée — prospects ajoutés, contactés, ayant répondu, devis émis, devis \
                 acceptés, factures émises, factures réglées — **chacune avec son taux de \
                 passage à la suivante**, puis la recette (facturé, encaissé, dû, et ce qui a \
                 été encaissé sur trente jours glissants), le coût du modèle, la cible posée et \
                 un verdict (`ahead`, `on_track`, `behind`, `no_target`). C'est la seule lecture \
                 qui dise si l'entreprise *progresse* : `outreach_summary_get` compte les approches, \
                 `pnl_get` ce qu'un siège brûle, `invoices_list` ce qui est dû, aucune \
                 ne met les sept bout à bout ni ne calcule les taux. \
                 Puis `attribution` : **d'où viennent les factures réglées de la fenêtre**, un seau \
                 par ensemble d'origines et par monnaie, remonté d'une facture à son affaire, à son \
                 compte, aux gens de ce compte et à la porte par laquelle ils sont entrés (une liste \
                 importée, une page d'annuaire lue). Aucun euro n'y est réparti : un seau à deux \
                 origines est une chaîne qui se scinde et les deux sont rendues, un seau dont \
                 `origins` est **vide** est une facture d'origine **inconnue** — et inconnu n'est pas \
                 organique. La somme des seaux d'une monnaie est son `collected_minor`. \
                 **`null` n'est jamais zéro** : un taux sans dénominateur n'existe pas, un coût \
                 `null` est un tarif non déclaré (ou un abonnement CLI, qui n'a pas de facture \
                 au jeton) et non un modèle gratuit, une recette `null` est un registre à \
                 plusieurs monnaies. Lire `unmeasured` avant de citer un taux : ce n'est pas une \
                 cohorte, donc un taux est un rapport de débits et pas une probabilité de \
                 conversion. Le point mort n'est pas ici, il est sur `forecast_window`.",
            method: Method::Get,
            path: "/v1/growth",
            schema: schema(
                json!({
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "description": "Fenêtre en jours comptée à rebours depuis aujourd'hui, bornes incluses. Défaut 30, maximum 365."
                    }
                }),
                &[],
            ),
            query: &["days"],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "growth_target_get",
            title: "La cible chiffrée de cette entreprise",
            description: "Rend l'objectif de recette mensuelle que cette entreprise s'est fixé, sa \
                 monnaie, l'échéance et la date à laquelle il a été posé — ou `null` si personne \
                 n'en a jamais posé. `growth_get` la porte déjà dans sa réponse : cet outil \
                 existe pour relire les deux champs avant d'en écrire de nouveaux, sans tirer \
                 tout l'entonnoir. Une cible ancienne se lit différemment d'une cible du \
                 matin, d'où `set_at`.",
            method: Method::Get,
            path: "/v1/growth/target",
            schema: schema(json!({}), &[]),
            query: &[],
            raw_body: None,
            risk: Risk::Read,
        },
        ToolDef {
            name: "growth_target_set",
            title: "Poser la cible que l'entreprise vise, et pour quand",
            description: "Écrit l'objectif de recette mensuelle et son échéance. **Il n'y en a qu'un par \
                 entreprise** : ceci remplace celui qui existait, sans en garder l'historique, \
                 et c'est ce qui fait basculer `verdict` de `no_target` vers une comparaison \
                 réelle. Le montant est en **unités mineures** (190 000 pour 1 900 $) et \
                 strictement positif — une cible à zéro est refusée, parce que zéro est \
                 l'absence de cible. La monnaie vaut USD par défaut et doit être celle du \
                 registre de factures : une cible en dollars contre un registre en euros rend \
                 `no_target`, aucune conversion n'étant faite. L'échéance peut être dans le \
                 passé — une cible manquée reste ce qu'on avait visé, et le verdict rend \
                 `behind`.",
            method: Method::Put,
            path: "/v1/growth/target",
            schema: schema(
                json!({
                    "mrr_minor": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "La recette mensuelle visée, en unités mineures de la monnaie (190000 = 1 900 $)."
                    },
                    "currency": {
                        "type": "string",
                        "description": "Code ISO 4217 à trois lettres. Défaut `USD`. Doit être celle du registre de factures, sans quoi rien n'est comparable."
                    },
                    "at": {
                        "type": "string",
                        "format": "date-time",
                        "description": "L'échéance, en RFC 3339 (`2026-12-31T00:00:00Z`). Le passé est admis."
                    }
                }),
                &["mrr_minor", "at"],
            ),
            query: &[],
            raw_body: None,
            // Elle écrit une ligne du locataire et remplace celle d'avant, mais
            // elle n'engage l'entreprise devant personne et rien ne part au
            // dehors : c'est la même classe que `PUT /v1/employees/{id}/initiative`.
            risk: Risk::Write,
        },
        ToolDef {
            name: "growth_stripe_connect",
            title: "Brancher la lecture du revenu d'abonnement sur Stripe",
            description: "Range la clé **restreinte** Stripe avec laquelle `growth_get` lira le revenu \
                 d'abonnement — le MRR, le nombre d'abonnés, les arrivées, les départs et les \
                 paliers — et rend `connected: true`. Cet outil existe parce que le registre de \
                 factures ne peut pas porter ces euros-là : une facture exige une affaire \
                 `closed_won` approuvée par un humain, et un abonnement pris en libre-service par \
                 carte n'a ni affaire ni approbation. C'est donc l'inverse de \
                 `growth_target_set`, qui écrit un chiffre que l'entreprise se donne : celui-ci \
                 branche une source extérieure. **La clé est prouvée avant d'être rangée** : une \
                 lecture part chez Stripe, et un refus n'écrit rien — la réponse dit alors ce qui \
                 manque à la clé. Il lui faut la lecture de `subscriptions`, et celle d'`events` \
                 pour savoir qui est arrivé et qui est parti ; sans la seconde, `growth_get` rend \
                 ces deux comptes à `null`. **Il n'y a qu'une clé par entreprise et ceci remplace \
                 celle d'avant** ; il n'existe pas de geste pour la retirer, parce que le vrai \
                 débranchement est la révocation de la clé dans le tableau de bord Stripe — c'est \
                 le seul qui arrête réellement la lecture. Rien de ce qui est collé ne ressort : \
                 ni la clé, ni une empreinte, ni ses quatre derniers caractères.",
            method: Method::Post,
            path: "/v1/growth/stripe",
            schema: schema(
                json!({
                    "api_key": {
                        "type": "string",
                        "description": "La clé restreinte Stripe, en clair. Elle n'a besoin que de la lecture : `subscriptions` et `events`. Une chaîne vide est refusée."
                    }
                }),
                &["api_key"],
            ),
            query: &[],
            raw_body: None,
            // Elle range un credential de paiement du locataire et remplace
            // celui d'avant, et elle parle à un tiers en le faisant. Même
            // classe que `model_connect`, qui prouve et range une clé d'API.
            risk: Risk::Write,
        },
    ]
}
