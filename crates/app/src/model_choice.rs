//! **Quel modèle pour ce tour-ci**, décidé avant l'appel, sans I/O.
//!
//! `agentos_domain::policy::model_for` répond à une question voisine et
//! différente : *quel modèle ce **siège** a le droit de faire tourner*. La
//! réponse est une propriété du rôle et des quatre couches de politique, donc
//! elle est la même à neuf heures du matin quand personne n'a écrit et à quinze
//! heures quand un client conteste une facture. C'est ce qui coûte cher.
//!
//! # Ce que la mesure dit
//!
//! Le pin d'évaluation (`agentos_eval::cost`, mesuré le 2026-08-26, re-piné le
//! 2026-09-05) donne 453–481 $/mois pour la paie d'Orizn, plafond 639 $, et
//! `cost.rs` écrit lui-même que c'est le plafond **sans cache**. Deux entrées
//! ont fait ce chiffre : les lignes de catalogue ont porté les appels modèle de
//! 2 à 8 par tour et l'entrée de ~4,6k à ~7,4k jetons. La troisième entrée est
//! celle-ci : chaque siège paie le même tarif pour tous ses réveils, alors que
//! la majorité des réveils de rythme finissent en « rien à faire ». Payer Opus
//! pour lire un tableau vide est du gaspillage pur, et aucune couche de
//! politique ne peut le dire — une politique parle de sièges, pas de moments.
//!
//! # La table est une table, et rien d'autre
//!
//! ponytail: pas d'apprentissage, pas de score, pas de fenêtre glissante sur la
//! qualité des réponses. [`wanted`] est un `match` de cinq lignes qu'un humain
//! relit en trente secondes et qu'un humain peut contredire en une ligne de
//! politique. Le plafond de ce choix est nommé plus bas, à `quiet_runs` : la
//! seule entrée qui vient d'une mesure est comptée par jour et non par tour.
//!
//! # La politique tranche en dernier, et elle ne tranche pas comme `model_for`
//!
//! [`choose`] propose, `allowed_models` dispose — mais la direction du repli
//! n'est pas celle de [`model_for`], et la différence est délibérée :
//!
//! * [`model_for`] part d'une **préférence de rôle**. Un opérateur qui a retiré
//!   Opus à un rôle a dit ce qu'il pensait de la dépense de ce rôle, donc le
//!   repli descend jusqu'au moins cher permis.
//! * [`choose`] part d'un **besoin de ce tour**. Si ce tour a besoin d'Opus et
//!   que l'opérateur ne permet que haiku ∧ sonnet, tomber sur Haiku ferait lire
//!   du texte non fiable au modèle le plus faible de la maison — l'exact
//!   contraire de ce que la règle du taint dit. Donc [`permitted`] prend **le
//!   plus capable des permis qui ne dépasse pas ce qu'on a demandé**, et ne
//!   remonte jamais au-dessus. Le seul cas où il remonte est celui où tous les
//!   modèles permis sont plus chers que le choix : là il n'y a rien d'autre à
//!   prendre, et c'est aussi la réponse de [`model_for`].
//!
//! Ensemble vide : `None`, et l'appelant rend l'erreur qu'il rendait déjà. Il
//! n'y a pas de modèle de secours ici pour la raison que `model_for` écrit en
//! entier : le cher serait une facture que personne n'a autorisée et le pas
//! cher une politique que cet opérateur n'a pas écrite.
//!
//! [`model_for`]: agentos_domain::policy::model_for

use std::collections::BTreeSet;

use agentos_domain::policy::{EffectivePolicy, ModelId};

use crate::{rolepack, rolepack_service};

/// Pourquoi ce siège se réveille. Ce que l'appelant sait **avant** l'appel.
///
/// Cinq variantes et pas six : « approbation rendue » n'a pas de réveil à soi
/// dans ce dépôt. Une approbation qui débloque un travail revient par le canal
/// interne, donc par [`Wake::Internal`], et une variante que rien ne produit
/// serait une ligne de table que personne ne peut relire contre le code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// Le rythme de travail est revenu : personne n'a écrit, rien n'est promis.
    /// C'est le réveil que ce module existe pour rendre moins cher.
    Rhythm,
    /// Une promesse tenue sur un fil qu'on a écrit et que personne n'a répondu.
    FollowUp,
    /// Une étape de séquence (`0092`) : la promesse dit quoi écrire.
    Sequence,
    /// Un tiers a écrit — un mail, un SMS, une page de réservation publique.
    Counterparty,
    /// Un collègue a écrit, y compris la réponse qui rend une approbation.
    Internal,
}

impl Wake {
    /// Vrai quand ce tour est parti de nous : personne n'attend au bout du fil.
    ///
    /// C'est la moitié de la règle du taint. Du texte d'inconnu dans le cadre
    /// d'un tour que **nous** avons décidé de prendre n'est pas la même chose
    /// que du texte d'inconnu dans une réponse à cet inconnu : dans le premier
    /// cas personne n'a demandé ces mots et le siège s'apprête à agir dessus.
    pub const fn self_started(self) -> bool {
        matches!(self, Wake::Rhythm | Wake::FollowUp | Wake::Sequence)
    }
}

/// Combien de passages « qui n'ont rien proposé » suffisent à dire d'un siège
/// qu'il n'a rien à faire.
///
/// Deux, pas un. Un tour vide est un tour ; deux d'affilée sont une tendance, et
/// c'est le plus petit nombre qui distingue les deux.
pub const QUIET_RUNS: u32 = 2;

/// Ce que l'appelant sait de ce tour avant d'avoir dépensé un jeton.
#[derive(Debug, Clone, Copy)]
pub struct TurnShape<'a> {
    /// Pourquoi le siège est réveillé.
    pub wake: Wake,
    /// Le rôle du siège, `Charter::role`. `None` est un employé que personne n'a
    /// chartré : son travail de ce tour est une note interne disant qu'il a été
    /// réveillé sans savoir pourquoi, et cette phrase-là est
    /// [`ModelId::UNCHARTERED`] — la même réponse que les deux sites de tour
    /// donnaient déjà avant ce module.
    pub role: Option<&'a str>,
    /// Vrai quand le cadre porte du texte que quelqu'un **hors de cette
    /// entreprise** a écrit : le corps d'un message entrant, la raison qu'un
    /// inconnu a tapée dans une page de réservation, une page lue.
    ///
    /// **Le tableau et l'agenda n'en sont pas**, et c'est une distinction et non
    /// un oubli. `loops::initiative` les met dans une clôture `Untrusted` parce
    /// qu'un titre de tâche traverse un prompt comme n'importe quel texte, mais
    /// ce sont nos propres lignes, écrites par nos propres employés. Les
    /// compter ici ferait passer à Opus tout siège qui a une tâche au tableau,
    /// c'est-à-dire à peu près tous, et la règle ne discriminerait plus rien.
    pub untrusted: bool,
    /// Combien de messages porte le fil sur lequel ce tour se réveille. Zéro
    /// pour un tour qui ne se réveille sur aucun fil.
    pub thread_messages: u32,
    /// Combien de passages récents de ce siège se sont terminés sur de la prose
    /// et rien que la Policy Gate ait tranché — `model_usage_daily.runs_unbacked`.
    ///
    /// ponytail: c'est un compte **du jour**, pas une série. Un siège qui a eu
    /// deux tours vides ce matin et qui travaille depuis lit toujours 2, donc
    /// ses réveils de rythme restent sur Haiku pour le reste de la journée. Le
    /// cas où ça se voit est exactement le cas que la règle vise — « regarde
    /// s'il y a quelque chose à faire », fil vide, sans texte d'inconnu — donc
    /// le plafond est admis. Chemin de sortie s'il devient gênant : une colonne
    /// de série sur `employee_initiative`, écrite là où `record` écrit déjà
    /// l'issue, pas un calcul ici.
    pub quiet_runs: u32,
}

/// Les rôles dont un tour engage l'entreprise devant quelqu'un d'autre.
///
/// Une négociation, un devis, une facture et un ordre donné à un autre siège
/// sont les quatre choses de ce système qu'on ne peut pas reprendre en disant
/// « le modèle s'est trompé » : elles sont parties chez un tiers ou elles ont
/// fait travailler quelqu'un. Elles vivent dans ces trois rôles, donc c'est le
/// rôle qui les nomme, et non une devinette sur le contenu d'un tour qu'on n'a
/// pas encore payé.
///
/// Les noms sont ceux des packs, pas des copies : `role` arrive de
/// `Charter::role`, qui rend ces mêmes constantes.
fn engages_the_company(role: &str) -> bool {
    role == rolepack_service::MANAGING
        || role == rolepack_service::FINANCE
        || role == rolepack::RolePack::international_buyer().name()
}

/// Le modèle que ce tour demande, avant que la politique n'ait son mot.
///
/// Premier bras qui matche gagne, et l'ordre est l'argument :
///
/// 1. **Un siège qui engage l'entreprise** est sur Opus quel que soit son
///    réveil. Une facture reste une facture le jour où c'est le rythme qui l'a
///    réveillée.
/// 2. **Du texte d'inconnu sur un tour parti de nous** est sur Opus. Le taint
///    est exactement le moment où le jugement compte : la clôture retire déjà
///    les schémas à haut risque, ce qui reste est de la lecture d'un texte
///    écrit par quelqu'un qui a intérêt à ce qu'on le croie.
/// 3. **Le réveil « rien à faire »** est sur Haiku : rythme, aucun texte
///    d'inconnu, un fil vide ou d'un seul message, et deux passages récents qui
///    n'ont rien proposé. La réponse est presque toujours non et une réponse
///    presque toujours non ne vaut pas cinq fois le prix.
/// 4. **Tout le reste** est sur Sonnet : écrire une relance, écrire l'étape
///    d'une séquence, répondre à un entrant, lire une page, la routine.
///
/// **Répondre à un entrant est sur Sonnet et pas sur Opus, alors qu'un entrant
/// est du texte non fiable par construction.** C'est le seul endroit où cette
/// table s'écarte de la lecture littérale de « taint ⇒ Opus », et l'écart est
/// la raison d'être de la règle 2 : si le corps d'un mail client suffisait,
/// alors *tout* mail client irait sur Opus, la règle voudrait dire « Opus dès
/// qu'il y a une contrepartie » et ne trierait plus rien. Le siège dont les
/// tours engagent vraiment l'entreprise est déjà sur Opus par la règle 1, quel
/// que soit qui a écrit.
fn wanted(shape: &TurnShape<'_>) -> ModelId {
    let Some(role) = shape.role else {
        return ModelId::UNCHARTERED;
    };
    if engages_the_company(role) {
        return ModelId::Opus5;
    }
    if shape.untrusted && shape.wake.self_started() {
        return ModelId::Opus5;
    }
    if shape.wake == Wake::Rhythm
        && !shape.untrusted
        && shape.thread_messages <= 1
        && shape.quiet_runs >= QUIET_RUNS
    {
        return ModelId::Haiku45;
    }
    ModelId::Sonnet5
}

/// Le plus capable des modèles permis qui ne dépasse pas `wanted` ; à défaut, le
/// moins cher des permis ; à défaut, rien. Voir la doc de module.
///
/// `BTreeSet<ModelId>` itère dans l'ordre du tarif — c'est la propriété que
/// `ModelId` documente et que `the_order_is_the_price_list` garde — donc
/// `range(..=wanted).next_back()` **est** « le plus capable qu'on ait le droit
/// de prendre » et ne demande aucun tri ici.
fn permitted(wanted: ModelId, allowed: &BTreeSet<ModelId>) -> Option<ModelId> {
    allowed
        .range(..=wanted)
        .next_back()
        .or_else(|| allowed.iter().next())
        .copied()
}

/// **Le modèle de ce tour.** Pur, sans I/O, testé en table.
///
/// `policy` est un `Option` pour la raison que `model_for` écrit en entier :
/// `None` veut dire *personne n'a pu lire de politique*, ce qui n'est pas le
/// même fait que *la politique n'accorde rien*. Une politique illisible n'est
/// pas une preuve sur les modèles, donc le choix tient et la gate refuse chaque
/// action au procès-verbal.
pub fn choose(shape: &TurnShape<'_>, policy: Option<&EffectivePolicy>) -> Option<ModelId> {
    let wanted = wanted(shape);
    let Some(policy) = policy else {
        return Some(wanted);
    };
    permitted(wanted, &policy.limits().allowed_models)
}

#[cfg(test)]
mod tests {
    use agentos_domain::policy::PolicyLimits;

    use super::*;

    /// Une politique qui permet exactement `models`, sur les quatre couches.
    fn policy(models: &[ModelId]) -> EffectivePolicy {
        let limits = PolicyLimits {
            allowed_models: models.iter().copied().collect(),
            ..PolicyLimits::default()
        };
        EffectivePolicy::try_new(&limits, &limits, &limits, &limits).expect("coherent limits")
    }

    /// Le réveil de rythme d'un siège qui n'a rien proposé deux fois de suite,
    /// sans texte d'inconnu et sans fil : le cas « regarde s'il y a quelque
    /// chose à faire ».
    fn quiet() -> TurnShape<'static> {
        TurnShape {
            wake: Wake::Rhythm,
            role: Some(rolepack_service::CUSTOMER_SUCCESS),
            untrusted: false,
            thread_messages: 0,
            quiet_runs: QUIET_RUNS,
        }
    }

    /// La table, une ligne par règle. Sans politique, pour que ce test lise le
    /// choix et pas le plafond — le plafond a ses propres tests plus bas.
    #[test]
    fn la_table_des_regles() {
        let open = policy(&ModelId::ALL);
        let case = |shape: &TurnShape<'_>| choose(shape, Some(&open)).expect("something permitted");

        // 3. le réveil « rien à faire »
        assert_eq!(case(&quiet()), ModelId::Haiku45);

        // 4. écrire : relance, séquence, réponse à un entrant, message interne
        for wake in [
            Wake::FollowUp,
            Wake::Sequence,
            Wake::Counterparty,
            Wake::Internal,
        ] {
            assert_eq!(
                case(&TurnShape { wake, ..quiet() }),
                ModelId::Sonnet5,
                "{wake:?} n'est pas un tour d'écriture"
            );
        }

        // 4 bis. et le rythme d'un siège qui vient de proposer quelque chose
        // reste sur Sonnet : il a du travail en cours.
        assert_eq!(
            case(&TurnShape {
                quiet_runs: QUIET_RUNS - 1,
                ..quiet()
            }),
            ModelId::Sonnet5
        );

        // 2. du texte d'inconnu sur un tour parti de nous
        assert_eq!(
            case(&TurnShape {
                untrusted: true,
                ..quiet()
            }),
            ModelId::Opus5
        );

        // 2 bis. le même texte d'inconnu dans une réponse à cet inconnu reste
        // sur Sonnet — c'est l'écart que `wanted` argumente.
        assert_eq!(
            case(&TurnShape {
                wake: Wake::Counterparty,
                untrusted: true,
                ..quiet()
            }),
            ModelId::Sonnet5
        );

        // 1. un siège qui engage l'entreprise, sur son réveil le plus bête
        for role in [
            rolepack_service::MANAGING,
            rolepack_service::FINANCE,
            rolepack::RolePack::international_buyer().name(),
        ] {
            assert_eq!(
                case(&TurnShape {
                    role: Some(role),
                    ..quiet()
                }),
                ModelId::Opus5,
                "{role} engage l'entreprise et devrait être sur Opus"
            );
        }

        // 0. personne ne l'a chartré : une note interne, et rien d'autre.
        assert_eq!(
            case(&TurnShape {
                role: None,
                ..quiet()
            }),
            ModelId::UNCHARTERED
        );
    }

    /// **Deux tours vides puis un troisième.** La borne est à `QUIET_RUNS`, et
    /// elle est basse : un seul tour vide n'y suffit pas.
    #[test]
    fn deux_tours_vides_font_basculer_le_troisieme() {
        let open = policy(&ModelId::ALL);
        let at = |quiet_runs| {
            choose(
                &TurnShape {
                    quiet_runs,
                    ..quiet()
                },
                Some(&open),
            )
        };
        assert_eq!(at(0), Some(ModelId::Sonnet5));
        assert_eq!(at(1), Some(ModelId::Sonnet5));
        assert_eq!(at(2), Some(ModelId::Haiku45));
        assert_eq!(at(9), Some(ModelId::Haiku45));
    }

    /// Un fil de deux messages n'est plus « il n'y a rien à faire » : quelqu'un
    /// a répondu à quelque chose.
    #[test]
    fn un_fil_qui_a_deux_messages_nest_plus_un_reveil_vide() {
        let open = policy(&ModelId::ALL);
        for (messages, expected) in [
            (0, ModelId::Haiku45),
            (1, ModelId::Haiku45),
            (2, ModelId::Sonnet5),
        ] {
            assert_eq!(
                choose(
                    &TurnShape {
                        thread_messages: messages,
                        ..quiet()
                    },
                    Some(&open)
                ),
                Some(expected),
                "un fil de {messages} message(s)"
            );
        }
    }

    /// **Une politique qui n'autorise que Sonnet.** Le tour taintté qui demande
    /// Opus descend sur Sonnet — le plus capable des permis — et le réveil vide
    /// qui demandait Haiku monte sur Sonnet, parce qu'il n'y a rien d'autre.
    #[test]
    fn une_politique_qui_nautorise_que_sonnet_tranche_dans_les_deux_sens() {
        let only_sonnet = policy(&[ModelId::Sonnet5]);
        assert_eq!(
            choose(
                &TurnShape {
                    untrusted: true,
                    ..quiet()
                },
                Some(&only_sonnet)
            ),
            Some(ModelId::Sonnet5)
        );
        assert_eq!(choose(&quiet(), Some(&only_sonnet)), Some(ModelId::Sonnet5));
    }

    /// **Le repli descend, il ne monte pas** — et il descend sur le plus capable
    /// des permis, ce qui est la seule différence assumée avec `model_for`.
    ///
    /// Un tour qui a besoin d'Opus sous une politique haiku ∧ sonnet prend
    /// Sonnet. Le prendre sur Haiku — ce que `model_for` ferait, et à raison
    /// pour une préférence de rôle — mettrait le modèle le plus faible de la
    /// maison devant le texte que la règle 2 existe pour juger.
    #[test]
    fn un_besoin_dopus_descend_sur_le_plus_capable_permis_jamais_sur_le_moins_cher() {
        let thrifty = policy(&[ModelId::Haiku45, ModelId::Sonnet5]);
        let tainted = TurnShape {
            untrusted: true,
            ..quiet()
        };
        assert_eq!(choose(&tainted, Some(&thrifty)), Some(ModelId::Sonnet5));

        // Et jamais au-dessus : un opérateur qui laisse Fable sur la liste ne
        // se retrouve pas à le payer parce qu'un tour a demandé Opus.
        let with_fable = policy(&[ModelId::Sonnet5, ModelId::Fable5]);
        assert_eq!(choose(&tainted, Some(&with_fable)), Some(ModelId::Sonnet5));

        // Le seul cas où le repli remonte est celui où il n'y a rien en dessous.
        let only_fable = policy(&[ModelId::Fable5]);
        assert_eq!(choose(&quiet(), Some(&only_fable)), Some(ModelId::Fable5));
    }

    /// L'ensemble vide refuse, et une politique illisible n'est pas l'ensemble
    /// vide : l'appelant rend l'erreur qu'il rendait déjà dans le premier cas et
    /// prend le tour dans le second.
    #[test]
    fn lensemble_vide_refuse_et_une_politique_illisible_nest_pas_lensemble_vide() {
        assert_eq!(choose(&quiet(), Some(&policy(&[]))), None);
        assert_eq!(choose(&quiet(), None), Some(ModelId::Haiku45));
    }

    /// **La garde désarmée.** Sans la règle du taint, le tour d'inconnu part sur
    /// le modèle du réveil vide — ce qui est exactement ce que ce module refuse.
    #[test]
    fn sans_la_regle_du_taint_le_tour_dinconnu_serait_sur_haiku() {
        let open = policy(&ModelId::ALL);
        let tainted = TurnShape {
            untrusted: true,
            ..quiet()
        };
        // La règle armée.
        assert_eq!(choose(&tainted, Some(&open)), Some(ModelId::Opus5));
        // Le même tour avec le seul champ que la règle lit remis à zéro : c'est
        // la ligne d'à côté de la table, et elle doit être différente.
        assert_ne!(
            choose(&tainted, Some(&open)),
            choose(
                &TurnShape {
                    untrusted: false,
                    ..tainted
                },
                Some(&open)
            )
        );
    }
}
