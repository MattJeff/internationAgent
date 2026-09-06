-- 0088_un_orphelin_a_un_chemin_de_retour : l'approbation qui autorise la
-- reprise d'une intention orpheline, nommée par la ligne qu'elle débloque.
--
-- ---------------------------------------------------------------------------
-- CE QUI MANQUAIT
-- ---------------------------------------------------------------------------
--
-- 0002 a fermé le vocabulaire de `provider_intents.state` sur quatre valeurs,
-- dont `orphaned` : « le worker est mort en plein appel, personne ne sait si le
-- fournisseur a créé la ressource ». Une seule instruction du dépôt l'écrivait
-- (`store::provisioning::mark_intent_orphaned`) et **aucune** ne l'effaçait.
-- `orphaned` était donc un état terminal : le moteur déposait une approbation
-- pour un humain, l'humain l'accordait, et la passe suivante retrouvait
-- `orphaned` et se garait de nouveau. Mesuré en production : deux étapes en
-- rond depuis onze heures, `attempt_count` à 8 et 11, deux approbations
-- `redeemed` sans le moindre effet sur le monde. Le siège était perdu pour
-- toujours.
--
-- Cette colonne est le chemin de retour, et rien d'autre.
--
-- ---------------------------------------------------------------------------
-- POURQUOI UN LIEN VERS LA LIGNE, ET PAS UNE COMPARAISON D'HORODATAGES
-- ---------------------------------------------------------------------------
--
-- La garantie à tenir est « un accord ne sert qu'une fois » : deux morts
-- successives du worker doivent redemander un humain, pas se resservir de
-- l'accord de la première.
--
-- L'autre façon de l'obtenir était de dater l'orphelinat et de n'accepter
-- qu'une décision postérieure. Elle est refusée ici pour deux raisons. La
-- première est que `provider_intents.updated_at` ne sert pas : `begin_intent`
-- le repousse à chaque passe par son `ON CONFLICT DO UPDATE`, donc l'instant de
-- l'orphelinat y est effacé avant même que l'humain ait répondu — il aurait
-- fallu une colonne `orphaned_at` de toute façon. La seconde est qu'une
-- comparaison d'horloges ne dit jamais *quelle* approbation a été accordée :
-- il aurait fallu retrouver « une approbation de réconciliation pour ce couple
-- (employé, étape) » en filtrant sur le hash de l'action dans le jsonb, c'est
-- à dire rejouer côté SQL une décision que le moteur venait de prendre.
--
-- Le lien la nomme. `mark_intent_orphaned` écrit l'identifiant de l'approbation
-- qu'il vient de déposer ; la reprise n'accepte que celle-là, `redeemed` ;
-- et elle remet la colonne à NULL en même temps qu'elle rend la ligne
-- `in_flight`. Un accord consommé n'est plus désigné par personne. La mort
-- suivante dépose une nouvelle approbation et écrit un nouveau lien : elle
-- **ne peut pas** hériter du précédent, puisque le précédent n'est plus là.
--
-- ---------------------------------------------------------------------------
-- ON DELETE SET NULL
-- ---------------------------------------------------------------------------
--
-- Le sens de la contrainte est « la reprise n'est autorisée que tant que
-- l'accord existe et se laisse relire ». Une cascade détruirait l'intention —
-- c'est à dire la seule preuve qu'un appel fournisseur a peut-être eu lieu —
-- pour effacer une approbation ; c'est exactement l'inverse de ce que ce
-- module protège. `set null` échoue du bon côté : l'étape se regare et
-- redemande un humain.
--
-- La FK ne regarde pas RLS (Postgres la vérifie en interne), donc elle
-- n'interdit pas à elle seule de désigner l'approbation d'un autre locataire.
-- Ce n'est pas elle qui tient cette propriété : la lecture de reprise joint
-- `approvals` dans une `TenantTx`, sous `tenant_isolation`, donc un lien
-- inter-locataires ne rend simplement aucune ligne et l'étape reste garée.

alter table provider_intents
  add column if not exists reconciliation_approval_id uuid
    references approvals (id) on delete set null;

comment on column provider_intents.reconciliation_approval_id is
  'L''approbation déposée au moment de l''orphelinat. La seule qui autorise la '
  'reprise de cette intention, et remise à NULL quand elle est consommée : un '
  'accord ne vaut que pour l''orphelinat qui l''a demandé.';
