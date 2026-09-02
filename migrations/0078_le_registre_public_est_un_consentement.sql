-- 0078_le_registre_public_est_un_consentement : une colonne qui dit oui, et une
-- vue qui ne sait rien dire d'autre.
--
-- Le registre public publie ce que la gate a refusé. C'est la seule preuve que
-- ce produit possède et qu'un concurrent sans gate ne peut pas copier — il n'a
-- rien à mettre dedans. Deux choses le rendent publiable, et toutes les deux
-- sont ici plutôt que dans le code au-dessus.
--
-- ---------------------------------------------------------------------------
-- 1. LE CONSENTEMENT EST UNE COLONNE, FAUSSE PAR DÉFAUT
-- ---------------------------------------------------------------------------
--
-- `default false` et `not null` : une entreprise qui n'a rien accepté n'est pas
-- « pas encore listée », elle est structurellement absente de la vue ci-dessous,
-- y compris de l'agrégat. Un booléen nullable aurait fait de l'absence de
-- réponse un troisième état que quelqu'un aurait fini par lire comme un oui.
--
-- Le GRANT est par colonne, et c'est le seul écrit que `app_role` obtiendra
-- jamais sur `tenants` (0001 ne lui donne que SELECT). Sans lui, basculer un
-- booléen sur une seule ligne demanderait `admin_tx_bypassing_rls` — le chemin
-- qui voit tous les locataires — pour un acte qui n'en concerne qu'un. La policy
-- `tenant_isolation` borne déjà la ligne : le rôle applicatif peut changer cette
-- colonne, sur sa propre ligne, et rien d'autre.
--
-- ---------------------------------------------------------------------------
-- 2. L'ANONYMAT EST UNE VUE, PAS UNE INTENTION
-- ---------------------------------------------------------------------------
--
-- La règle du registre est que la requête Rust ne nomme aucune colonne
-- identifiante, et un test lit cette requête caractère par caractère pour le
-- vérifier. Or le filtre de consentement a besoin de `audit_log.tenant_id` pour
-- joindre `tenants` : écrite en Rust, la jointure mettrait `tenant_id` dans la
-- chaîne même que le test interdit, et la garde deviendrait décorative — soit
-- elle échoue sur sa propre requête, soit on l'affaiblit jusqu'à ce qu'elle
-- n'interdise plus rien.
--
-- La jointure vit donc ici, une fois. La vue n'expose que quatre colonnes, dont
-- aucune ne désigne quelqu'un, et la requête au-dessus ne peut pas sélectionner
-- ce qui n'existe pas. C'est la même forme que `signing::published_keys` :
-- l'impossibilité est dans la projection, pas dans la prudence de l'appelant.
--
-- `security_invoker = true`, comme `employee_autonomy_daily` en 0022 et pour la
-- même raison : la vue hérite de la RLS de `audit_log` au lieu de la contourner,
-- donc le GRANT ci-dessous ne peut pas devenir une fuite inter-locataires si un
-- jour quelqu'un lit cette vue depuis une transaction de locataire. La route
-- publique, elle, lit par `admin_tx_bypassing_rls` : c'est le seul agrégat de ce
-- dépôt qui traverse les locataires, et il ne le peut que parce que la vue lui
-- interdit d'en distinguer un.
--
-- ÉCARTÉ : une table de compteurs incrémentée à chaque décision. `billing` et
-- `capability` ont déjà tranché — un agrégat dérivé du journal se recalcule un
-- an plus tard et se vérifie ligne à ligne, un compteur ne vaut que la
-- disponibilité du process qui l'incrémente, et l'erreur y est invisible.

alter table tenants
  add column if not exists public_register_opt_in boolean not null default false;

grant update (public_register_opt_in) on tenants to app_role;

create or replace view public_register_decisions
  with (security_invoker = true) as
select a.occurred_at,
       a.decision,
       a.deny_reason_code,
       -- Des tranches, jamais la valeur, et calculées ici pour que le montant
       -- exact ne quitte jamais la base : rien au-dessus ne peut le réagréger.
       -- Les bornes sont en unités mineures de la devise dont l'approbation a
       -- été déposée. Pas de conversion : le registre est un ordre de grandeur,
       -- et un taux de change est un chiffre que ce dépôt ne mesure pas.
       case
         when p.amount_minor is null    then null
         when p.amount_minor <  10000   then '0_100'
         when p.amount_minor < 100000   then '100_1k'
         when p.amount_minor < 500000   then '1k_5k'
         else                                'gt_5k'
       end as held_bucket
  from audit_log a
  join tenants t on t.id = a.tenant_id
  -- `app::gate` écrit une seule ligne par escalade : la décision ici, et
  -- l'`approval_id` de la ligne `approvals` qu'elle vient de déposer dans la
  -- même transaction. La jointure est donc exacte.
  --
  -- Comparaison en TEXTE, et surtout pas `(… ->> 'approval_id')::uuid` :
  -- `payload` est un objet libre, donc cette clé peut y valoir n'importe quoi.
  -- Le `a.decision = 'require_approval'` d'à côté ne garde pas le cast — le
  -- planificateur est libre de réordonner une clause de jointure, et il le
  -- fait : une ligne `allow` portant un `approval_id` mal formé suffit à faire
  -- rendre 500 au registre entier, pour tous les visiteurs, sur la donnée de
  -- n'importe quel locataire consentant. `audit_log` est en ajout seul : cette
  -- ligne-là ne se répare pas après coup. `p.id::text` ne peut pas lever, et un
  -- `approval_id` illisible donne une tranche nulle au lieu d'une panne.
  left join approvals p
    on a.decision = 'require_approval'
   and p.id::text = a.payload ->> 'approval_id'
 where t.public_register_opt_in
   -- Une ligne sans décision n'est pas une décision : le journal enregistre
   -- aussi ce qui arrive *à* un employé, et un message reçu n'a rien à faire
   -- dans un décompte de ce que la gate a tranché.
   and a.decision is not null;

grant select on public_register_decisions to app_role;
