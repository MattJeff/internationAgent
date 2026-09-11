-- 0104_un_role_sur_les_comptes_humains : la troisième moitié de l'étape zéro.
--
-- `0089` a sorti l'accès humain de l'environnement et créé `console_accounts`.
-- Il a donné à une personne une adresse, un mot de passe et un locataire — et
-- rien qui dise ce qu'elle a le droit d'y faire. Conséquence, jusqu'à cette
-- ligne : toute personne qui ouvre la console d'un locataire peut approuver un
-- paiement, arrêter la société, résilier un siège, brancher le modèle, émettre
-- et révoquer une clé d'API. Le produit distingue huit rôles d'employé sous
-- quatre couches de politique et ne distingue pas le fondateur de son
-- stagiaire.
--
-- Ce n'est pas une gêne, c'est ce qui borne le nombre d'humains par client à
-- un. `docs/CE_QUI_MANQUE.md` § 7 le met en troisième place pour cette raison :
-- ça ne rapporte pas un euro chez un fondateur seul, et ça bloque le deuxième
-- humain chez un client.
--
-- ---------------------------------------------------------------------------
-- DEUX RÔLES, ET POURQUOI PAS QUATRE
-- ---------------------------------------------------------------------------
--
-- Le découpage tombe de la lecture des routes, pas d'une idée générale des
-- SaaS. Ce qu'un humain peut décider depuis la console se range en deux tas et
-- pas en quatre :
--
--   * ce qui **engage l'argent ou l'existence de la société** — approuver une
--     dépense, arrêter ou relancer l'entreprise, créer ou résilier un siège,
--     brancher le modèle qui est facturé, émettre ou révoquer un credential,
--     déplacer un plafond de dépense, poser ou retirer un domaine d'envoi,
--     dire qu'une facture est payée ou l'avoirer, et donner ce rôle-ci ;
--   * **tout le reste** — lire, écrire une note, une tâche, un prospect,
--     répondre sur un fil, ce qui se corrige en le refaisant.
--
-- Un troisième rôle « lecture seule » a été écarté : les routes qui écrivent
-- sans engager n'ont pas de conséquence qu'un client veuille interdire à
-- quelqu'un à qui il a déjà donné un mot de passe, et un rôle qu'on n'attribue
-- jamais est un rôle qu'on ne teste jamais. Le jour où un client le demande, la
-- contrainte ci-dessous prend une troisième valeur et `role_engages` une
-- troisième branche ; c'est l'endroit, et c'est tout.
--
-- Un rôle « approbateur » a été écarté pour une autre raison, plus dure : il
-- existe déjà. `routes::approvals::held_role` lit le rôle d'approbation dans
-- l'ÉTIQUETTE du credential, et `api_keys::session_label` documente le fait
-- qu'une session de console s'appelle `session-<uuid>`, ne porte donc aucun
-- rôle, et ne peut donc approuver personne. Ces deux mécanismes ne se
-- recouvrent pas et ne doivent pas fusionner ici.
--
-- ---------------------------------------------------------------------------
-- POURQUOI `owner` PAR DÉFAUT — LA SEULE VALEUR SÛRE
-- ---------------------------------------------------------------------------
--
-- Aujourd'hui, en production, il y a un humain par locataire, et c'est le
-- fondateur. Une valeur par défaut de `member` le rétrograde à l'instant où
-- cette migration s'applique : il perd l'arrêt d'urgence, ses clés, ses
-- plafonds et ses approbations, sans qu'aucune ligne de journal ne dise
-- pourquoi, et personne ne peut le lui rendre — puisque donner un rôle demande
-- le rôle. Le déploiement se retrouve sans aucun propriétaire et il faut un
-- UPDATE à la main pour en ressortir.
--
-- `owner` par défaut fait l'inverse : le jour de la migration, personne ne perd
-- rien et rien ne change de comportement. Le rôle se descend ensuite, un compte
-- à la fois, par le geste explicite qui l'attribue. Une politique se resserre
-- depuis un état qui marche ; elle ne se découvre pas en production.
--
-- Le même argument vaut une deuxième fois, ailleurs et plus discrètement :
-- `apps/server/src/auth.rs` donne `owner` à tout credential qui n'est PAS une
-- session de console — les clés de l'environnement et les clés d'intégration
-- d'un client. Elles n'ont pas de ligne ici, donc pas de rôle à lire, et les
-- refuser serait couper l'intégration de chaque client au déploiement de cette
-- vague.
--
-- ---------------------------------------------------------------------------
-- POURQUOI UNE COLONNE `text` + CHECK, ET PAS UN `enum` POSTGRES
-- ---------------------------------------------------------------------------
--
-- C'est la forme que ce dépôt a déjà choisie pour `employees.lifecycle` et pour
-- `approvals.state` : un `CHECK` se modifie dans une migration ordinaire, là où
-- `ALTER TYPE ... ADD VALUE` ne se joue pas dans une transaction et se retire
-- encore moins. La valeur est lue par un `match` Rust qui refuse ce qu'il ne
-- connaît pas (`accounts::ConsoleRole::parse`), donc les deux bouts sont
-- fermés.
alter table console_accounts
  add column if not exists role text not null default 'owner';

alter table console_accounts
  drop constraint if exists console_accounts_role_is_known;
alter table console_accounts
  add constraint console_accounts_role_is_known
    check (role in ('owner', 'member'));

-- `0089` accorde à `app_role` un SELECT colonne par colonne, et laisse dehors
-- la seule qui compte (`password_hash`). La nouvelle colonne rejoint les
-- lisibles : un annuaire qui montre les personnes de sa propre entreprise sans
-- pouvoir dire laquelle peut arrêter la société est un annuaire qui ne répond
-- pas à la question qu'on lui pose. Écrire reste interdit à `app_role` — comme
-- pour les quatre autres colonnes, un changement de rôle passe par
-- `admin_tx_bypassing_rls` et par une route qui a vérifié qui appelle.
grant select (role) on console_accounts to app_role;
