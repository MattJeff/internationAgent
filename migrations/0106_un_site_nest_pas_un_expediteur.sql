-- 0106_un_site_nest_pas_un_expediteur : le domaine où le site d'un client
-- *publie* est posé à côté du dépôt qui le sert, et pas dans la table des
-- domaines d'où il *envoie*.
--
-- `docs/CONTENU.md` § 7.3 nomme le défaut, et il est plus grave qu'il n'en a
-- l'air : `agentos_app::content::our_domains` lit `SELECT domain FROM
-- tenant_domains` pour savoir ce que « nous » veut dire dans une mesure de
-- citation. `tenant_domains` est la liste des domaines d'**envoi d'e-mail**.
-- Pour Orizn elle porte `agents.getorizn.com` et `agent.oriznapi.uk` ; le site
-- est `visa.orizn.app`, qui n'y est pas et n'a rien à y faire. La boucle
-- mesure donc juste et répond faux : le site du client peut sortir premier,
-- elle ne le reconnaît pas comme lui et annonce qu'il n'est pas cité. Tout le
-- reste de la boucle — le brief, l'angle, qui dépasser — est bâti sur ce
-- booléen.
--
-- ---------------------------------------------------------------------------
-- POURQUOI PAS UNE LIGNE DE PLUS DANS `tenant_domains`
-- ---------------------------------------------------------------------------
--
-- C'est le chemin court, et il marcherait le temps d'une démonstration. Il est
-- refusé parce que `tenant_domains` n'est pas une liste de noms : c'est une
-- **rotation d'envoi**, et y déposer un nom a des effets que personne
-- n'a demandés.
--
-- 1. `sending_domain::pick_from` choisit l'expéditeur d'un mail vers
--    l'extérieur parmi « le domaine **vérifié** du locataire dont il reste le
--    plus de plafond aujourd'hui ». Une ligne `visa.orizn.app` en `verified`
--    entre dans cette rotation le jour où elle est écrite, et le premier mail
--    de prospection part d'un domaine qui n'a ni DKIM ni SPF. Ce n'est pas une
--    ligne inerte, c'est un incident de délivrabilité.
-- 2. L'écrire en `pending` l'écarte de la rotation et crée l'autre moitié du
--    problème : `status` suit un fournisseur, `provider` est `not null`, et un
--    siège dont le domaine n'est pas `verified` attend en `pending_external`
--    (0093). On ferait attendre un siège la vérification d'un domaine que
--    personne n'a déclaré chez Resend, et qui ne sera donc jamais vérifié.
-- 3. Et l'asymétrie qui tranche : **un domaine d'envoi non vérifié interdit à
--    un siège de s'y asseoir ; un domaine de site n'a rien à vérifier.** Le
--    DNS d'un site est l'affaire du client, il est déjà en ligne, et nous n'y
--    posons aucun enregistrement. Deux colonnes `status` qui ne veulent pas
--    dire la même chose dans la même table, c'est la deuxième vérité que 0100
--    et 0102 refusent partout ailleurs.
--
-- S'y ajoutent `daily_cap`, `is_primary`, l'index unique partiel, et la clé
-- étrangère de `domain_send_buckets` — six colonnes d'envoi portées par une
-- ligne qui n'envoie rien, et autant de requêtes existantes à relire une par
-- une pour leur apprendre à l'ignorer. Séparer coûte cette migration ; mélanger
-- coûte un audit de `sending_domain.rs` et un incident.
--
-- ---------------------------------------------------------------------------
-- POURQUOI UNE COLONNE DE `content_repos`, ET PAS UNE TABLE `tenant_sites`
-- ---------------------------------------------------------------------------
--
-- Une fois la séparation admise, la question restante est **où**. Une table à
-- part serait une migration, un module de rangement, une route, un outil MCP —
-- les six phrases de `mcp_tools/mod.rs` comptent les outils — et un geste de
-- plus dans l'installation d'un client. Elle achèterait le droit de déclarer un
-- site sans dépôt.
--
-- `content_repos` (0102) porte déjà **le dépôt qui sert le site du client** :
-- le serveur, le dépôt, la branche qui sert le site, le dossier que le
-- générateur lit. L'adresse publique de ce site est le cinquième fait de la
-- même phrase, su par la même personne, au même moment — celui qui dit
-- « pousse dans `orizn/site`, dossier `content/blog`, branche `main` » est
-- exactement celui qui sait que ça ressort sur `visa.orizn.app`. Une table à
-- part serait deux endroits à tenir d'accord pour une seule décision.
--
-- Ce que ça ne couvre pas, nommé : un locataire qui veut mesurer avant d'avoir
-- ouvert un dépôt n'a pas de site à déclarer, donc `our_domains` rend une liste
-- vide et la mesure sort en 409 `no_domain_of_ours`. C'est un refus fort et
-- lisible — « dis-moi ce que “nous” veut dire » — là où la lecture d'avant
-- rendait une mesure fausse sans le dire. Et le seul chemin de publication
-- codé est celui qui passe par ce dépôt (`docs/CONTENU.md` § 5, chemin A) :
-- mesurer sans pouvoir publier n'est pas encore un besoin. Le jour du chemin B
-- — un domaine servi par nous — c'est lui qui apportera sa table, avec son
-- certificat et son gabarit.
--
-- ---------------------------------------------------------------------------
-- LA COLONNE
-- ---------------------------------------------------------------------------
--
-- `nullable`, et c'est délibéré. Les lignes écrites avant aujourd'hui n'ont pas
-- de site à déclarer rétroactivement, et une valeur par défaut serait un
-- domaine inventé — exactement ce que 0093 raconte d'`agent-orizn.com`, cinq
-- jours d'envoi depuis un domaine que personne ne possède. Un dépôt sans site
-- pousse toujours ses articles ; il ne participe simplement pas à la réponse
-- d'`our_domains`.
--
-- La forme est celle de `tenant_domains_domain_shape` (0093), pour la raison de
-- 0102 sur `folder` : c'est un hôte qui finit comparé à ce qu'une page de
-- résultats affiche, et c'est la dernière place où la forme est vérifiable
-- d'un coup pour toutes les lignes. L'hôte seul — `visa.orizn.app` — sans
-- schéma, sans chemin, sans port : c'est ce que `lite.duckduckgo.com` affiche
-- sur sa troisième ligne, et `read_results` compare des hôtes.
--
-- Pas d'unicité, contrairement à `tenant_domains.domain`. 0093 la demande parce
-- que le fournisseur d'e-mail ne distinguerait pas deux locataires sous un même
-- nom ; ici il n'y a pas de fournisseur, deux sièges d'un même locataire
-- peuvent servir le même site depuis deux dépôts, et rien ne casse si deux
-- locataires se disent chez eux au même endroit — la mesure de chacun est lue
-- sous sa propre RLS.

alter table content_repos
  add column if not exists site text
    constraint content_repos_site_shape
    check (site is null
           or (site = lower(site)
               and site ~ '^[a-z0-9.-]+\.[a-z]{2,}$'));

comment on column content_repos.site is
  'L''hôte public où les articles de ce dépôt ressortent, p. ex. `visa.orizn.app`. '
  'Ce que « nous » veut dire dans une mesure de citation (`content::our_domains`). '
  'Ce n''est PAS un domaine d''envoi : ceux-là sont dans `tenant_domains`, ils ont '
  'un fournisseur, un statut de vérification et un plafond journalier, et celui-ci '
  'n''a aucun des trois.';
