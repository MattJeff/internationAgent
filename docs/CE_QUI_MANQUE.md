# Ce qu'une entreprise gère, et ce que ce produit en couvre

Écrit le 2026-09-11, au sha `89f99d8`, à la demande du fondateur, dont le
dernier mot était : *« il y a aussi tout ce qu'une entreprise peut gérer qu'on
a encore »*. La vision derrière cette phrase est que le produit finisse par
**gérer une entreprise entière**, prouvé sur Orizn puis sur cinq ou six autres
SaaS, et se vende alors tout seul.

Ce document est l'inventaire qui dit où on en est de cette phrase. Il a trois
colonnes et pas une de plus : **couvert**, **à moitié**, **pas du tout**. Il se
termine par un ordre — pas des priorités, un ordre, avec la raison de chaque
place.

**Relu le 2026-09-12**, en parcourant `point-du-jour` sur une instance locale.
Les trois premières places de § 7 sont bâties ; § 3.3 et § 3.4 portent ce qui
leur reste, § 7 porte les dates et une sixième place. Rien d'autre n'a été
revérifié : ce qui n'est pas daté du 2026-09-12 date toujours du 2026-09-11.

---

## 0. Comment il a été établi, et ce qu'il ne prétend pas

`docs/ROADMAP_CROISSANCE.md` existe déjà et dit ce qu'il faut *faire*. Celui-ci
dit ce qui *est*, ce qui n'est pas la même chose et se périme moins vite.

**La règle que ce document s'impose : chaque « c'est couvert » nomme la table,
la route et l'outil qui le portent ; chaque « à moitié » nomme l'endroit exact
où ça s'arrête — la colonne, la contrainte, le `const` vide — et jamais une
impression.** Le modèle est `docs/CONTENU.md` § 5, qui ne dit pas « la
publication n'est pas finie » mais « `content_drafts.url` est une adresse
constatée et un `CHECK` interdit de mentir sur le mot *publié* ».

L'inventaire part des deux bouts. Par le bas : les 93 fichiers de
`migrations/`, chacun argumentant ce qu'il a écarté ; les sept modules de
`crates/app/src/mcp_tools/` ; les chemins montés dans
`apps/server/src/routes/` ; `crates/app/src/catalog.rs` ; les treize verbes de
`crates/app/src/turn.rs`. Par le haut : la vision du fondateur dans l'ordre où
il l'a dite, puis ce qu'une entreprise gère et qu'il n'a pas nommé.

### Ce que je n'ai pas vérifié, et qui compte

* **L'état du déploiement.** Tout ce qui suit est lu dans le dépôt au sha
  `89f99d8`. Si une clé Anthropic est posée en production, si le serveur MCP
  répond sur siglair, si Orizn a un `whsec_…` chez Stripe — je ne peux pas le
  voir d'ici, et `docs/ROADMAP_CROISSANCE.md` § Phase 0 dit que la réponse à
  ces trois questions était non le 2026-09-11 au matin. **Un produit complet et
  éteint rapporte exactement zéro** ; ce document mesure la complétude, jamais
  l'allumage.
* **Ce que les tests prouvent.** Je n'ai lancé aucune suite. Quand j'écris
  « c'est construit », je veux dire : le code et le schéma existent et
  s'argumentent, pas que `scripts/test.sh` était vert ce matin.

### Un chiffre corrigé en passant

`crates/app/src/mcp_tools/mod.rs`, `crates/app/src/mcp_server.rs` et
`docs/MCP_SERVEUR.md` disaient tous les trois **116 outils** au sha lu. Le compte des noms
distincts hors blocs de test, au sha lu, est **136** : `societe` 51,
`commerce` 36, `exploitation` 32, `contenu` 9, `social` 5, `croissance` 3,
`appels` **0**. Les 116 datent d'avant l'ouverture des quatre domaines de la
croissance le 2026-09-11. Ce n'est pas un défaut — c'est l'illustration de ce
que `crates/eval/src/cost.rs` dit d'un nombre tapé dans de la prose : *prose
cannot be re-run*.

---

## 1. La vision du fondateur, dans son ordre, avec un verdict

| ce qu'il a dit | verdict | où ça s'arrête, en un mot |
|---|---|---|
| recherche de lead | **à moitié** | l'effet existe, aucun outil ne l'expose |
| relève du courrier | **couvert** | — |
| lancement de campagne | **à moitié** | la séquence promet, elle n'envoie pas elle-même |
| publicité Google | **pas du tout** | pas une ligne |
| articles SEO et GEO | **à moitié** | rien ne publie |
| images et vidéos | **pas du tout** | pas une ligne |
| publication sur les réseaux | **à moitié** | le câblage est fait, les revues d'app ne sont pas passées |
| statistiques de tout | **couvert** | — |
| coder le projet (GitHub, serveur) | **à moitié** | le siège existe avec zéro outil autorisé ; pas d'accès serveur, par refus |
| service client, e-mail | **couvert** | — |
| service client, téléphone | **à moitié** | l'appel parle une fois et raccroche |

Les trois sections suivantes détaillent chacune de ces onze lignes, plus ce
qu'il n'a pas nommé.

---

## 2. Ce qui est couvert

Une ligne n'est ici que si elle nomme sa table, sa route et son outil.

### 2.1 La société elle-même

Le socle, et c'est ce qui est le plus abouti du dépôt. `tenants`, `employees`,
`teams`, `sections`, `team_memberships` (avec `reports_to` depuis `0012_org`),
`employee_charters` — huit rôles embauchables depuis `0074` :
`international-buyer`, `sales-development`, `customer-success`, `growth`,
`finance`, `entry-requirements`, `engineering`, `managing`. Les outils :
`company_create`, `employees_create` / `_suspend` / `_resume` / `_terminate`,
`org_apply`, `teams_*` (douze lignes), `policy_role_get` / `_set`.

Les limites sont réelles et réservées sous verrou, pas vérifiées puis
oubliées : `spend_buckets` + `spend_caps` + `spend_reservations` (`0003`),
`turn_buckets` (`0016`), `outreach_buckets` (`0055`), `team_budgets` (`0012`).
`0003` explique pourquoi : *check-then-act lets ten concurrent requests each
read « 0 spent today »*.

Et l'interrupteur existe : `company_halts` (`0045`), `halt_place` /
`halt_release`, plus `company_windows` (`0054`) qui fait de « les agents
tournent une semaine » un arrêt et non une nouvelle sorte de refus.

### 2.2 La relève du courrier

Un e-mail entrant arrive par `POST /v1/webhooks/{path}`, dont la signature est
vérifiée par endpoint (`webhook_endpoints`, `0053`, une ligne par locataire
derrière un même compte fournisseur), atterrit dans `conversations` +
`messages` avec un `trust_label`, réveille un tour, et **ouvre un item sur le
tableau** : `work_items` (`0061`) lié à la conversation par `0080`, un seul
item ouvert par fil. C'est la promesse qu'on achète à un helpdesk — *aucun
message entrant n'est perdu* — et elle est tenue par une contrainte, pas par
une boucle.

La livraison sortante laisse aussi ses traces depuis `0091` : `delivered`,
`opened`, `clicked` lus de Resend, en plus de `bounced` et `complained` qui
finissent dans `suppressions`.

### 2.3 Les statistiques de tout

C'est, à ma lecture, la partie la mieux faite du produit, et celle qu'un
acheteur voit en premier. Sept lectures qui ne se contredisent pas :

* `GET /v1/growth` — l'entonnoir en sept étapes, chacune nommant sa table et sa
  colonne (`contacts.created_at`, `outreach_buckets.contacts_taken`,
  `messages`, `sales_quotes.issued_at` / `.accepted_at`, `invoices.issued_at` /
  `.paid_at`), plus `mrr_minor` défini comme *trente jours glissants
  d'encaissé* et non comme une projection ;
* `GET /v1/pnl` — par siège : tours, jetons, `cost_usd` avec son `cost_source` ;
* `GET /v1/forecast` — le point mort, une division avec ses opérandes nommés ;
* `GET /v1/usage` et `/v1/usage/models` — les jetons du client, sur son propre
  contrat Anthropic ;
* `GET /v1/billing` et `/v1/billing/worked-seats` — ce qu'on a fourni ;
* `GET /v1/autonomy` — quelle part du travail les agents ont réellement faite
  (`0022`) ;
* `GET /v1/refusals` et `GET /v1/public-register` — ce que la gate a refusé, et
  la vue qui ne sait rien dire d'autre (`0078`).

Le tout sous une règle qui tient : **aucun prix appliqué au client qu'il n'ait
déclaré** (`tenant_model_tariff`, `0079`), et `null` plutôt que zéro quand une
étape n'a pas de table.

### 2.4 Le service client par e-mail

Le siège `customer-success` existe (`0029`), un message entrant devient un
ticket (`0080`), l'employé répond par `send_email` sous la Policy Gate, le
carnet garde ce qui dépasse le tour (`work_items`), le calendrier promet une
heure (`appointments`, `0063`) et `0072` distingue une promesse tenue en retard
d'une promesse consommée jamais tenue. Une page publique de réservation existe
(`GET /book/{domain}/{slug}`), et `0083` fait de l'ouverture de cette porte une
colonne qu'un humain met à `true`.

### 2.5 La facturation de nos clients à eux

`invoices` (`0066`) avec trigger d'immuabilité, numéro sans trou
(`invoice_counters`, `0071`), lignes (`invoice_lines`), échéance, avoir
(`corrects_invoice_id`), mentions légales françaises du locataire — forme
juridique, SIREN, RCS, TVA ou motif d'exemption, pénalités de retard (`0087`,
avec l'indemnité de 40 € en constante parce que la loi la fixe et qu'une
colonne laisserait un client la mettre à zéro) — et un PDF écrit à la main dans
`crates/app/src/invoice_document.rs`. La facture part par e-mail avec le PDF en
pièce jointe (`Effects::send_invoice`) et une livraison Stripe la marque payée
(`0081`, `record_stripe_payment`).

### 2.6 Les intégrations

`crates/app/src/catalog.rs` : une trentaine de connecteurs épinglés, chacun
resondé le jour où sa ligne est écrite, avec un plancher de risque qui ne peut
que resserrer, un pin SHA-256 par outil qu'un opérateur a lu, et `CUSTOM` pour
ce que nous n'avons jamais vu. `mcp_servers`, `mcp_tool_declarations`,
les credentials scellés (`0040`), l'OAuth (`0042`), l'hébergé (`0043`). Les
outils : `integrations_catalog_list`, `_connect`, `_discover`,
`_tools_declare`, `_oauth_start`, `_disconnect`.

### 2.7 Le navigateur

Notre Chromium plutôt que Browserbase depuis le 2026-09-10 : un contexte CDP
par tâche, cookies scellés par employé (`0095`), journal par tâche (`0096`),
sortie par le proxy du locataire (`0098`), vue en direct en SSE. Outils
`browser_tasks_list` / `_get`, `browser_summary_get`, `browser_proxy_*`.

---

## 3. Ce qui est couvert à moitié

C'est la section qui vaut le document. Chaque ligne nomme l'endroit exact où ça
s'arrête.

### 3.1 La recherche de lead — l'effet existe, aucun outil ne l'expose

`Effects::discover_prospects` (`crates/app/src/effects.rs:2249`) lit un annuaire
au navigateur, sous `max_new_contacts_per_day` relu dans les quatre couches de
politique, et écrit des `contacts`. Le verbe existe côté modèle :
`find_prospects`, l'un des treize de `turn.rs`.

**Où ça s'arrête :** aucun des 136 outils MCP ne l'expose. Les deux seules
lignes du domaine prospect sont `prospects_segments_list` et `prospects_import`
— un CSV. Un humain au terminal peut donc *verser* une liste, jamais *en
chercher une*. Et rien n'enrichit : pas de vérification d'adresse, pas de
données firmographiques, `prospects.rs` pose `UNKNOWN_COUNTRY` (`ZZ`) parce
qu'*une page ne dit pas où une société est immatriculée et ceci ne devine pas*.

### 3.2 La campagne — la séquence promet, elle n'envoie pas

`sequences` + `sequence_runs` (`0092`) : déclencheur, e-mail, attente, branche
— *« ce que Lumail, Smartlead et Lemlist vendent, sans l'interface »*. La
boucle `loops/sequence.rs` tourne. Outils `sequences_create`, `_enroll`,
`_runs_list`, `_archive`.

**Où ça s'arrête :** l'en-tête de `0092` le dit lui-même — **« et sans second
chemin d'envoi »**. Une séquence pose des promesses ; c'est le tour de
l'employé, avec son `send_email` sous la gate, qui envoie. Conséquence
pratique : une campagne ne part que si des sièges ont des tours à dépenser, et
un plafond de tours épuisé est une campagne silencieuse. C'est un choix
défendable — un seul chemin d'envoi, un seul endroit où les refus s'appliquent
— mais quiconque attend le comportement d'un séquenceur sera surpris.

### 3.3 Le devis — la table est là, rien ne la remplit

`sales_quotes` et `sales_quote_lines` (`0090`), le PDF dans
`crates/app/src/quote_document.rs`, les outils `quotes_list`, `quotes_accept`,
`quotes_decline`.

**Bâti le 2026-09-11, et ce paragraphe est ce qu'il disait** : il n'y avait
pas de `POST /v1/quotes` et **pas d'effet non plus** ;
`apps/server/src/routes/quotes.rs` l'écrivait en toutes lettres, et les deux
étapes `quotes_issued` / `quotes_accepted` de `GET /v1/growth` étaient
structurellement à zéro quoi que fasse l'entreprise.

`Effects::propose_quote` (`14d7b32`) est la moitié qui manquait, écrite sur le
modèle d'`issue_invoice` : la Gate statue pour un siège nommé sur un
`ActionKind::QuoteIssue` neuf — et non `InvoiceIssue` réutilisé, parce
qu'`rolepack_sales` refuse celui-là en toutes lettres et qu'emprunter le verbe
de facturation ferait du vendeur le seul siège capable d'accorder un prix *et*
d'en exiger le paiement. La ligne et son PDF commitent ensemble ; l'audit part
dans une seconde transaction. Il n'y a toujours **aucune route d'opérateur**, et
c'est le refus argumenté de `routes::quotes`, pas un manque.

**Ce qui reste, et c'est une ligne, pas une vague :** aucune ligne de catalogue
de tour, donc aucun siège ne se voit encore offrir le schéma — `turn::UNSERVED`
porte l'entrée `QuoteIssue` avec sa raison (une ligne de catalogue déplace
`cost::DIGEST`, dont la remesure demande un appel de modèle réel) et la
procédure. Et **aucun pack ne le propose** : `rolepack_sales` est le porteur
évident, et élargir l'ensemble `proposable` d'un pack est une décision qui
appartient au commit qui livre l'outil. Tant que ces deux lignes n'existent pas,
l'entonnoir reste à zéro au milieu **en production**, mais plus par construction
— `Effects::propose_quote` a ses tests et la table se remplit.

Le module `routes::quotes` n'a pas été relu depuis : son en-tête dit encore
*« tant que l'effet n'est pas écrit »* et *« la forme exacte est dans le rapport
de cette vague, à poser dans `agentos_app::effects` »*. C'est faux depuis le
2026-09-11, et c'est le genre de prose qu'un lecteur croit.

### 3.4 Les articles — rien ne publie

`content_questions`, `content_citations` en ajout seul, `content_drafts`
(`0100`), neuf outils `content_*`, la mesure sur `duckduckgo_lite` par un siège
qui porte `Channel::Web`.

**Le chemin A a été codé le 2026-09-11** (`0043dde`), et le titre de cette
section reste vrai au mot près : **rien ne publie**, parce que proposer n'est
pas publier. `content_repos` (`0102`) tient un dépôt par siège ;
`POST /v1/content/drafts/{id}/propose` et l'outil `content_drafts_propose`
poussent l'article dans le dépôt qui sert le site du client et ouvrent une pull
request, par trois `Action::McpCall` sur le connecteur GitHub déjà au catalogue
(`create-branch`, `create-or-update-file`, `create-pull-request`), chacun avec
son verdict de Gate et sa ligne d'audit. Un troisième état, `proposed`, et une
colonne `review_url` — dont l'adresse est **rebâtie** à partir de nos chaînes et
d'un entier lu chez GitHub, pour qu'un serveur compromis n'envoie pas le
relecteur ailleurs.

`content_drafts.url` reste une adresse **constatée** et le `CHECK` de `0100`
refuse toujours un `published` sans adresse ni date : c'est un humain qui fusionne
la pull request, et c'est lui qui constate. Le chemin B (sous-domaine servi par
nous) n'est toujours pas codé, et `docs/CONTENU.md` § 5 dit pourquoi il ne
devrait pas l'être avant le chemin A. **Aucun appel n'a été fait contre le vrai
serveur de GitHub** — les tests parlent à un faux monté au port —, donc le
premier article proposé pour de bon reste à voir.

Et la mesure a son propre plafond, nommé : un seul moteur lisible, parce que
tous les autres exigent un compte ou le refusent dans leur `robots.txt`
(vérifié le 2026-09-11 sur cinq). Une mesure sur un moteur n'est pas la
citation par un modèle ; c'en est le meilleur indicateur gratuit.

### 3.5 Les réseaux sociaux — le câblage est fait, les comptes ne le sont pas

Cinq outils (`social_accounts_list`, `social_connect_url_get`,
`social_post_preview_get`, `social_post_publish`, `social_posts_list`) par
`apps/social`, branché comme n'importe quel connecteur sous le handle `social`
via `catalog::CUSTOM`.

**Où ça s'arrête :** trois choses hors du code, écrites dans `docs/SOCIAL.md`
§ « Les revues d'app ». L'app Meta du fondateur ne sert que les comptes qui ont
un *rôle* dessus ; TikTok reste `SELF_ONLY` et plafonné à cinq comptes avant
audit ; l'écran Google en `Testing` rend un jeton de rafraîchissement qui meurt
en sept jours. Et le service lui-même n'est pas déployé — c'est la raison pour
laquelle il n'a pas d'entrée nommée au catalogue, une ligne `Provision::Dial`
sur une URL qui ne répond pas étant *la première affirmation fausse* de ce
fichier.

Deuxième limite, celle que personne ne dit : **un employé ne publie pas.**
`social_post_publish` est un outil MCP — donc un humain ou Claude Code depuis
un terminal. Pour qu'un siège publie pendant son tour, il lui faut
`call_mcp_tool` vers le connecteur `social`, et donc un opérateur qui a déclaré
l'outil au digest. Ce n'est pas un bug, c'est la conséquence des treize verbes.

### 3.6 Coder le projet — le siège existe, avec zéro outil

`0073` a ouvert le rôle `engineering` et `RolePack::engineering` existe, avec
le briefing le plus dense du dépôt et un modèle choisi par argument de coût
(Opus, ~0,041 $ l'appel contre 0,025 $ sur Sonnet, parce qu'un changement
subtilement faux compile, se relit comme plausible, et se trouve en
production).

**Où ça s'arrête, et `0073` le dit lui-même :** *« the pack ships with an empty
`allowed_mcp_tools`, so an employee hired into this role can reach no
repository at all until an operator names a tool in a policy layer »*. Le
connecteur GitHub est au catalogue (`Provision::Dial` vers
`api.githubcopilot.com/mcp/`), donc la route existe ; elle est fermée par
défaut et s'ouvre outil par outil — « peut ouvrir une pull request » et « peut
la fusionner » sont séparables, et le test
`engineering_reaches_a_repository_only_through_a_tool_an_operator_named` tient
la moitié qui dit que la permission ne se propage pas à l'outil voisin.

**L'accès serveur, lui, est refusé et non oublié.** `catalog.rs` § « There is
no SSH variant, and that is the load-bearing part » : une clé SSH est un
credential *pour exécuter des programmes sur la machine de quelqu'un d'autre*,
donc SSH n'est pas un connecteur, c'est un déploiement. Je ne propose pas de
revenir dessus.

### 3.7 Le téléphone — l'appel parle une fois et raccroche

`phone_numbers`, `number_allocations` (`0010` : les numéros appartiennent au
locataire, les employés y sont alloués, parce qu'un paquet réglementaire par
employé en France est une adresse et un justificatif relus par un humain).
Outils `pool_numbers_list` / `_add`, `pool_routing_list` / `_reassign`,
`inventory_stranded_list`. Le SMS et le WhatsApp entrants sont câblés (`0069`),
`OutboundCall::says` porte une `Announcement`, l'adaptateur rend `<Say>`, la
synthèse du transporteur parle sur le compte du locataire, et
`CallOutcome::read` range le résultat.

**Où ça s'arrête, et c'est écrit dans `turn::UNSERVED` :** *« what remains is a
call that speaks once and hangs up »*. La réponse de l'appelé est de la parole,
rien dans cet espace de travail ne transforme de la parole en texte, et un
`<Gather>` demanderait de composer du TwiML en cours d'appel — c'est-à-dire la
boucle de tour de parole. Une ligne de catalogue ici donnerait à un modèle le
pouvoir de diffuser une phrase dans l'oreille d'un inconnu et de lui raccrocher
au nez : *un robocall avec un identifiant de décision*.

Deuxième verrou, indépendant du premier : `store::policy::default_ceiling`
n'accorde ni `Channel::Voice` ni indicatif d'appel, et les couches ne font que
resserrer. Même en ajoutant le verbe, aucun locataire ne pourrait passer un
appel. Le même double verrou vaut pour WhatsApp, dont la fenêtre de 24 heures
est pourtant construite de bout en bout (`Effects::whatsapp_window`,
`OpenWindow` qui nomme la personne avec qui la fenêtre est ouverte) : ce qui
manque en plus, c'est un registre de gabarits, *un objet dans une console que
personne ici n'a ouverte*.

Et le module `crates/app/src/mcp_tools/appels.rs` existe, est déclaré dans
`registry()`, et rend `Vec::new()` — *« (à écrire) »*. Le domaine est nommé et
vide, ce qui est la façon la plus honnête possible de dire « pas encore ».

### 3.8 Payer — la gate autorise, rien ne paie

`Action::PaymentCreate`, `Effects::pay`, la réservation contre
`spend_buckets`, l'approbation humaine qui lie le clic au hash de l'action,
`PolicyGate::redeem_approval` qui le revérifie. Toute la chaîne de décision
existe et elle est bonne.

**Où ça s'arrête :** `trait PaymentProvider` porte sa propre note —
*« ponytail: same reasoning as `McpCaller` — a port with no adapter yet »*. Il
n'y a aucun adaptateur dans `crates/providers/`. La méthode `is_live()` existe
précisément pour que `routes::approvals::approve` ne **brûle pas l'approbation
d'un humain** contre un port qui ne peut pas payer : la rédemption est
committée, le nonce est mort, et seulement ensuite on entre dans le port.
Quelqu'un a pensé à l'ordre des opérations d'un rail qui n'existe pas.

Côté encaissement, Stripe est **entrant seulement** : `on_stripe_webhook` lit
une session Checkout payée et règle la facture qu'elle nomme. Rien dans ce
dépôt ne *crée* une session Checkout ni un lien de paiement. Le client est donc
facturé par PDF et paie par un lien fabriqué ailleurs.

### 3.9 Signer — la gate escalade, il n'y a rien à signer

`ActionKind::ContractSign` existe, l'acheteur le propose, la gate en fait
toujours une décision humaine (`ApprovalReason::ContractSignature`) et ne la
refuse jamais.

**Où ça s'arrête,** dans les mots de `UNSERVED` : *« there is no effect behind
it. What is missing is not authority — it is a signing surface, a document to
sign and somewhere to put the executed copy »*. Les trois moitiés existent
séparément : DocuSign est au catalogue, `quote_document` et `invoice_document`
savent écrire un PDF, et `files` (`0067`) est l'endroit où ranger l'exemplaire
signé. Personne ne les a jointes.

### 3.10 Le classeur et la connaissance — lisibles, pas écrivables par un siège

`files` (`0067`, *le classeur* : les octets tels qu'on nous les a donnés) et
`knowledge_sources` / `knowledge_chunks` (`0004`, avec un index HNSW qui
s'applique vraiment depuis `0076` quand `EMBEDDER_API_KEY` est posée) sont tous
les deux complets et exposés : `files_list` / `_get` / `_create`,
`knowledge_documents_list` / `_ingest` / `_search`.

**Où ça s'arrête :** aucun des treize verbes d'un tour ne touche l'un ou
l'autre. La `ROADMAP` assume pour les fichiers (*« un tour produit du texte,
pas des octets »*) ; pour la connaissance, le rappel est **automatique** sur le
message entrant (`apps/server/src/main.rs`) et délibérément absent du canal
interne, parce que *retrouver les documents de l'entreprise contre l'ordre d'un
collègue laisserait une injection relayée choisir quels documents entrent dans
le tour*. Un employé ne peut donc pas décider d'aller chercher un document ; on
le lui apporte, ou pas.

---

## 4. Ce qui n'est pas couvert du tout

Trois choses, et l'absence se vérifie par un `grep` qui ne rend rien.

### 4.1 La publicité

Aucune occurrence de `google ads`, `adwords`, `facebook ads` ou `meta ads` dans
`migrations/`, `crates/`, `apps/`, `docs/`. Pas de table de campagne payante,
pas de budget média, pas de créa, pas de conversion attribuée. Le mot
« publicité » n'apparaît dans ce dépôt que dans la liste de ce que le fondateur
a demandé.

### 4.2 Les images et les vidéos

Aucune occurrence de génération d'image ou de vidéo. Le seul connecteur
approchant est `magnific`, qui **agrandit** une image existante. Rien ne crée
un visuel, rien n'en range un, et `ActionKind::FileUpload` n'est proposé par
aucun pack — la raison donnée étant bonne : *« upload the creative » et
« upload the customer list » sont une seule action*.

### 4.3 La paie, la banque, la trésorerie

Aucune table d'employé humain payé, aucun compte bancaire, aucun
rapprochement, aucune prévision de trésorerie. `spend_buckets` est un plafond,
pas un solde : il dit ce qu'un siège a le droit de dépenser aujourd'hui, jamais
ce qu'il reste en caisse. `GET /v1/forecast` calcule un point mort, pas un plan
de trésorerie.

---

## 5. Ce qu'une entreprise gère et qu'il n'a pas nommé

C'est la partie où il faut trancher plutôt que lister. Une société a une
comptabilité, des contrats, des obligations légales, des gens, une trésorerie,
des fournisseurs, des prix, un support, une conformité. Toutes ne méritent pas
d'être ici.

### 5.1 La comptabilité — à moitié, et la moitié qui manque n'est pas la nôtre

`GET /v1/accounting/export` sort un CSV des factures et des dépenses sur une
fenêtre, les mentions légales françaises sont portées (`0087`), la TVA a son
taux (`vat_rate_bp`) et son motif d'exemption.

Ce qui manque est un plan comptable, un grand livre, un lettrage, une liasse.
**Et ça ne doit pas venir ici.** L'expert-comptable du client existe déjà, il a
son outil, et le format d'export est ce qui les relie. Un grand livre dans ce
produit serait un deuxième endroit où le chiffre d'une société peut être vrai —
c'est exactement l'erreur que `growth.rs` refuse de commettre en ne recopiant
pas le point mort de `forecast.rs`.

**Verdict : on ne fait pas.** Ce qu'on fera peut-être, pour un jour d'agent :
un deuxième format d'export (le FEC français) le jour où un client le demande.

### 5.2 Les contrats — à faire, et c'est § 3.9

Voir plus haut : trois moitiés qui existent, personne ne les a jointes. C'est
le manque le mieux préparé du dépôt.

### 5.3 Les obligations légales — couvert là où ça engage, absent ailleurs

Couvert, et bien : `lawful_basis` sur chaque contact (`0011`, *« GDPR still
applies to business contacts, so every approach names its basis »*),
`suppressions` qui survit à la suppression du locataire qui l'a créée,
`unsubscribe_links` (`0085`) pour le `List-Unsubscribe-Post` exigé par Google
et Yahoo depuis février 2024, `outreach_warmup` (`0070`) qui fait descendre le
plafond de contacts froids tout seul, `public_register` avec son consentement
(`0078`).

Absent : registre des traitements, DPA, politique de conservation, droit à
l'effacement en un geste. **Verdict : on ne fait pas maintenant.** Ce sont des
documents avant d'être des tables, et le premier client qui les exigera sera un
grand compte — c'est-à-dire pas le chemin du ×10.

### 5.4 Les gens — un manque réel, et personne n'en parle

`console_accounts` (`0089`) a sorti l'accès humain de l'environnement : il y a
enfin plusieurs administrateurs possibles par déploiement, là où
`ADMIN_EMAIL` / `ADMIN_PASSWORD` en autorisait exactement un. Les colonnes sont
`id`, `tenant_id`, `email`, `password_hash`, `created_at`, `deactivated_at`.

**Il n'y a pas de colonne de rôle.** Tout humain qui ouvre la console d'un
locataire peut donc tout faire : approuver un paiement, résilier un siège,
arrêter l'entreprise, changer le tarif, lire chaque message. Le produit sait
distinguer huit rôles d'employé IA sous quatre couches de politique, et ne sait
pas distinguer le fondateur de son stagiaire.

C'est le manque dont je n'ai trouvé trace nulle part : ni dans la roadmap, ni
dans un `ponytail:`, ni dans l'argument d'une migration. Il ne coûte pas cher —
une colonne, un `CHECK`, une vérification dans les routes qui engagent — et il
devient bloquant au **deuxième humain chez un client**, donc quelque part entre
le troisième et le sixième SaaS.

### 5.5 Les fournisseurs — couvert, sauf les deux derniers gestes

`suppliers`, `supplier_contacts`, `supplier_observations`, `rfqs`, `quotes`,
`negotiations`, `negotiation_rounds`, `purchase_orders`, `shipments` (`0007`),
plus `0056` qui transforme « ceci est ce qui empêche un appel d'offres de
partir deux fois » d'une convention en une contrainte. La chaîne va de bout en
bout jusqu'au bon de commande.

Les deux derniers gestes sont payer (§ 3.8) et signer (§ 3.9). Le vertical
acheteur est donc complet *sauf les deux actes qui engagent l'argent*.

### 5.6 Les prix — un refus délibéré, à relire un jour

`GET /v1/billing` compte des jours facturables et **refuse d'y coller un
prix** : *« counting and collecting are two jobs »*. `growth.rs` va plus loin :
*« ce n'est pas un abonnement. Rien dans ce schéma ne porte de récurrence — il
n'y a pas de table d'abonnements »*.

Pour Orizn et cinq SaaS, c'est le bon choix : six contrats se facturent à la
main en une heure par mois. **Verdict : on ne fait pas**, et on relit cette
ligne au douzième client, pas avant.

### 5.7 Le support et la conformité produit

Le support est § 2.4 et § 3.7. La conformité au sens « ce que la société a le
droit de faire » est la Policy Gate elle-même, plus le registre public, et
c'est la seule chose de ce produit qu'un concurrent sans gate ne peut pas
copier — *il n'a rien à mettre dedans* (`0078`).

---

## 6. Ce qu'on ne fera pas, et pourquoi

Un document qui ne refuse rien n'a rien tranché. Voici les refus, chacun avec
sa raison plutôt qu'un goût.

* **La publicité payante.** Ce n'est pas seulement un chantier, c'est un
  changement de nature : le produit se mettrait à dépenser l'argent du client
  en continu, contre une mesure d'attribution que personne ne sait rendre
  honnête. `docs/CONTENU.md` § 1 dit pourquoi le contenu gagne à budget égal là
  où la publicité ne le fait pas. Et une régie est une facture mensuelle de
  plus, ce qui est exactement ce que la `ROADMAP` refuse pour le téléphone.
* **La génération d'images et de vidéos.** Deux raisons. Un visuel est jugé par
  un œil, donc l'humain reste dans la boucle et le gain d'automatisation est
  faible ; et chaque génération est une facture à un tiers, c'est-à-dire une
  ressource et non du logiciel — la ligne de partage que `docs/BROWSER.md` § v3
  a déjà tranchée une fois.
* **La voix conversationnelle.** Reconnaissance, barge-in, boucle de tour de
  parole sur un flux média : c'est un trimestre, et le résultat est un produit
  différent. La position de `UNSERVED` est la bonne et elle tient toute seule.
* **Le grand livre comptable.** § 5.1.
* **Le rail de paiement sortant.** Un adaptateur qui bouge de l'argent est la
  surface la plus dangereuse qu'on puisse écrire, et le besoin est aujourd'hui
  celui d'un client qui n'existe pas : Orizn ne paie pas de fournisseurs. La
  gate reste prête, le port reste vide, et `is_live()` dit la vérité.
* **Un abonnement pour nous facturer.** § 5.6.
* **Une ferme de contenu.** `docs/CONTENU.md` l'a déjà refusée, et l'argument
  vaut par-delà le contenu : tout ce qui publierait au nom de dix clients
  depuis un domaine à nous est un produit qui meurt le jour où un client s'en
  aperçoit.

---

## 7. L'ordre, et la raison de chaque place

Pas des priorités : un ordre. La question à chaque place est celle de
`docs/ROADMAP_CROISSANCE.md` — *190 $/mois vers 1 900 $ en trois à quatre
mois* — et **rien ne rapporte tant que rien ne tourne**.

> **Relu le 2026-09-12.** Les **trois premières places sont bâties**, toutes les
> trois dans les vingt-quatre heures qui ont suivi l'écriture de ce document, et
> chacune porte ci-dessous sa date et ce qui lui reste. La quatrième
> (signature), la cinquième (recherche de lead) et la suite sont intactes. Ce
> qui s'est ajouté à la liste entre-temps est en fin de section, sous
> *Sixième*.

### Zéro — allumer ce qui existe

Pas un chantier, donc pas une place numérotée : la clé Anthropic, le serveur
MCP déployé, le `whsec_…` de Stripe. Le fondateur, en une heure. Toute place
ci-dessous suppose celle-ci faite, sans quoi elle rapporte zéro.

### Premier — l'effet qui pose un devis

**Une vague.** `Effects::issue_quote`, à côté d'`issue_invoice`, avec sa ligne
de catalogue de tour, et le re-pin de `cost::DIGEST` qui va avec.

*Pourquoi premier :* c'est le seul manque de ce document qui casse une mesure
plutôt qu'une capacité. Deux des sept étapes de `GET /v1/growth` comptent une
table qu'aucun employé ne peut remplir, donc **l'écran qui doit prouver le ×10
ne peut pas le prouver aujourd'hui**. Et c'est le chaînon entre une réponse de
prospect et une facture : sans lui, tout ce qui se passe entre « il a répondu »
et « il a payé » se fait hors du produit, ce qui est précisément l'endroit où
un client conclut qu'il pourrait le faire sans nous.

*Ce que ça rapporte, et pour qui :* directement pour Orizn, dont chaque euro
passe par là ; et c'est la seule ligne de ce document qui rend les six autres
mesurables.

**Fait le 2026-09-11** (`14d7b32`), et § 3.3 dit comment : `Effects::propose_quote`
existe, gaté et audité, sur un `ActionKind::QuoteIssue` neuf. **Ce qui reste est
une ligne, pas une vague** : aucune ligne de catalogue de tour (elle déplace
`cost::DIGEST`, dont la remesure demande un appel de modèle réel — `turn::UNSERVED`
porte la procédure) et aucun pack ne le propose. Donc l'entonnoir est toujours à
zéro au milieu *en production*, et il ne l'est plus *par construction* : la seule
chose qui manque est mesurable en une vague, et elle est nommée.

### Deuxième — publier un article, par le chemin A

**Une vague.** Le chemin A de `docs/CONTENU.md` § 5 : une ligne
`employee_resources` pour le dépôt et la branche, un effet `publish_article`
derrière la gate, la pull request comme circuit d'approbation déjà existant.

*Pourquoi deuxième :* c'est le levier que `ROADMAP_CROISSANCE` § 2.1 met en
tête et l'argument tient — coût marginal quasi nul par article, effet
cumulatif, seul canal où un petit bat un gros à budget égal. Tout est construit
sauf le dernier geste : questions, mesure, brief, brouillon. **On a une boucle
qui tourne à vide,** et la refermer coûte moins que n'importe quelle ligne
neuve de ce document. Le chemin A plutôt que le B parce qu'il n'ajoute aucun
produit à tenir : un site public qui tombe est une panne client.

*Ce que ça rapporte, et pour qui :* pour Orizn — le rang 2 mesuré le 2026-09-11
sur `visa requirements api` est le chiffre de départ, et c'est lui qu'on fait
bouger. C'est aussi la démonstration la plus vendable aux cinq SaaS suivants,
parce que c'est un résultat qu'ils peuvent lire sans nous croire sur parole.

**Fait le 2026-09-11** (`0043dde`), et § 3.4 dit comment : `content_repos`
(`0102`), `POST /v1/content/drafts/{id}/propose`, l'outil
`content_drafts_propose`, un état `proposed` et une `review_url` rebâtie.
**La boucle ne tourne plus à vide** — elle s'arrête sur une pull request ouverte,
qui est un humain, pas un trou. Ce qui reste : le chemin B, toujours refusé ; et
le fait qu'aucun appel n'a jamais été fait contre le vrai serveur de GitHub.

### Troisième — un rôle sur `console_accounts`

**Un jour d'agent.** Une colonne, un `CHECK`, et la vérification sur les routes
qui engagent : approbations, halt, résiliation, tarif, clés.

*Pourquoi troisième :* le coût est le plus bas du document et le manque est
structurel — un produit qui vend « une entreprise entière » et où le stagiaire
peut arrêter la société est invendable au deuxième humain. Il passe après les
deux premiers parce qu'il ne produit pas d'euro chez Orizn, où le fondateur est
seul ; il passe avant tout le reste parce qu'il bloque le troisième client, et
que le ×10 en passe par là.

*Fait le 2026-09-11*, et nommé ici pour que personne ne le rebâtisse : la
colonne et son `CHECK` sont
`migrations/0104_un_role_sur_les_comptes_humains.sql` (`owner` par défaut, et la
première personne d'un locataire est propriétaire quand les suivantes ne le sont
pas) ; la vérification est `auth::require_console_role`, une couche de
`with_api_stack`, qui refuse **tout ce qui n'est ni une lecture ni l'une des
vingt-et-une écritures qui n'engagent rien** — donc une route ajoutée demain est
fermée, pas ouverte ; l'attribution est `PUT /v1/console/accounts/role` et
l'outil `console_accounts_role_set`. Ce qui reste est côté console : griser ce
qu'un membre ne peut pas presser, en lisant `console_role` sur `GET /v1/whoami`.

### Quatrième — la signature d'un document

**Une vague.** Les trois moitiés existent (DocuSign au catalogue, les deux
générateurs de PDF, `files` pour l'exemplaire exécuté) ; il manque l'effet, et
la gate escalade déjà vers un humain sans jamais refuser.

*Pourquoi quatrième :* c'est ce qui ferme le vertical acheteur, et c'est la
première chose qu'un SaaS B2B demandera après le devis. Il passe après le rôle
de console parce qu'une signature sans rôles est une signature que n'importe
qui peut déclencher.

### Cinquième — exposer la recherche de lead

**Un jour d'agent.** Un outil MCP sur `discover_prospects`, sous le plafond
`max_new_contacts_per_day` que l'effet relit déjà.

*Pourquoi cinquième :* le travail est fait à quatre-vingt-dix pour cent, mais
`ROADMAP_CROISSANCE` § 2.2 a raison — la prospection existe de bout en bout et
**n'a jamais tourné une semaine**. Ouvrir le robinet d'entrée avant d'avoir
mesuré le taux d'ouverture, de réponse et de rendez-vous, c'est ajouter avant
de mesurer. Cette place est celle de « après la première semaine réelle ».

### Sixième — un siège qui ne travaille plus doit être nommé sans qu'on le cherche

**Ajouté le 2026-09-12**, après avoir parcouru `point-du-jour` pour la première
fois (`plugin/skills/point-du-jour/SKILL.md`) sur trois sociétés montées à la
main. Deux tiers de la place ont été pris dans la même marche et sont déjà là :
`GET /v1/health/company` rend désormais `last_failure_employee_slug`, et les deux
taux de `GET /v1/outreach/health` valent `null` tant qu'aucune trace n'est
revenue au lieu d'annoncer une livraison parfaite sur quarante envois muets.

*Ce qui reste, et c'est la place :* **rien ne dit pourquoi une société qui
travaille n'avance pas.** Le fondateur lit `contacted: 120` d'un côté et
`sent: 40` de l'autre, et aucune lecture ne joint les deux — le geste doit lui
apprendre que l'une compte des créneaux dans `outreach_buckets` et l'autre des
lignes de `messages`, et que l'écart est un fichier exporté et jamais chargé
chez le prestataire. C'est l'état d'Orizn aujourd'hui, c'est la phrase qui
déciderait de sa journée, et le produit ne sait pas la dire : il sait rendre les
deux nombres.

*Pourquoi ici et pas plus haut :* parce que ce n'est **peut-être pas une route**.
Une huitième étape à l'entonnoir (`outreach_buckets` réservés moins `messages`
écrits) est un chantier de mesure sur une surface que la console lit déjà, et
`GET /v1/growth` argumente à sept. La décision à prendre est celle-là, et elle
demande une semaine de prospection réelle pour savoir si l'écart est une panne
ou une méthode. Elle passe donc après la cinquième place, qui est la même
semaine.

### Et ensuite, dans l'ordre décroissant de ce qu'on en sait

Les revues d'app du social (pas du code : du temps du fondateur), le second
format d'export comptable si un client le demande, et rien d'autre de ce
document avant le sixième client.

---

## 8. Les trois lignes à relire dans six mois

1. **Le prix.** § 5.6 refuse un abonnement pour six clients. À douze, c'est un
   refus qui coûte une journée par mois, et la relecture est due.
2. **Le paiement sortant.** Le port est vide parce qu'Orizn ne paie personne.
   Le premier client qui achète vraiment le remplit.
3. **Le chiffre 116.** Trois fichiers l'annonçaient, le compte était 136 —
   corrigé à l'intégration de ce document, et désormais tenu par
   `every_written_count_is_the_registry_s_own`, qui lit ces fichiers et refuse
   un compte qui n'est pas celui du registre. Ce n'est
   pas grave, et c'est la démonstration de la règle du dépôt : un nombre dans
   de la prose est vrai le jour où il est écrit.
