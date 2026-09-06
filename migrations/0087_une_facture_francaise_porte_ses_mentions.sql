-- 0087_une_facture_francaise_porte_ses_mentions : une facture n'est pas un
-- total, c'est un document réglementé — et les
-- mentions qu'il doit porter sont celles du locataire, pas celles du produit.
--
-- 0066 a créé le registre, 0071 lui a donné un numéro sans trou, et
-- `crates/app/src/invoice_document.rs` écrit le PDF à la main. Il manquait la
-- seule chose qui rende ce PDF émissible en France : l'identité de l'émetteur,
-- le taux, et les mentions de retard. `invoice_lines.tax_rate_bp` existe depuis
-- 0071 et son commentaire de colonne dit pourquoi il est resté vide — « un taux
-- est un fait sur une juridiction et une entreprise, pas sur du logiciel ».
-- C'est exact, et c'est précisément pour cela que les colonnes ci-dessous sont
-- sur `tenants` : l'entreprise, ce sont elles.
--
-- ## Pourquoi des colonnes sur `tenants` et pas une table
--
-- 0078 a fait le même geste pour `public_register_opt_in`, et l'argument tient
-- ici mieux encore : il y a **exactement une** ligne de mentions par locataire,
-- elle est lue dans la même jointure que `tenants.name` que
-- `agentos_store::invoices::parties` faisait déjà, et la RLS de `tenants`
-- (0001, `id = app.tenant_id`) est déjà la bonne — une table à part serait une
-- deuxième politique à écrire, un deuxième GRANT, une deuxième jointure, et une
-- ligne qui peut manquer là où une colonne ne peut qu'être nulle.
--
-- `grant select on tenants` (0001) porte déjà sur la table entière, donc la
-- lecture est acquise ; l'écriture est accordée colonne par colonne, comme 0078,
-- pour que `PUT /v1/invoices/issuer` ne devienne pas un droit d'écrire `slug`.
--
-- ## Pourquoi `vat_rate_bp` ne peut pas valoir zéro
--
-- Une facture sans TVA n'est pas une facture avec une TVA de 0 %. Les deux se
-- présentent différemment à l'administration : l'une porte une mention
-- (« TVA non applicable, art. 293 B du CGI », autoliquidation, exonération),
-- l'autre affirme un taux. Un `0` stocké ici rendrait les deux cas identiques
-- dans la base et laisserait le PDF imprimer « TVA 0,00 % » en croyant dire
-- quelque chose. Le CHECK borne donc à 1..=10000 : *pas de taux* est `NULL`, et
-- `NULL` **exige** `vat_exemption_reason`, que le rendu et la route lisent comme
-- l'obligation qu'elle est. `invoice_lines.tax_rate_bp` garde son `>= 0` de
-- 0071 — c'est une autre table et son commentaire est encore vrai —, et
-- `ventilate` traite un `0` de ligne comme « hors TVA », jamais comme un taux.
--
-- Le XOR est un CHECK et non une convention : un locataire qui aurait *les
-- deux* serait un locataire dont le PDF a deux réponses à la même question.
--
-- ## Ce qui n'est pas une colonne
--
-- L'indemnité forfaitaire de recouvrement (40 €, art. D441-5 du code de
-- commerce) est un montant fixé par la loi, identique pour tous les locataires :
-- c'est une constante de `invoice_document`, pas un réglage. Une colonne
-- laisserait un client la mettre à 0.

alter table tenants
  -- « SAS », « SARL », « EURL »… — la forme juridique, à côté de la
  -- dénomination que `tenants.name` porte déjà.
  add column if not exists legal_form           text,
  -- Le siège, en une chaîne : ce dépôt n'a nulle part ailleurs d'adresse
  -- structurée, et une facture l'imprime sur une ligne.
  add column if not exists postal_address       text,
  -- Neuf chiffres. Le SIRET n'est pas ici : le SIREN est la mention obligatoire,
  -- le SIRET est l'établissement et un locataire n'en a qu'un dans ce schéma.
  add column if not exists siren                text,
  -- La ville du greffe : « RCS Paris 123 456 789 ».
  add column if not exists rcs_city             text,
  -- Le numéro de TVA intracommunautaire. Nul quand le locataire n'y est pas
  -- assujetti — d'où la contrainte croisée avec `vat_rate_bp` plus bas.
  add column if not exists vat_number           text,
  -- Le taux applicable par défaut, en points de base (2000 = 20,00 %). Une
  -- ligne de facture peut le surcharger (`invoice_lines.tax_rate_bp`), ce qui
  -- est ce qui rend une facture à deux taux représentable.
  add column if not exists vat_rate_bp          integer,
  -- La mention qui *remplace* la TVA quand elle ne s'applique pas. Le texte est
  -- au locataire parce que le motif l'est : franchise en base, autoliquidation,
  -- exonération n'ont pas la même phrase.
  add column if not exists vat_exemption_reason text,
  -- Le taux des pénalités de retard, en points de base. Obligatoire sur toute
  -- facture entre professionnels ; sans accord, c'est le taux BCE + 10 points,
  -- que ce dépôt ne mesure pas — donc le locataire l'écrit.
  add column if not exists late_penalty_rate_bp integer;

alter table tenants
  add constraint tenants_siren_shape
    check (siren is null or siren ~ '^[0-9]{9}$'),
  -- Deux lettres de pays puis 2 à 13 caractères : la forme commune à l'UE, pas
  -- la clé de contrôle française — vérifier une clé serait affirmer connaître
  -- l'algorithme de vingt-sept administrations.
  add constraint tenants_vat_number_shape
    check (vat_number is null or vat_number ~ '^[A-Z]{2}[0-9A-Z]{2,13}$'),
  add constraint tenants_vat_rate_is_never_zero
    check (vat_rate_bp is null or (vat_rate_bp between 1 and 10000)),
  add constraint tenants_late_penalty_rate_range
    check (late_penalty_rate_bp is null or (late_penalty_rate_bp between 1 and 20000)),
  -- Un taux ou une raison de ne pas en avoir, jamais les deux.
  add constraint tenants_vat_is_a_rate_or_a_reason
    check (vat_rate_bp is null or vat_exemption_reason is null),
  -- Un assujetti a un numéro intracommunautaire. L'inverse n'est pas vrai — un
  -- non-assujetti peut en avoir un pour ses acquisitions — donc la contrainte
  -- ne va que dans ce sens.
  add constraint tenants_a_vat_rate_needs_a_vat_number
    check (vat_rate_bp is null or vat_number is not null);

grant update (
  legal_form, postal_address, siren, rcs_city,
  vat_number, vat_rate_bp, vat_exemption_reason, late_penalty_rate_bp
) on tenants to app_role;
