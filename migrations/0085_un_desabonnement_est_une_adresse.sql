-- 0085_un_desabonnement_est_une_adresse : le lien de désinscription que
-- `List-Unsubscribe` doit porter, et la seule chose qui le rend vérifiable.
--
-- Google et Yahoo exigent depuis février 2024 que tout envoi en volume porte
-- `List-Unsubscribe` **et** `List-Unsubscribe-Post: List-Unsubscribe=One-Click`.
-- `crates/domain/src/policy.rs` cite déjà l'autre moitié du même document —
-- `Deliverability::MAX_REFUSALS_PER_MILLE`, les 0,3 % de plaintes — et un
-- domaine qui applique la moitié « ne dépassez pas le seuil » sans la moitié
-- « offrez la porte de sortie » atteint le seuil d'autant plus vite : sans lien,
-- le seul bouton qu'un destinataire a sous la main est « spam ».
--
-- ---------------------------------------------------------------------------
-- POURQUOI UNE TABLE, ET PAS UNE URL DÉRIVÉE DE L'ADRESSE
-- ---------------------------------------------------------------------------
--
-- `…/unsubscribe/{base64(email)}` se devine, et un `POST` en un clic n'a par
-- construction aucune authentification derrière lui : la porte est ouverte à
-- tout le monde, pour tout le monde. `suppressions` n'accepte aucun DELETE
-- (0011), donc une désinscription forgée est **définitive** — c'est la seule
-- écriture de ce dépôt qu'un inconnu peut provoquer et que personne ne peut
-- annuler. Le jeton est donc un secret, pas une clé de lecture.
--
-- Même forme et même raison que `webhook_endpoints.path` (0053) : 16 octets de
-- CSPRNG en base64url derrière un préfixe. « Le chemin n'est pas un
-- credential » y était vrai parce qu'une signature suivait ; ici il n'y en a
-- pas, donc le jeton EST le credential et les 128 bits sont ce qui le tient.
--
-- ---------------------------------------------------------------------------
-- UNE LIGNE PAR (LOCATAIRE, ADRESSE), PAS PAR ENVOI
-- ---------------------------------------------------------------------------
--
-- Un jeton par envoi ferait grossir la table à la vitesse du volume sortant
-- pour rien : le lien ne dit qu'une chose, « cette personne ne veut plus de mail
-- de cette entreprise », et elle ne change pas d'un envoi au suivant. Un lien
-- stable a aussi la propriété qu'on veut le jour où quelqu'un clique sur un mail
-- vieux de six mois. `on conflict do nothing` + relecture, donc deux envois
-- simultanés au même prospect rendent le même jeton.
--
-- L'adresse est normalisée exactement comme `contacts.email` et
-- `suppressions.address`, parce que la désinscription se termine par un
-- `INSERT` dans `suppressions` et qu'une orthographe différente est une
-- suppression qui ne se déclenche jamais.

create table if not exists unsubscribe_links (
  -- `unsub_` + 16 octets CSPRNG en base64url. Clé primaire : la route publique
  -- ne connaît que ça, et elle le cherche avant de savoir de quel locataire il
  -- s'agit.
  token       text        primary key
                          constraint unsubscribe_links_token_shape
                          check (token ~ '^unsub_[A-Za-z0-9_-]{16,64}$'),

  tenant_id   uuid        not null references tenants (id) on delete cascade,

  -- Le destinataire. Normalisée à l'écriture, parce que la lecture s'en sert
  -- pour écrire dans `suppressions`, dont la CHECK exige la même forme.
  address     text        not null
                          constraint unsubscribe_links_address_normalised
                          check (address = lower(address)
                                 and address ~ '^[^@[:space:]]+@[^@[:space:]]+$'),

  created_at  timestamptz not null default now(),

  -- Un lien par personne et par entreprise : deux jetons pour une adresse est
  -- un jeton qui traîne dans un vieux mail et ne désabonne plus.
  constraint unsubscribe_links_tenant_address_key unique (tenant_id, address)
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, comme `appointments` (0063) : le rôle
-- propriétaire ne doit pas non plus lire les liens de toutes les entreprises
-- par distraction.
--
-- L'exception est documentée et unique : la route publique résout le jeton par
-- `admin_tx_bypassing_rls`, parce que la recherche PRÉCÈDE le fait de savoir de
-- quel locataire il s'agit — exactement l'argument de `webhook_endpoints`
-- (0053) et de `routes::booking`. Une fois le locataire connu, l'écriture de la
-- suppression repasse par `Db::tenant_tx`.

alter table unsubscribe_links enable row level security;
alter table unsubscribe_links force row level security;
drop policy if exists tenant_isolation on unsubscribe_links;
create policy tenant_isolation on unsubscribe_links
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Ni UPDATE ni DELETE : un jeton ne se réécrit pas, il est imprimé dans des
-- mails déjà partis. La ligne meurt avec le locataire, par cascade, et pas
-- autrement.
grant select, insert on unsubscribe_links to app_role;
