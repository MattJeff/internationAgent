-- 0098_un_locataire_sort_par_son_proxy : l'adresse par laquelle les onglets
-- d'un locataire sortent, et les identifiants qui l'ouvrent.
--
-- `docs/BROWSER.md` § v3 trie une fois pour toutes : ce qui est du **logiciel**
-- se construit, ce qui est une **ressource** se paie. Une adresse IP
-- résidentielle est une ressource — Bright Data, Oxylabs, ou la ligne du
-- client. Nous n'en louons aucune et nous n'ouvrons aucun compte : cette table
-- est la **prise**, et rien d'autre. Un locataire qui n'a pas de ligne ici
-- sort par l'adresse du VPS, exactement comme avant.
--
-- ---------------------------------------------------------------------------
-- POURQUOI UNE LIGNE PAR LOCATAIRE, ET PAS PAR EMPLOYÉ
-- ---------------------------------------------------------------------------
--
-- `tenant_id` est la clé primaire, la forme de `tenant_domains` (0093) et pour
-- son argument : un proxy est une facture que le client paie, comme un
-- domaine, et la facture est au locataire. Un proxy par siège serait N
-- factures et N réputations d'adresse à suivre, pour un produit dont personne
-- n'a encore dit qu'il en avait besoin — et le passage à N est une deuxième
-- colonne dans la clé primaire le jour où quelqu'un le demande, pas une
-- réécriture.
--
-- Le port côté fournisseur (`Proxies::proxy_for`) est en revanche indexé par
-- **contexte** (`ctx-<tag>`), comme `CookieJar` et `BrowserProfiles`, parce que
-- c'est la seule chose que `browser_chrome.rs` tient des deux côtés ; c'est
-- `agentos_app::browser_proxy` qui remonte du contexte au locataire par
-- `employee_resources`, sous `admin_tx_bypassing_rls`, l'argument de 0095.
--
-- ---------------------------------------------------------------------------
-- L'ADRESSE EN CLAIR, LES IDENTIFIANTS SCELLÉS
-- ---------------------------------------------------------------------------
--
-- `url` est en clair : `http://gate.fournisseur.com:7000` n'est pas un secret,
-- c'est ce que la console affiche et ce qu'un opérateur compare avec la page
-- du fournisseur. `sealed_credentials` porte `utilisateur:mot de passe` sous
-- une enveloppe AES-256-GCM (`secrets.rs`), contexte `browser://<locataire>/proxy`
-- — le même espace de noms que le pot de cookies (`browser://<locataire>/<employé>`),
-- et un scellé recopié d'un locataire sur l'autre ne s'ouvre pas, parce que
-- l'AAD porte le locataire. Le préfixe `sealed_` est ce que
-- `identity::SEALED_COLUMNS` lit : cette colonne passe sous la rotation de clé
-- maître comme les six autres, et son test échoue si on l'oublie.
--
-- Le CHECK sur le schéma est la forme que `--proxy-server` et
-- `Target.createBrowserContext.proxyServer` acceptent (mesuré le 2026-09-10 sur
-- Chrome 152 : `GET /json/protocol` documente `proxyServer` comme « similar to
-- the one passed to --proxy-server »). Pas de chemin, pas de requête, pas
-- d'identifiants dans l'URL : un `http://user:pass@hote:port` mettrait le mot
-- de passe dans une colonne en clair, ce que la colonne d'à côté existe pour
-- éviter.
--
-- `checked_at` / `last_error` : le dernier verdict de `POST /v1/browser/proxy/check`,
-- comme `tenant_domains.checked_at`. Nul tant que personne n'a vérifié — et
-- personne ne vérifie sans un service d'écho **fourni par le client** : ce
-- dépôt n'écrit l'URL d'aucun tiers en dur.

create table if not exists browser_proxies (
  tenant_id           uuid        primary key references tenants (id) on delete cascade,

  url                 text        not null
                                  constraint browser_proxies_url_scheme
                                  check (url ~ '^(https?|socks4|socks5h?)://[^/?#@[:space:]]+$'),

  -- `Envelope::to_bytes` de `utilisateur:mot de passe`, sous
  -- `browser://<locataire>/proxy`. NULL : un proxy sans authentification.
  sealed_credentials  bytea,

  -- Ce que `--proxy-bypass-list` accepte : `<-loopback>;*.interne.example`.
  -- NULL = rien ne contourne le proxy.
  bypass              text,

  created_at          timestamptz not null default now(),
  checked_at          timestamptz,
  -- Le code de la dernière vérification ratée, jamais un message du
  -- fournisseur : `proxy_unreachable`, `proxy_auth_refused`, `no_ip_in_echo`.
  last_error          text
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, comme `tenant_domains` (0093) : le rôle
-- propriétaire ne lit pas le proxy des autres par distraction non plus. Et
-- c'est la garde qui compte ici plus qu'ailleurs — la ligne d'un voisin, c'est
-- son adresse de sortie et sa facture.

alter table browser_proxies enable row level security;
alter table browser_proxies force row level security;
drop policy if exists tenant_isolation on browser_proxies;
create policy tenant_isolation on browser_proxies
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- `delete` cette fois, contrairement à `tenant_domains` : un proxy se retire.
-- Retirer le sien, c'est sortir par l'adresse du VPS, ce qui est l'état de
-- départ de tout le monde et n'invalide aucune adresse déjà imprimée.
grant select, insert, update, delete on browser_proxies to app_role;
