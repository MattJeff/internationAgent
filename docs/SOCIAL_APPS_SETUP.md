# SOCIAL — mise en place des apps

Le service est `apps/social` (binaire `agentos-social`). Les paires
client/secret vivent dans l'environnement, jamais dans le dépôt.
`docs/SOCIAL.md` porte le contrat des outils et les revues d'app ; cette
page est le geste opérateur.

Variables : `SOCIAL_DATABASE_URL`, `SOCIAL_MASTER_KEY`, `SOCIAL_PUBLIC_URL`,
puis `SOCIAL_X_*`, `SOCIAL_LINKEDIN_*`, `SOCIAL_META_*`, `SOCIAL_TIKTOK_*`,
`SOCIAL_GOOGLE_CLIENT_ID` / `SOCIAL_GOOGLE_CLIENT_SECRET`.

## YouTube — Data API et Analytics

Les deux API se activent dans le **même** projet Google Cloud
(`https://console.cloud.google.com`), celui dont le client OAuth est déjà
dans `SOCIAL_GOOGLE_*`.

1. **API et services → Bibliothèque.** Activer **YouTube Data API v3**
   (déjà requise pour publier) et **YouTube Analytics API**. Sans la
   seconde, `youtube_analytics_report` prend un 403 d'API non activée, pas
   un rapport.
2. **Écran de consentement OAuth.** Les portées demandées par le service,
   séparées par des espaces :

   `https://www.googleapis.com/auth/youtube.upload`
   `https://www.googleapis.com/auth/youtube.force-ssl`
   `https://www.googleapis.com/auth/youtube.readonly`
   `https://www.googleapis.com/auth/yt-analytics.readonly`

   `youtube.readonly` est exigé par `reports.query` en plus de
   `yt-analytics.readonly` (documentation Analytics, page datée
   2026-10-15). On ne demande pas la portée monétaire.
3. **Redémarrer `agentos-social`.** Le binaire applique la migration
   `0008` au démarrage (`oauth_scopes` sur `social_accounts`, kind
   `youtube` dans la file d'approbation). Un redémarrage sans le nouveau
   binaire laisse les outils absents.
4. **Reconnecter les deux chaînes une fois.** Chaque compte YouTube déjà
   connecté n'a que `youtube.upload` et `youtube.force-ssl`.
   `youtube_analytics_report` répond `scopes_insuffisants` et nomme
   `account_connect_url` : un humain ouvre l'URL (`prompt=consent`,
   `include_granted_scopes=true`). Les autres écritures Data API, couvertes
   par `youtube.force-ssl`, continuent en attendant. Deux chaînes, deux
   consentements, pas plus.

Après coup, `accounts_list` montre les mêmes handles. Les outils neufs se
déclarent comme les autres (`integrations_discover`, puis
`integrations_declare_tool` sur le digest lu). Tant qu'un outil n'est pas
déclaré, l'appel employé est refusé.

## Ce que ces outils ne font pas

L'API officielle ne le permet pas, et le service ne l'invente pas :

* les liens de la section À propos (site, autres réseaux) ;
* les posts Communauté ;
* l'édition de la bannière de chaîne.

`youtube_channel_update` relit `brandingSettings` et n'écrase que les champs
demandés, y compris `image`, pour ne pas effacer une bannière déjà posée.
Il n'en téléverse pas une.

## Approbation

Supprimer une vidéo, une playlist, un élément de playlist, un commentaire
ou une piste de sous-titres, changer une visibilité (`privacy`,
`publish_at`), ou modérer un commentaire pose une ligne `pending_approval`.
`approval_decide` (route opérateur, pas un outil d'employé) envoie l'appel
YouTube. Le rejeu de la même `idempotency_key` ne crée pas une seconde
ligne.
