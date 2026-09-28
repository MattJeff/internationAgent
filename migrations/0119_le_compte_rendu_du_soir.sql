-- 0119_le_compte_rendu_du_soir : `tenants.digest_sent_on`, le jour où le
-- compte rendu quotidien est parti au fondateur.
--
-- Savoir « ce qui s'est passé aujourd'hui » coûtait vingt requêtes à la main.
-- `GET /v1/digest` les rend en une, et une boucle envoie la même lecture par
-- mail à 18 h UTC. La colonne est la mémoire de cette boucle, au geste de
-- `content_repos.measured_on` (0115) et de `sequences.fed_on` : l'UPDATE qui
-- la pose est la réclamation, deux réplicas n'envoient qu'un mail.

alter table tenants add column if not exists digest_sent_on date;
