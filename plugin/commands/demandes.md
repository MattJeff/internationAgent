---
name: demandes
description: Vider la file humaine — lire, décider, et écrire à l'employé concerné.
argument-hint: [id d'une approbation, ou rien pour toute la file]
disable-model-invocation: true
---

Traite les demandes en attente : « $ARGUMENTS » (sans argument, toute la file).

Lis `${CLAUDE_PLUGIN_ROOT}/skills/repondre-aux-demandes/SKILL.md` et suis-le. L'action d'une
approbation se recopie octet par octet ; ne la reformule jamais.
