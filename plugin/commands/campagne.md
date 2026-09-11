---
name: campagne
description: Lancer une campagne — de l'import d'une liste au premier envoi.
argument-hint: [le CSV, le segment, ou ce qu'on veut lancer]
disable-model-invocation: true
---

Lance la campagne décrite par « $ARGUMENTS ».

Lis `${CLAUDE_PLUGIN_ROOT}/skills/lancer-une-campagne/SKILL.md` et suis-le dans l'ordre. Le
domaine d'envoi se vérifie avant tout le reste, et l'import passe à blanc avant d'être réel.
