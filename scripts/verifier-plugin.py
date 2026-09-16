#!/usr/bin/env python3
"""Ce que le plugin Claude Code promet, et qu'aucun compilateur ne relit.

Cinq choses, parce que ce sont les cinq qui se cassent en silence :
le frontmatter de chaque skill, **chaque outil cité par un geste existe encore
dans le registre Rust** (c'est celle qui compte — les 116 lignes sont éditées par
d'autres chantiers, et un outil renommé rend un skill faux sans rien casser),
l'absence de secret, **les gabarits de limites embarqués par `monter-la-societe`
sont encore les documents du fondateur à l'octet près**, et le chemin du
marketplace vers son manifeste.

    python3 scripts/verifier-plugin.py
"""

import glob, json, os, re, sys

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
bad = []

# 1. frontmatter of every skill / command
for p in sorted(glob.glob("plugin/skills/*/SKILL.md") + glob.glob("plugin/commands/*.md")):
    t = open(p, encoding="utf-8").read()
    if not t.startswith("---\n"):
        bad.append(f"{p}: pas de frontmatter en tete")
        continue
    fm = t.split("---\n", 2)[1]
    keys = [l.split(":", 1)[0] for l in fm.splitlines() if l and not l.startswith(" ")]
    known = {"name", "description", "argument-hint", "disable-model-invocation"}
    unknown = set(keys) - known
    if unknown:
        bad.append(f"{p}: champ non documente {unknown}")
    if "description" not in keys:
        bad.append(f"{p}: pas de description")
    if "name" not in keys:
        bad.append(f"{p}: pas de name")
    # le nom doit correspondre au dossier / fichier
    nm = re.search(r"^name:\s*(\S+)", fm, re.M).group(1)
    want = os.path.basename(os.path.dirname(p)) if p.endswith("SKILL.md") else os.path.basename(p)[:-3]
    if nm != want:
        bad.append(f"{p}: name={nm} != {want}")
    d = re.search(r"^description:\s*(.+)$", fm, re.M).group(1)
    if len(d) > 1536:
        bad.append(f"{p}: description > 1536 car.")
    print(f"OK frontmatter {p} (name={nm}, description {len(d)} car.)")

# 2. chaque outil cite existe-t-il dans le registre Rust ?
rust = "".join(open(f, encoding="utf-8").read() for f in glob.glob("crates/app/src/mcp_tools/*.rs"))
registry = set(re.findall(r'"([a-z][a-z0-9_]+)"', rust))
cited = set()
for p in glob.glob("plugin/skills/*/SKILL.md") + glob.glob("plugin/commands/*.md") + ["docs/PLUGIN.md"]:
    cited |= set(re.findall(r"`([a-z][a-z0-9]+_[a-z0-9_]+)`", open(p, encoding="utf-8").read()))
noise = {"dry_run", "user_config", "last_failure_detail", "outstanding_minor", "cost_source",
         "bad_segment", "name_taken", "approval_action_mismatch", "no_spend_policy",
         "policy_widens", "reporting_cycle", "draft_is_not_resumable", "turns_taken",
         "contacts_held_back", "acts_on_its_own", "set_by", "reports_to", "team_id",
         "employee_id", "action_kind", "deny_reason", "role_name", "max_turns_per_day",
         "interval_secs", "section_id", "plugin_root", "cle_api", "base_url", "next_since",
         # Champs de reponse et valeurs d'enum que `point-du-jour` cite par leur
         # nom, parce qu'un geste qui dit « lis le verdict » sans dire lequel ne
         # se relit pas. Ils ont la meme forme qu'un nom d'outil et n'en sont pas.
         "last_success_at", "last_failure_employee_slug", "expires_at",
         # Le champ que `work_items_list` rend et que `point-du-jour` doit
         # pouvoir nommer : c'est lui qui mene du tableau au texte recu.
         "conversation_id",
         "to_next_rate", "no_target", "on_track", "raised_after_denials",
         # Les codes de refus et les champs d'objectif que `monter-la-societe`
         # nomme, parce qu'un geste qui dit « si ca refuse, recommence » sans
         # dire ce qu'on lit fait deviner. Aucun n'est un outil.
         "cli_failed", "cli_spawn_failed", "domain_taken", "no_charter",
         "no_model", "no_platform_policy", "not_sent", "objective_field",
         "role_layer_exists", "tenant_mismatch", "unreachable_colleague",
         "window_exists", "corporate_travel", "escalate_to",
         "first_response_hours", "target_accounts"}
missing = sorted(t for t in cited - noise if t not in registry)
if missing:
    bad.append(f"outils cites et absents du registre : {missing}")
else:
    print(f"OK {len(cited - noise)} outils cites, tous presents dans le registre")

# 2b. et le compte que la doc en annonce. Meme regle que
# `every_written_count_is_the_registry_s_own` cote Rust : un nombre tape dans de
# la prose est vrai le jour ou il est ecrit. Celui-ci disait 55 pendant que les
# gestes en citaient 60.
attendu = f"chacun des {len(cited - noise)} outils nommes par les cinq gestes"
plugin_md = open("docs/PLUGIN.md", encoding="utf-8").read()
plugin_md_sans_accents = (plugin_md.replace("\u00e9", "e").replace("\u00e8", "e")
                          .replace("\u00ea", "e").replace("\u00e0", "a"))
if attendu.replace("\n", " ") not in " ".join(plugin_md_sans_accents.split()):
    bad.append(f"docs/PLUGIN.md n'annonce plus le bon compte : {attendu!r}")
else:
    print(f"OK docs/PLUGIN.md annonce {len(cited - noise)} outils cites")

# 3. aucun secret
for p in sorted(glob.glob("plugin/**/*", recursive=True) + [".claude-plugin/marketplace.json", "docs/PLUGIN.md"]):
    if not os.path.isfile(p):
        continue
    t = open(p, encoding="utf-8").read()
    # un `Bearer ` suivi de douze caracteres de jeton ; `${...}` et `<cle>` sont des trous, pas des secrets
    for pat in (r"sk-[A-Za-z0-9]", r"\bre_[A-Za-z0-9]", r"whsec_[A-Za-z0-9]", r"Bearer [A-Za-z0-9_.\-]{12}"):
        if re.search(pat, t):
            bad.append(f"{p}: secret possible, motif {pat}")
print("OK aucun sk- / re_ / whsec_ / Bearer litteral" if not any("secret" in b for b in bad) else "")

# 3b. les gabarits embarques sont les documents du fondateur, a l'octet pres.
# Le plugin doit etre lisible une fois installe, donc il porte sa copie ; une copie
# qui derive est un modele qui pose des limites que personne n'a ecrites.
for src, dst in [("docs/orizn-org.json", "organigramme.json")] + [
        (f"docs/orizn-roles/{r}.json", f"{r}.json")
        for r in ("direction", "sales-development", "customer-success", "growth", "finance")]:
    emb = os.path.join("plugin/skills/monter-la-societe/gabarits", dst)
    if not os.path.isfile(emb):
        bad.append(f"{emb}: gabarit absent")
    elif open(emb, "rb").read() != open(src, "rb").read():
        bad.append(f"{emb} a derive de {src} — le gabarit est une copie, pas une variante")
    else:
        print(f"OK gabarit {dst} == {src}")

# 4. le marketplace pointe sur un plugin qui existe
mk = json.load(open(".claude-plugin/marketplace.json"))
for e in mk["plugins"]:
    src = e["source"]
    assert src.startswith("./"), src
    man = os.path.join(src, ".claude-plugin", "plugin.json")
    if not os.path.isfile(man):
        bad.append(f"marketplace: source {src} sans manifeste")
    elif json.load(open(man))["name"] != e["name"]:
        bad.append(f"marketplace: nom {e['name']} != manifeste")
    else:
        print(f"OK marketplace -> {src} (plugin '{e['name']}')")

print()
if bad:
    print("\n".join("ECHEC " + b for b in bad)); sys.exit(1)
print("tout passe")
