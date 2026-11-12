#!/usr/bin/env bash
# Essais du refus des bibliothèques qui posent du code lancé avant main (ou après lui) : une entrée de .init_array
# sous Linux, de .CRT$XCU sous Windows, qui tourne avant tout journal et tout filet de panique sans qu'aucune ligne ne
# l'appelle. Le refus est dans les quatre configurations de cargo deny du dépôt ([bans] deny).
#   1. deny.toml, fenetre/deny.toml, extensions/deny.toml et fuzz/deny.toml refusent chacune des bibliothèques
#      connues (CONNUES ci-dessous), sans en oublier une.
#   2. inventory n'est admis que par Vanguard lui-même et par YARA-X (deny.toml), qui l'amènent aujourd'hui ; par
#      personne dans les crates à part. Aucune autre exception (wrappers) sur ces noms.
#   3. cargo deny refuse pour de vrai, sur un dépôt jetable aux crates locales : ctor amené par une crate quelconque,
#      inventory amené par une autre que vanguard ; inventory amené par « vanguard » passe.
# Sans cargo-deny : code 77, sauté avec sa raison, jamais un vert.
# Pas couvert : un constructeur posé à la main (#[link_section = ".init_array"]) par une bibliothèque, ou par une
# bibliothèque absente de la liste ; outils/constructeurs.py de toile le cherche aussi dans les sources et dans le
# programme compilé, ce regard n'est pas porté ici.
# Lancé par outils/verifier.sh (étape « constructeurs »).
#   outils/essais-constructeurs.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

CONNUES="ctor ctor-lite ctor-proc-macro dtor dtor-proc-macro inventory link-section linkme small_ctor startup static_init"

# 1 et 2 : lus dans les quatre fichiers (tomllib), une ligne par écart.
ecarts=$(CONNUES=$CONNUES python3 -I - <<'EOF'
import os, tomllib
connues = set(os.environ["CONNUES"].split())
admis = {"deny.toml": {"inventory": ["vanguard", "yara-x"]}}
for f in ["deny.toml", "fenetre/deny.toml", "extensions/deny.toml", "fuzz/deny.toml"]:
    try:
        with open(f, "rb") as d:
            refus = tomllib.load(d).get("bans", {}).get("deny", [])
    except (OSError, tomllib.TOMLDecodeError) as e:
        print(f"{f} illisible : {e}")
        continue
    vus = {}
    for r in refus:
        nom = r if isinstance(r, str) else r.get("crate", r.get("name", ""))
        vus[nom] = r.get("wrappers", []) if isinstance(r, dict) else []
    for nom in sorted(connues - vus.keys()):
        print(f"{f} : {nom} n'est pas refusée")
    for nom in sorted(connues & vus.keys()):
        voulu = admis.get(f, {}).get(nom, [])
        if sorted(vus[nom]) != sorted(voulu):
            print(f"{f} : {nom} admise par {vus[nom]}, attendu {voulu}")
EOF
)
code=$?
[[ $code == 0 && -z $ecarts ]] && ok "les quatre deny.toml refusent les $(wc -w <<<"$CONNUES") bibliothèques connues ; inventory par Vanguard et YARA-X seulement" ||
  ko "deny.toml (code $code) : $ecarts"

# 3 : cargo deny lui-même, avec le vrai deny.toml, sur des crates locales aux noms refusés.
if ! command -v cargo-deny >/dev/null; then
  echo "  (sauté : cargo-deny absent, le refus réel pas essayé)"
  ((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
  echo "cargo-deny absent : refus réel pas essayé."
  exit 77
fi
J=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-constructeurs.XXXX")
trap 'rm -rf "$J"' EXIT
crate() { # nom version [dépendance version] (une version écrite : sans elle, cargo deny y voit un joker)
  mkdir -p "$J/$1/src" && : >"$J/$1/src/lib.rs"
  printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\nlicense = "MIT"\npublish = false\n' "$1" "$2" \
    >"$J/$1/Cargo.toml"
  [[ -z ${3:-} ]] || printf '[dependencies]\n%s = { path = "../%s", version = "=%s" }\n' "$3" "$3" "$4" >>"$J/$1/Cargo.toml"
}
juge() { # crate
  SORTIE=$(CARGO_TARGET_DIR=$J/cible cargo deny --offline --manifest-path "$J/$1/Cargo.toml" --config deny.toml \
    check bans 2>&1)
  CODE=$?
}
crate ctor 0.5.0 && crate inventory 0.3.25
crate quelconque 0.1.0 ctor 0.5.0 && juge quelconque && avec_ctor=$CODE && dit_ctor=$SORTIE
crate autre 0.1.0 inventory 0.3.25 && juge autre && avec_inventory=$CODE && dit_inventory=$SORTIE
crate vanguard 0.95.0 inventory 0.3.25 && juge vanguard && par_vanguard=$CODE && dit_vanguard=$SORTIE
[[ $avec_ctor != 0 ]] && grep -q "crate 'ctor = 0.5.0' is explicitly banned" <<<"$dit_ctor" &&
  ok "cargo deny : ctor amené par une crate quelconque, refusé" || ko "ctor (code $avec_ctor) : $(tail -n3 <<<"$dit_ctor")"
[[ $avec_inventory != 0 ]] && grep -q "crate 'inventory = 0.3.25' is explicitly banned" <<<"$dit_inventory" &&
  ok "cargo deny : inventory amené par une autre que vanguard, refusé" ||
  ko "inventory par une autre (code $avec_inventory) : $(tail -n3 <<<"$dit_inventory")"
[[ $par_vanguard == 0 ]] && ok "cargo deny : inventory amené par vanguard, admis" ||
  ko "inventory par vanguard (code $par_vanguard) : $(grep -m3 -E '^(error|warning)' <<<"$dit_vanguard")"

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "Constructeurs : refusés partout, inventory seulement par Vanguard et YARA-X."
