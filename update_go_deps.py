#!/usr/bin/env python3
r"""
Sauvegarde puis mise à jour ciblée des dépendances : modules Go vulnérables ET
packages Python utilisés par les scripts (pont TF/Isaac, etc.).

Par défaut le script est en LECTURE SEULE : il analyse et affiche ce qu'il ferait.
Rien n'est modifié sans --apply.

Usage :
    python update_go_deps.py                      # analyse Go + Python (dry-run)
    python update_go_deps.py --apply              # sauvegarde + mise à jour
    python update_go_deps.py --apply --skip-python    # seulement Go
    python update_go_deps.py --apply --skip-go        # seulement Python
    python update_go_deps.py --python-dir U:\\Projets\\Bridge --python-dir D:\\autre\\scripts
    python update_go_deps.py --apply --latest         # Go : dernière version plutôt que la version corrigée minimale
    python update_go_deps.py --apply --called-only    # Go : seulement les failles réellement appelées
    python update_go_deps.py --apply --allow-major    # Python : accepte aussi les sauts de version majeure

--- Go ---
  1. govulncheck repère les modules vulnérables (stdlib seulement signalée : elle dépend de la version de Go).
  2. go get <module>@<version corrigée>, go mod tidy, go build ./..., go vet ./...
  3. Échec du build/vet : go.mod et go.sum sont restaurés depuis la sauvegarde.

--- Python ---
  1. Détecte les imports des .py trouvés dans --python-dir (défaut : ../../Bridge, soit U:\Projets\Bridge) et les associe aux packages pip installés.
  2. Cible : packages vulnérables (si pip-audit est installé) + packages en retard (mineures/correctifs).
     Les sauts de version MAJEURE sont seulement signalés (sauf --allow-major ou faille corrigée par un saut majeur).
  3. pip install -U <packages>, puis pip check et py_compile sur chaque script.
  4. Échec : les anciennes versions sont réinstallées (pip install pkg==ancienne).
  IMPORTANT : le script met à jour l'interpréteur qui l'exécute (ou --python-exe). Les scripts du serveur
  (C:\\TI_Projet_Fuel, C:\\TI_Projet_Bridge) utilisent le Python DU SERVEUR : lance ce script là-bas.

Sauvegardes : backups/deps_<date>/ (go.mod, go.sum, .exe, pip freeze, copie des .py). Jamais écrasé ni supprimé.
Les .exe ne sont JAMAIS remplacés (le build de vérification est jeté).
"""
import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKUP_ROOT = ROOT / "backups"
GO_FILES_TO_BACKUP = ["go.mod", "go.sum"]
EXE_GLOBS = ["*.exe"]  # copiés dans la sauvegarde par sécurité, jamais modifiés
SKIP_DIRS = {"backups", "venv", ".venv", "env", "__pycache__", "site-packages", ".git", "node_modules"}
# import -> nom de package pip quand ils diffèrent
IMPORT_TO_DIST = {"dotenv": "python-dotenv", "yaml": "pyyaml", "bs4": "beautifulsoup4", "PIL": "pillow", "cv2": "opencv-python"}


def run(cmd, check=True, capture=True):
    print(f"$ {' '.join(str(c) for c in cmd)}")
    res = subprocess.run([str(c) for c in cmd], cwd=ROOT, text=True, capture_output=capture,
                         encoding="utf-8", errors="replace")
    if check and res.returncode != 0:
        if capture:
            sys.stdout.write(res.stdout or "")
            sys.stderr.write(res.stderr or "")
        raise RuntimeError(f"Commande en échec ({res.returncode}): {' '.join(str(c) for c in cmd)}")
    return res


# ----------------------------------------------------------------- sauvegarde

class Backup:
    """Crée le dossier de sauvegarde une seule fois, au premier besoin."""

    def __init__(self):
        self.dest = None

    def get(self):
        if self.dest is None:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.dest = BACKUP_ROOT / f"deps_{stamp}"
            self.dest.mkdir(parents=True, exist_ok=False)  # ne jamais réutiliser/écraser
            print(f"Sauvegarde : {self.dest}")
        return self.dest


# ------------------------------------------------------------------------- Go

def find_govulncheck():
    exe = shutil.which("govulncheck")
    if exe:
        return exe
    gopath = run(["go", "env", "GOPATH"]).stdout.strip().split(os.pathsep)[0]
    candidate = Path(gopath) / "bin" / ("govulncheck.exe" if os.name == "nt" else "govulncheck")
    if candidate.exists():
        return str(candidate)
    print("govulncheck absent : installation (go install golang.org/x/vuln/cmd/govulncheck@latest)")
    run(["go", "install", "golang.org/x/vuln/cmd/govulncheck@latest"])
    if candidate.exists():
        return str(candidate)
    raise RuntimeError("govulncheck introuvable après installation")


def parse_version(v):
    v = str(v).lstrip("vV").split("+")[0].split("-")[0]
    parts = []
    for p in v.split(".")[:3]:
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def go_scan(govulncheck):
    """{module: {"fixed": version max, "called": bool, "osv": set(ids)}} (stdlib incluse)."""
    res = run([govulncheck, "-format", "json", "./..."], check=False)
    if res.returncode not in (0, 3):  # 3 = vulnérabilités trouvées
        sys.stdout.write(res.stdout or "")
        sys.stderr.write(res.stderr or "")
        raise RuntimeError("govulncheck a échoué")
    dec = json.JSONDecoder()
    text, i, found = res.stdout, 0, {}
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        f = obj.get("finding")
        if not f or not f.get("trace"):
            continue
        frame = f["trace"][0]
        mod, fixed = frame.get("module"), f.get("fixed_version")
        if not mod or not fixed:
            continue
        entry = found.setdefault(mod, {"fixed": fixed, "called": False, "osv": set()})
        if parse_version(fixed) > parse_version(entry["fixed"]):
            entry["fixed"] = fixed
        if frame.get("function"):
            entry["called"] = True
        entry["osv"].add(f.get("osv", "?"))
    return found


def go_phase(args, backup):
    if not shutil.which("go"):
        print("Go introuvable dans le PATH : partie Go ignorée.")
        return 0
    print("\n===== GO =====")
    print(run(["go", "version"]).stdout.strip())
    govulncheck = find_govulncheck()

    print("\n== Analyse des vulnérabilités ==")
    found = go_scan(govulncheck)
    stdlib = found.pop("stdlib", None)
    if args.called_only:
        found = {m: e for m, e in found.items() if e["called"]}

    if stdlib:
        print(f"\nBibliothèque standard Go : corrigée dans {stdlib['fixed']} "
              f"({', '.join(sorted(stdlib['osv']))}). Compile avec un Go >= cette version. Non traité ici.")

    # correctif seulement disponible en pseudo-version (pas encore de release taguée) : on ne l'applique pas
    unreleased = {m: e for m, e in found.items() if "-" in e["fixed"].lstrip("vV")}
    found = {m: e for m, e in found.items() if m not in unreleased}
    for mod, e in sorted(unreleased.items()):
        print(f"\n{mod} : le correctif ({', '.join(sorted(e['osv']))}) n'existe qu'en pseudo-version "
              f"({e['fixed']}), sans release taguée. Non appliqué : surveille la prochaine release.")

    if not found:
        print("\nAucun module Go vulnérable à mettre à jour.")
        return 0

    print("\nModules Go à mettre à jour :")
    for mod, e in sorted(found.items()):
        target = "latest" if args.latest else e["fixed"]
        print(f"  - {mod} -> {target}  ({'appelée' if e['called'] else 'importée seulement'}; {', '.join(sorted(e['osv']))})")

    if not args.apply:
        print("\nDry-run : rien n'a été modifié.")
        return 0

    dest = backup.get()
    for name in GO_FILES_TO_BACKUP:
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, dest / name)
    for pattern in EXE_GLOBS:
        for src in ROOT.glob(pattern):
            shutil.copy2(src, dest / src.name)
    try:
        for mod, e in sorted(found.items()):
            run(["go", "get", f"{mod}@{'latest' if args.latest else e['fixed']}"])
        run(["go", "mod", "tidy"])
        run(["go", "build", "./..."])  # vérification seulement : n'écrit aucun .exe
        run(["go", "vet", "./..."])
    except RuntimeError as err:
        print(f"\nÉCHEC Go : {err}")
        for name in GO_FILES_TO_BACKUP:
            if (dest / name).exists():
                shutil.copy2(dest / name, ROOT / name)
        print("go.mod et go.sum restaurés depuis la sauvegarde.")
        return 1

    print("\n== Nouvelle analyse Go ==")
    after = go_scan(govulncheck)
    after.pop("stdlib", None)
    if args.called_only:
        after = {m: e for m, e in after.items() if e["called"]}
    if after:
        print("Il reste des modules signalés :")
        for mod, e in sorted(after.items()):
            print(f"  - {mod} (corrigé dans {e['fixed']})")
    else:
        print("Plus aucun module Go vulnérable.")
    return 0


# --------------------------------------------------------------------- Python

def find_py_scripts(dirs):
    files = []
    for d in dirs:
        d = Path(d)
        if not d.exists():
            print(f"Dossier introuvable, ignoré : {d}")
            continue
        for p in d.rglob("*.py"):
            if not any(part in SKIP_DIRS for part in p.parts):
                files.append(p)
    return sorted(set(files))


def imported_modules(files):
    mods = set()
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as e:
            print(f"Syntaxe invalide dans {f}: {e}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods.add(node.module.split(".")[0])
    return mods


def pip_json(py, *pipargs):
    res = run([py, "-m", "pip", *pipargs, "--format", "json", "--disable-pip-version-check"], check=False)
    try:
        return json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        return []


def python_phase(args, backup):
    print("\n===== PYTHON =====")
    py = args.python_exe
    print(run([py, "--version"]).stdout.strip(), "|", py)

    dirs = args.python_dir or [str(ROOT.parent.parent / "Bridge")]
    files = find_py_scripts(dirs)
    if not files:
        print("Aucun script Python trouvé.")
        return 0
    print(f"{len(files)} script(s) analysé(s) :", ", ".join(str(f) for f in files))

    # imports -> packages pip installés (ignore la bibliothèque standard)
    stdlib_names = getattr(sys, "stdlib_module_names", set())
    mods = {m for m in imported_modules(files) if m not in stdlib_names and m != "__future__"}
    # table import->distribution selon l'interpréteur ciblé
    probe = ("import importlib.metadata as m, json;"
             "print(json.dumps({k: v for k, v in m.packages_distributions().items()}))")
    mapping = json.loads(run([py, "-c", probe]).stdout)
    installed = {p["name"].lower(): p["version"] for p in pip_json(py, "list")}

    wanted, missing = {}, []
    for m in sorted(mods):
        dists = mapping.get(m) or ([IMPORT_TO_DIST[m]] if m in IMPORT_TO_DIST else [m])
        dist = next((d for d in dists if d.lower() in installed), None)
        if dist:
            wanted[dist.lower()] = installed[dist.lower()]
        else:
            missing.append(m)
    print("\nPackages utilisés par les scripts :", ", ".join(f"{k} {v}" for k, v in sorted(wanted.items())) or "aucun")
    if missing:
        print("Non installés sur CET interpréteur (ignorés ici) :", ", ".join(missing))

    # vulnérabilités (pip-audit, si présent)
    vulnerable = {}
    audit = run([py, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off"], check=False)
    if audit.returncode in (0, 1) and (audit.stdout or "").strip().startswith("{"):
        for dep in json.loads(audit.stdout).get("dependencies", []):
            name = dep["name"].lower()
            if name in wanted and dep.get("vulns"):
                fixes = [v for vv in dep["vulns"] for v in vv.get("fix_versions", [])]
                vulnerable[name] = max(fixes, key=parse_version) if fixes else None
    else:
        print("pip-audit non installé : seule la mise à jour des versions en retard est évaluée "
              "(pour les failles : python -m pip install pip-audit).")

    outdated = {p["name"].lower(): p for p in pip_json(py, "list", "--outdated") if p["name"].lower() in wanted}

    targets, skipped_major = {}, []
    for name, old in sorted(wanted.items()):
        o = outdated.get(name)
        vuln = name in vulnerable
        if not o and not vuln:
            continue
        latest = o["latest_version"] if o else vulnerable[name]
        is_major = bool(o) and parse_version(latest)[0] > parse_version(old)[0]
        if is_major and not (args.allow_major or vuln):
            skipped_major.append((name, old, latest))
            continue
        targets[name] = (old, latest, vuln)

    if skipped_major:
        print("\nSauts de version MAJEURE non appliqués (relance avec --allow-major après avoir testé) :")
        for name, old, latest in skipped_major:
            print(f"  - {name} {old} -> {latest}")
    if not targets:
        print("\nAucun package Python à mettre à jour.")
        return 0

    print("\nPackages Python à mettre à jour :")
    for name, (old, latest, vuln) in targets.items():
        print(f"  - {name} {old} -> {latest}{'  [VULNÉRABLE]' if vuln else ''}")

    if not args.apply:
        print("\nDry-run : rien n'a été modifié.")
        return 0

    dest = backup.get()
    freeze = run([py, "-m", "pip", "freeze"]).stdout
    (dest / "pip_freeze.txt").write_text(freeze, encoding="utf-8")
    scripts_dir = dest / "python_scripts"
    scripts_dir.mkdir(exist_ok=True)
    for f in files:
        shutil.copy2(f, scripts_dir / f"{abs(hash(str(f))) % 10**6}_{f.name}")

    try:
        run([py, "-m", "pip", "install", "--upgrade", *[f"{n}>={v[1]}" if v[2] else n for n, v in targets.items()]])
        run([py, "-m", "pip", "check"])
        for f in files:
            run([py, "-m", "py_compile", f])
    except RuntimeError as err:
        print(f"\nÉCHEC Python : {err}")
        run([py, "-m", "pip", "install", *[f"{n}=={v[0]}" for n, v in targets.items()]], check=False)
        print("Anciennes versions réinstallées.")
        return 1
    print("\nMise à jour Python terminée (pip check et compilation des scripts OK).")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Sauvegarde + mise à jour des dépendances Go et Python")
    ap.add_argument("--apply", action="store_true", help="applique réellement (sinon dry-run)")
    ap.add_argument("--skip-go", action="store_true")
    ap.add_argument("--skip-python", action="store_true")
    ap.add_argument("--latest", action="store_true", help="Go : dernière version au lieu de la version corrigée minimale")
    ap.add_argument("--called-only", action="store_true", help="Go : seulement les failles réellement appelées")
    ap.add_argument("--python-dir", action="append", help="dossier de scripts Python à analyser (répétable)")
    ap.add_argument("--python-exe", default=sys.executable, help="interpréteur Python à mettre à jour")
    ap.add_argument("--allow-major", action="store_true", help="Python : accepte les sauts de version majeure")
    args = ap.parse_args()

    backup = Backup()
    rc = 0
    if not args.skip_go:
        rc |= go_phase(args, backup)
    if not args.skip_python:
        rc |= python_phase(args, backup)
    if args.apply and backup.dest:
        print(f"\nTerminé. Sauvegarde : {backup.dest}")
        print("Reste à faire : tester (idéalement sur Fuel_test) avant de recompiler/relancer en production.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
