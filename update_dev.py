#!/usr/bin/env python3
"""
Mise à jour de l'environnement de dev en un clic : double-clic ou `python update_dev.py`.

Fait, dans l'ordre (voir update_go_deps.py pour le détail) :
  1. Sauvegarde dans backups/deps_<date>/ (go.mod, go.sum, .exe, pip freeze, scripts Python).
  2. Met à jour les modules Go vulnérables, puis go mod tidy / go build / go vet
     (retour automatique à l'ancien go.mod/go.sum si ça échoue).
  3. Met à jour les packages Python utilisés par les scripts de U:\\Projets\\Bridge
     (versions en retard, sans saut de version majeure; retour arrière automatique si ça échoue).

Ne remplace JAMAIS les .exe de production et ne supprime rien.
Pour seulement voir ce qui serait fait : python update_dev.py --dry-run
"""
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_go_deps  # noqa: E402


def main():
    if "--dry-run" in sys.argv:
        sys.argv.remove("--dry-run")
    elif "--apply" not in sys.argv:
        sys.argv.insert(1, "--apply")
    return update_go_deps.main()


if __name__ == "__main__":
    rc = 1
    try:
        rc = main()
    except Exception:
        traceback.print_exc()
    print("\n" + ("Terminé." if rc == 0 else "Terminé avec des erreurs : lis les messages ci-dessus."))
    input("Appuie sur Entrée pour fermer...")
    sys.exit(rc)
