# Einzelhost-Lücken: Umsetzungsplan

Design: [2026-11-02-single-host-gaps-design.md](../specs/2026-11-02-single-host-gaps-design.md). Jede Aufgabe: Test schreiben und rot sehen, minimal umsetzen, grün, committen (Conventional Commits, Dateien einzeln stagen).

## Aufgabe 1: `org_file` (Lücke 1)

- Dateien: `nuk/sources.py` (`SourceEntry.org_file`, Validierung), `nuk/facility.py` (`TreeContext.build(org_file=…)`), `nuk/converge.py` (`_prepare_source` und Meldung), Tests in `tests/test_nuk_converge.py`.
- Test rot: Platform-Tree mit `nuklaut.org.yml` wird nur mit `org_file: nuklaut.org.yml` gefunden; Default findet `nuklaut.astrocloud.org.yml` weiter; Tenant mit `org_file` und Pfadtrenner werden abgelehnt.
- Commit: `feat(sources): configurable org manifest name per platform source`.

## Aufgabe 2: Einzelhost (Lücke 2)

- Dateien: `nuk/org.py` (`Host.private_ip` optional, Validator, `composed_by_all_in_one`), `nuk/converge.py` (`_render_routers` überspringt), `nuk/ingress.py` (Guard), Tests in `tests/test_nuk_org.py`, `tests/test_nuk_edge_render.py`.
- Test rot: reproduziert „no host with role 'app'“ über `render_edge_routers` auf einem `all-in-one`-Org; Org mit zwei Hosts ohne `privateIp` bleibt ungültig.
- Commit: `fix(edge): leave app placements local on an all-in-one host` und `feat(org): privateIp optional for a single-host org`.

## Aufgabe 3: `spec.install` (Lücke 3)

- Dateien: `nuk/models.py` (`Install`, `FacilitySpec.install`), neu `nuk/install.py` (Render, Eigentum, atomares Schreiben), `nuk/paths.py` (Merkhash-Verzeichnis ableitbar aus `CONVERGE_STATE`), `nuk/rollout.py` (Aufruf nach dem Payload-Mirror, `declaration_only`), Tests neu `tests/test_nuk_install.py`.
- Schritte: erst die reine Render-Funktion (Tokens nur in Werten), dann Eigentum und atomares Schreiben, dann die Verdrahtung in `cmd_apply`, zuletzt die Regression „Facility ohne `install` unverändert“.
- Commits: `feat(install): render and atomically install facility files`, `feat(facility): spec.install in cmd_apply`.

## Aufgabe 4: Abschluss

- `uv run pytest` voll, `ruff check` und `ruff format --check` gegen die Baseline (122 Fehler, 8 Dateien).
- README: Abschnitt zu `org_file` und `spec.install`. PR auf `bartixcloud/nuk`, nicht gemergt.
