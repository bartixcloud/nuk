# Einzelhost-Betrieb: drei Lücken in nuk (Design)

Status: von Jona freigegeben (Entwurf A für Lücke 3, Vorschläge zu Lücke 1 und 2), 2026-11-02.

## Anlass

ekd-akd soll nicht auf die Incus-Flotte, sondern auf einen eigenen VPS: ein Tenant, eine VM,
Rolle `all-in-one`, eigene Source und eigener Signaturanker. Ein Probelauf von nuk v2.13.0
auf einer Wegwerf-VM hat drei Lücken gezeigt. Alle Änderungen sind opt-in; die Flotte
(`astrocloud`) konvergiert unverändert und ihre Renders bleiben byte-identisch.

## Ziele

- Der Name des Org-Manifests ist pro Platform-Source einstellbar.
- Eine Deployment-Placement `app` funktioniert auf einem `all-in-one`-Einzelhost.
- `privateIp` ist bei genau einem Host nicht mehr Pflicht.
- Eine Facility kann Dateien aus dem verifizierten Tag nach `traefik/dynamic/` installieren,
  atomar und mit strukturbewusstem Token-Rendering.

## Nicht-Ziele

- Keine Lockerung der Mehrhost-Validierung (`org.py` Exactly-one-entry-host, Eindeutigkeit der IPs).
- Keine Änderung an `infra/tf-incus/instances.tf` und keine Änderung an der Flotten-Facility `ingress`.
- Kein Entfernen von Dateien (die Schleife löscht weiter nichts), kein Anlegen des Docker-Netzes `edge`.
- Kein Generieren der Gates aus den Facility-Deklarationen (wäre ein Umbau der Flotten-Renders).

## Anti-Ziele

- Ein Tag darf den Dateinamen des Org-Manifests nicht bestimmen können.
- `install` darf nie eine Datei überschreiben, die nuk nicht selbst geschrieben hat.
- Nie Textersetzung auf YAML. Nie ein halb geschriebenes Ziel im beobachteten Verzeichnis.

## Lücke 1: `org_file`

`sources.yml`, Eintrag der Platform-Source (der mit `facilities` in `apply`):

```yaml
sources:
  - name: platform
    repo: ssh://…
    deploy_key: …
    apply: [facilities, deployments, routes]
    org_file: nuklaut.org.yml   # optional, Default nuklaut.astrocloud.org.yml
```

- `SourceEntry.org_file: str = DEFAULT_ORG_FILE`. Muster: reiner Dateiname, `^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$`
  (kein `/`, kein `..`). Auf einer Tenant-Source (ohne `facilities`) ist ein gesetztes Feld ein
  Validierungsfehler, denn nur die Platform-Source hat einen Org-Manifest.
- Das Feld steht in der Host-Konfiguration, nicht im signierten Tag. Ein Tag kann den Namen nicht umbiegen.
- `TreeContext.build(..., org_file=…)` liest `base / org_file`. `_prepare_source` reicht den Namen der
  Platform-Source durch, die Tenant-Sources erben den Org der Platform-Tree und brauchen ihn nicht.
- Die Fehlermeldung in `converge.py` nennt den konfigurierten Namen.
- `DEFAULT_ORG_FILE` bleibt als Konstante (Tests und Default).
- Verworfen: Umgebungsvariable (implizit, schwer prüfbar), Zeiger-Datei im Tag (Vertrauensfrage).

## Lücke 2: Einzelhost

Ursache: Auf einem `all-in-one`-Host rendert `cmd_apply` den Router lokal mit Containername und
veröffentlicht keinen Host-Port (`edge_term` ist False). Der Edge-Render überspringt Placements mit
Rolle `edge` oder `all-in-one` schon (`_render_routers`), nicht aber `app`. Das Deployment scheitert
in `backend_address` mit „no host with role 'app'“, und selbst ein aufgelöstes Backend würde den
lokalen Router mit einem `privateIp:port` überschreiben, auf dem nichts lauscht.

- `Org.composed_by_all_in_one(placement) -> bool`: wahr, wenn der Org einen `all-in-one`-Host hat und
  (`placement.host` ist gesetzt und nennt genau diesen Host) oder (`placement.host` fehlt und der Org
  deklariert für `placement.role` keinen eigenen Host). Der `all-in-one`-Host komponiert Edge, Data und
  App (`placement_matches`), also läuft die Placement dort lokal.
- `_render_routers` überspringt solche Placements wie die Entry-Rollen.
- Mehrhost-Orgs mit echtem `app`-Host bleiben unverändert; `test_backend_refuses_a_role_the_org_does_not_declare`
  (Placement `all-in-one` ohne `all-in-one`-Host) bleibt ein Fehler.
- `Host.private_ip: str | None`. Ein Validator verlangt `privateIp` unbedingt, sobald der Org mehr
  als einen Host hat. Eindeutigkeit und Subnetz-Prüfung überspringen `None`. `backend_address`
  verweigert einen Host ohne `privateIp` mit klarer Meldung (erreichbar nur im Mehrhost-Fall, also nie).

## Lücke 3: `spec.install`

Facility-Feld, nur in `FacilitySpec`:

```yaml
spec:
  install:
    - src: global.yml          # relativ zum Payload-Verzeichnis facilities/<name>/
      name: global.yml         # Dateiname in /opt/nuklaut/traefik/dynamic/
      vars: {AUTH_BACKEND: "authentik-server:9000"}
      secretVars: {DASHBOARD_AUTH: /etc/nuklaut/secrets/dashboard-users}
```

Ablauf in `cmd_apply`, direkt nach dem Payload-Mirror (nur `kind: Facility`, nur wenn die Placement
zum Host passt, also edge oder all-in-one):

1. Quelle lesen: `<project>/repo/<src>` (der gespiegelte, verifizierte Tag-Stand). `src` ist relativ,
   ohne `..`, und muss innerhalb von `repo/` auflösen.
2. Rendern, strukturbewusst: `yaml.safe_load`, dann in allen String-Blättern (Werte und Listenelemente,
   nie Schlüssel, nie Kommentare) `__NAME__` ersetzen, dann `yaml.safe_dump(sort_keys=False)`, dann das
   Ergebnis erneut parsen und gegen das Original-Gerüst prüfen (muss ein Mapping sein). Tokenquellen:
   eingebaut `DOMAIN` = `org.platformDomain`; `vars` als Literale; `secretVars` liest die erste nicht
   leere Zeile einer Datei, die unter `/etc/nuklaut/secrets/` oder `/run/nuklaut/secrets/` liegen muss.
   Ein verbleibendes `__NAME__` oder eine fehlende Quelle bricht ab (fail closed), nichts wird geschrieben.
   Secrets landen nie in einer Fehlermeldung oder im Status.
3. Eigentum prüfen: Zielpfad `paths.DYNAMIC / name`; `name` ist ein reiner Dateiname mit
   Endung `.yml`/`.yaml`. nuk merkt sich den SHA-256 der zuletzt geschriebenen Datei unter
   `paths.CONVERGE_STATE/installed/<facility>--<name>.sha256`. Überschrieben wird nur, wenn das Ziel
   fehlt, dem Merkhash entspricht oder bereits dem neuen Inhalt gleicht. Sonst bricht die Facility mit
   der Anweisung ab, die Datei einmal beiseitezulegen. So überschreibt nuk weder die cloud-init-Kopie der
   Flotte noch ein altes Host-Artefakt ungefragt.
4. Schreiben, atomar: gleicher Inhalt bedeutet kein Schreiben und kein Reload. Sonst temp-Datei in
   `paths.DYNAMIC.parent / ".nuk-staging"` (gleiches Dateisystem, außerhalb des beobachteten
   Verzeichnisses), `fsync`, Modus 0644, `os.replace`, danach Merkhash schreiben.
- `declaration_only` gilt nur ohne `install`, damit eine Facility mit `install` ihr Payload-Verzeichnis braucht.
- Die Flotten-Facility `ingress` deklariert kein `install`; ihr Verhalten ändert sich nicht.

## Entscheidungen von Jona

| Punkt | Entscheidung |
|---|---|
| Lücke 3 | Entwurf A (nuk installiert selbst) statt Sync-Container in der Facility |
| Lücke 1 | `org_file` pro Platform-Source in `sources.yml`, Default unverändert |
| Lücke 2 | Edge-Render überspringt, `privateIp` nur bei genau einem Host optional |

## Meine Entscheidungen (zur Kenntnis)

- Zielverzeichnis ist fest `paths.DYNAMIC`, kein frei wählbarer Pfad.
- Kein Überschreiben fremder Dateien; Auflösung per Handgriff statt Flag.
- Kollidiert `name` mit dem Router-Dateinamen eines Deployments (`<deployment>.yml`), wird das nicht
  geprüft; der Fall ist unrealistisch (`global.yml` gegen ein Deployment namens `global`).
- Ausgabe von `safe_dump` verliert Kommentare und Einrückungsstil. Gewollt: die installierte Datei ist
  ein Render, keine Kopie.

## Tests (alle zuerst rot)

- `test_nuk_sources`/`test_nuk_converge`: Default-Name, eigener Name, Tenant mit `org_file` abgelehnt,
  Pfadtrenner abgelehnt, Fehlermeldung nennt den Namen, Tenant-Tree wird mit dem Platform-Namen gelesen.
- `test_nuk_org`/`test_nuk_edge_render`: Einzelhost ohne `privateIp` lädt; zwei Hosts ohne `privateIp` nicht;
  Deployment `app` auf `all-in-one` rendert nichts am Edge und lässt den lokalen Router unberührt;
  Mehrhost mit `app`-Host rendert wie bisher.
- `test_nuk_install` (neu): Token nur in Werten, Kommentar- und Schlüssel-Token bleiben unberührt,
  Rest-Token bricht ab, Secret-Datei außerhalb der Allowlist abgelehnt, atomarer Austausch (nie ein
  leeres oder halbes Ziel, auch bei Fehler in der Mitte), gleicher Inhalt schreibt nicht, fremde Datei
  wird verweigert, vom Merkhash bekannte Datei wird ersetzt, Facility ohne `install` unverändert.
- Regression: die gesamte bestehende Suite grün, Ruff-Baseline (122 Fehler, 8 Format-Dateien) nicht überschritten.
