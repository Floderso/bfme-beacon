# Einen Beacon-Server betreiben

Diese Anleitung ist für den, der den Server für seine Freunde betreibt. Du brauchst
etwas Erfahrung mit der Linux-Kommandozeile. Die Spieler-Anleitung steht in
[spielen.md](spielen.md).

`beacon-server` ist der Lobby- und Relay-Server von BFME Beacon. Die Spieler melden
sich mit `Beacon.exe` an, sehen sich in der Lobby und spielen BFME über das
Netzwerk-Menü, als säßen alle im selben Heimnetz. Jedes Spielpaket läuft dabei
verschlüsselt über deinen Server.

## 1. Was du brauchst

* Einen **Linux-Rechner mit x86_64-Prozessor** (64-Bit-PC, Mini-PC, NAS oder
  gemieteter Server), der während des Spielens läuft. Ein Image für ARM (zum
  Beispiel Raspberry Pi) gibt es noch nicht.
* **Docker** mit dem **Compose-Plugin** (`docker compose version` muss
  funktionieren).
* **Wenig Leistung:** Der Server ist ein kleines Programm ohne Datenbank. Er
  braucht kaum Prozessorleistung und nur einige Megabyte Arbeitsspeicher. Die
  Bandbreite ist gering, weil BFME nur kleine Pakete schickt. Beacon sendet jedes
  Paket zur Sicherheit zwei- bis dreimal; plane also etwas Upload-Reserve ein.
* **Am besten ein LAN-Kabel:** Jedes Spielpaket läuft über den Server.
  Schwankungen im WLAN spüren deshalb alle Spieler.
* **Einen Port:** 28086, für **TCP und UDP**.

## 2. Einrichten

Lege einen Ordner an, zum Beispiel `/opt/beacon`, und lade die Beispieldateien aus
[deploy/docker/](../../deploy/docker/) herunter:

```sh
sudo mkdir -p /opt/beacon && sudo chown "$USER": /opt/beacon
cd /opt/beacon
curl -fsSLO https://raw.githubusercontent.com/Floderso/bfme-beacon/main/deploy/docker/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/Floderso/bfme-beacon/main/deploy/docker/config.toml
mkdir -p maps data
chmod 600 config.toml
```

Der Container läuft als Benutzer `1000:1000`. Prüfe deine eigene Benutzer- und
Gruppen-ID:

```sh
id -u    # meistens 1000
id -g    # meistens 1000
```

Stehen da andere Zahlen, trage sie in `compose.yaml` bei `user:` ein. Dann kann der
Container `config.toml` lesen und in `data/` schreiben.

Passe in `config.toml` mindestens `server_name` und `motd` (Begrüßungstext) an.
Optional: `admin_names` (diese Spieler sind immer Host) und `max_players`.

## 3. Passwort setzen

Alle Spieler melden sich mit demselben Server-Passwort an. Es muss mindestens 8
Zeichen lang sein; besser 12 oder mehr. Gespeichert werden nur ein zufälliges Salt
und ein daraus abgeleiteter Schlüssel, nie das Passwort selbst.

```sh
cd /opt/beacon
read -rs -p "Server-Passwort: " PW && echo
printf '%s\n' "$PW" | docker run --rm -i --network none \
  --user "$(id -u):$(id -g)" -v "$PWD/config.toml:/config.toml" \
  ghcr.io/floderso/bfme-beacon-server:latest set-password --password-stdin
unset PW
```

Der Befehl ersetzt nur `salt` und `psk` in `config.toml`; Kommentare bleiben
erhalten. **Halte `config.toml` privat:** Der Schlüssel darin öffnet den Server
genau wie das Passwort.

Änderst du das Passwort später, starte den Server danach neu
(`docker compose restart beacon`). Die Spieler müssen dann das neue Passwort
eingeben. Beacon zeigt ihnen dabei „Server-Identität geändert“ an; sag ihnen
vorher Bescheid.

## 4. Karten

Jede Karte ist ein eigener Ordner unter `maps/`, genau wie im BFME-Kartenordner:

```
maps/
└── Helms Klamm 2v2/
    ├── Helms Klamm 2v2.map
    ├── Helms Klamm 2v2_art.tga
    └── map.str
```

* Deine eigenen BFME-Karten findest du unter Windows meist in
  `%APPDATA%\My Battle for Middle-earth Files\Maps`. Kopiere die Kartenordner zum
  Beispiel mit WinSCP oder `scp -r` nach `/opt/beacon/maps`.
* Neue Karten erkennt der Server nach spätestens 60 Sekunden
  (`map_rescan_secs`), sofort mit `docker compose kill -s HUP beacon`.
* Die Spieler laden die Karten in der Lobby mit „Karten synchronisieren“. Beacon
  prüft jede Datei mit einer Prüfsumme.
* Verteile nur Karten, die du weitergeben darfst, zum Beispiel selbst gebaute oder
  frei veröffentlichte. Die Original-Karten haben alle Spieler schon.

## 5. Starten und prüfen

```sh
cd /opt/beacon
docker compose up -d
docker compose ps                                # nach etwa 30 s: „healthy“
curl -s http://127.0.0.1:28087/health            # → ok
```

Gib deinen Mitspielern drei Dinge: die **Adresse** (siehe nächster Abschnitt), den
**Port** 28086 (nur nötig, wenn du ihn geändert hast) und das **Passwort**.

### Ports

| Port | Protokoll | Zweck | erreichbar für |
|---|---|---|---|
| 28086 | TCP | Anmeldung, Lobby, Chat, Karten (verschlüsselt) | Spieler |
| 28086 | UDP | Spieldaten (verschlüsselt) | Spieler |
| 28087 | TCP | Status und Healthcheck (`/health`, `/status`) | nur der Server selbst (`127.0.0.1`) |

Es ist **ein** Port für Spieler, aber **beide Protokolle** sind nötig: TCP für
Anmeldung und Lobby, UDP für das Spiel.

## 6. Erreichbarkeit

Deine Freunde müssen deinen Server über das Internet erreichen. Dafür gibt es zwei
Wege.

### Weg A: Portfreigabe im Router

1. Gib dem Server im Heimnetz eine **feste IP-Adresse** (im Router meist „immer
   dieselbe IP-Adresse zuweisen“).
2. Richte im Router eine **Portfreigabe** (auch „Portweiterleitung“) zum Server ein:
   * **TCP** 28086 → 28086
   * **UDP** 28086 → 28086
3. Deine öffentliche IP-Adresse ändert sich meist regelmäßig. Richte deshalb
   **dynamisches DNS (DynDNS)** ein (viele Router können das selbst) und gib den
   Spielern diesen Namen, zum Beispiel `mein-server.dyndns.org`.
4. Teste von außen, zum Beispiel vom Handy ohne WLAN oder mit einem Freund:
   `nc -vz <adresse> 28086` muss „succeeded“ melden.

Hat dein Anschluss **keine eigene öffentliche IPv4-Adresse** (oft „DS-Lite“ bei
Kabel- und Glasfaseranschlüssen), funktioniert die Portfreigabe über IPv4 nicht.
Nimm dann Weg B.

**Sicherheit:** Ohne Passwort kommt niemand über die Anmeldung hinaus. Nach
mehreren Fehlversuchen sperrt der Server die Adresse vorübergehend. Der
Status-Port 28087 ist nie von außen erreichbar.

### Weg B: VPN, zum Beispiel Tailscale

Mit einem VPN wie [Tailscale](https://tailscale.com) brauchst du keine
Portfreigabe. Der Server ist dann nur für die Leute im VPN erreichbar.

1. Installiere Tailscale auf dem Server.
2. Alle Mitspieler installieren Tailscale auf ihrem PC. Lade sie in dein Tailnet
   ein, oder gib den Server für sie frei (Tailscale-Verwaltung → *Machines* →
   Server → *Share*).
3. Adresse für die Spieler: die Tailscale-IP des Servers (`tailscale ip -4`,
   beginnt mit `100.`) oder sein MagicDNS-Name.
4. Optional lauscht der Server nur im VPN. Ersetze dazu in `compose.yaml` die
   Port-Zeilen (mit deiner Tailscale-IP):
   ```yaml
   ports:
     - "100.x.y.z:28086:28086/tcp"
     - "100.x.y.z:28086:28086/udp"
     - "127.0.0.1:28087:28087"
   ```
5. Prüfe mit `tailscale ping <gerät-eines-spielers>`, dass die Verbindung direkt
   läuft („via <IP>“) und nicht über ein DERP-Relay. Sonst steigt der Ping.

## 7. Status und Logs

```sh
curl -s http://127.0.0.1:28087/status | jq   # Spieler, Ping, Verlust, Zähler
docker compose logs -f beacon                # Anmeldungen, Fehler, Sperren
docker compose logs --since 1h beacon
```

Für mehr Details setze `log_level = "debug"` in `config.toml` und starte neu
(`docker compose restart beacon`). Docker begrenzt die Logs auf 3 × 10 MB.

## 8. Updates

```sh
cd /opt/beacon
docker compose pull
docker compose up -d
docker image prune -f        # alte Images entfernen
```

* Lies vorher das [Änderungsprotokoll](../../CHANGELOG.md). Neue Einstellungen
  haben Standardwerte; `config.toml` musst du nur anpassen, wenn das
  Änderungsprotokoll es sagt. Tippfehler in `config.toml` lehnt der Server beim
  Start mit einer Fehlermeldung ab.
* Server und `Beacon.exe` sollten zusammenpassen. Ist ein Spieler-Beacon zu alt,
  meldet der Server das beim Verbinden. Sag deinen Freunden, wenn sie
  aktualisieren sollen.
* Willst du selbst bestimmen, wann aktualisiert wird, trage in `compose.yaml` eine
  feste Version ein, zum Beispiel `ghcr.io/floderso/bfme-beacon-server:0.1.0`.
* Startet der Server neu, während gespielt wird, verbinden sich die Spieler von
  selbst neu. Besser ist ein Update zwischen zwei Spielen.

## 9. Sichern

Sichere regelmäßig:

* `config.toml` (Einstellungen und Passwort-Schlüssel; privat halten),
* `data/` (feste virtuelle IP-Adresse pro Spielername),
* `maps/`, wenn du die Karten nicht anderswo hast.

Zum Wiederherstellen legst du die Dateien zurück und startest mit
`docker compose up -d`. Weil Salt und Schlüssel gleich bleiben, merken die Spieler
davon nichts.

## 10. Benachrichtigungen (optional)

Der Server kann bei Ereignissen (`start`, `stop`, `join`, `leave`, `launch`,
`kick`) eine Nachricht schicken, zum Beispiel über [ntfy](https://ntfy.sh) aufs
Handy. Kommentiere dazu in `config.toml` den Abschnitt `[webhook]` ein. Der Server
sendet einen HTTP-POST mit dem Text als Inhalt und dem Header `Title`, also genau
das Format von ntfy. Nur `http://` wird unterstützt (kein TLS):

* ntfy läuft auf demselben Rechner: in `compose.yaml` `extra_hosts` einkommentieren
  und `url = "http://host.docker.internal:<ntfy-port>/<topic>"` verwenden.
* ntfy läuft in einem anderen Compose-Projekt: beide Container in ein gemeinsames
  Docker-Netz hängen und `url = "http://ntfy/<topic>"` verwenden.
* Zugriffsschutz: `token = "…"` wird als `Authorization: Bearer …` gesendet.

## Ohne Docker

Unter [Releases](https://github.com/Floderso/bfme-beacon/releases/latest) gibt es
den Server auch als einzelne Datei `beacon-server-<version>-linux-x86_64`
(statisch gelinkt, läuft auf jedem x86_64-Linux):

```sh
mv beacon-server-*-linux-x86_64 beacon-server && chmod +x beacon-server
./beacon-server init-config config.toml        # kommentierte Beispiel-Konfiguration
./beacon-server set-password --config config.toml
./beacon-server run --config config.toml
```

Ohne Docker lauscht der Status-Port standardmäßig nur auf `127.0.0.1`. Für den
Dauerbetrieb richtest du am besten einen systemd-Dienst ein. `SIGTERM` beendet den
Server sauber, `SIGHUP` liest die Karten neu ein.
