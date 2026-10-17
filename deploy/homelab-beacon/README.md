# BFME Beacon auf dem Homelab-Server

`beacon-server` ist der Lobby- und Relay-Server von BFME Beacon: Spieler melden
sich mit `Beacon.exe` an, sehen sich in der Lobby und spielen BFME über das
„LAN“-Menü, als säßen alle im selben Netz. Der Server braucht **einen** Port
(Standard **28086**) für **TCP und UDP**.

| Port | Protokoll | Zweck | erreichbar |
|---|---|---|---|
| 28086 | TCP | Anmeldung, Lobby, Chat, Karten-Downloads (verschlüsselt) | Spieler |
| 28086 | UDP | Spieldaten-Relay (verschlüsselt) | Spieler |
| 28087 | TCP | `/health`, `/status` (JSON) | nur `127.0.0.1` des Hosts |

## 1. Installation

Auf dem Entwicklungs-PC das statische Linux-Binary bauen (Repo-Wurzel):

```sh
cargo build -p beacon-server --release --target x86_64-unknown-linux-musl
```

Auf dem Server den Ordner anlegen und die Dateien hineinkopieren:

```sh
sudo mkdir -p /srv/docker/beacon && sudo chown "$USER": /srv/docker/beacon
cd /srv/docker/beacon
mkdir -p maps data
sudo chown 1000:1001 data          # der Container läuft als 1000:1001
```

| Datei im Repo | Ziel auf dem Server |
|---|---|
| `deploy/Dockerfile` | `/srv/docker/beacon/Dockerfile` |
| `deploy/homelab-beacon/compose.yaml` | `/srv/docker/beacon/compose.yaml` |
| `deploy/homelab-beacon/config.toml` | `/srv/docker/beacon/config.toml` |
| `deploy/homelab-beacon/.dockerignore` | `/srv/docker/beacon/.dockerignore` |
| `…/x86_64-unknown-linux-musl/release/beacon-server` | `/srv/docker/beacon/beacon-server` |

```sh
chmod 755 beacon-server
chmod 600 config.toml   # enthält nach dem Passwort-Setzen den Zugangsschlüssel
```

Hat dein Benutzer nicht die UID 1000, muss der Container die Datei trotzdem
lesen können: `sudo chown 1000:1001 config.toml`. `set-password` (Abschnitt 2)
dann mit `sudo` aufrufen (`… | sudo ./beacon-server set-password …`); Besitzer
und Rechte der Datei bleiben dabei erhalten.

In `config.toml` mindestens `server_name` und `motd` anpassen, optional
`admin_names` (diese Spieler sind immer Host).

## 2. Passwort setzen

Alle Spieler melden sich mit demselben Server-Passwort an. Gespeichert werden
nur ein zufälliges Salt und der daraus abgeleitete Schlüssel (Argon2id), nie
das Passwort selbst. Mindestens 8 Zeichen; lieber 12 oder mehr.

```sh
cd /srv/docker/beacon
# Eingabe ohne Bildschirmausgabe:
read -rs -p "Server-Passwort: " PW && echo && \
  printf '%s\n' "$PW" | ./beacon-server set-password --config config.toml --password-stdin
unset PW
```

(Einfacher, aber mit sichtbarer Eingabe: `./beacon-server set-password --config config.toml`.)

Nur `salt` und `psk` werden in `config.toml` ersetzt, Kommentare bleiben
erhalten. Danach `docker compose restart beacon` – angemeldete Spieler müssen
sich mit dem neuen Passwort neu verbinden.

## 3. Karten

Jede Karte ist ein Ordner unter `maps/`, genau wie im BFME-Ordner `Maps`:

```
maps/
└── Helms Klamm 2v2/
    ├── Helms Klamm 2v2.map
    ├── Helms Klamm 2v2_art.tga
    └── map.str
```

Beacon kündigt jede Datei mit Größe und BLAKE3-Prüfsumme an; die Launcher laden
fehlende Karten herunter und prüfen sie. Neue Karten werden spätestens nach
`map_rescan_secs` (Standard 60 s) erkannt, sofort mit
`docker compose kill -s HUP beacon`.

## 4. Starten und prüfen

```sh
cd /srv/docker/beacon
docker compose up -d --build
docker compose ps                                  # Status „healthy“ nach ~10 s
curl -s http://127.0.0.1:28087/health              # → ok
curl -s http://127.0.0.1:28087/status | jq         # Spieler, Ping, Verlust, Zähler
```

Die Spieler brauchen: **Adresse** (siehe unten), **Port** 28086 und das **Passwort**.

Für flüssiges Spielen sollte der Server per LAN-Kabel angeschlossen sein:
WLAN-Schwankungen (Jitter) spüren alle Spieler, weil jedes Spielpaket über den
Server läuft.

## 5. Erreichbarkeit

### Variante A: Portfreigabe am Speedport (öffentlich)

1. Dem Server im Heimnetz eine feste IP geben (Speedport: *Heimnetz* →
   Gerät auswählen → „Immer dieselbe IPv4-Adresse zuweisen“).
2. *Internet* → *Portfreischaltung* (je nach Modell „Port-Umleitungen und
   Port-Weiterleitungen“) → neue Regel für den Homelab-Server:
   - **TCP** 28086 → 28086
   - **UDP** 28086 → 28086

   Beide Protokolle sind nötig: TCP für Anmeldung und Lobby, UDP für das Spiel.
3. Die öffentliche IPv4 wechselt meist täglich: im Speedport unter *Internet* →
   *Dynamisches DNS* einen DynDNS-Namen einrichten und diesen den Spielern geben.
4. Test von außen (z. B. Handy ohne WLAN): `nc -vz <adresse> 28086` muss
   „succeeded“ melden.

Hat der Anschluss keine eigene öffentliche IPv4 (DS-Lite), funktioniert die
Portfreigabe über IPv4 nicht; dann ist Variante B (Tailscale) der einfachste Weg.

Sicherheit: ohne Passwort kommt niemand über den Handshake hinaus; wiederholte
Fehlversuche sperren die IP vorübergehend (`[limits]`). Der Status-Port 28087
bleibt immer lokal.

### Variante B: Tailscale (keine Portfreigabe)

Wenn der Server nicht öffentlich erreichbar sein soll:

1. Die Mitspieler installieren Tailscale; den Server per *Machine sharing*
   (Tailscale-Admin-Konsole → Machines → Server → *Share*) für sie freigeben
   oder sie ins eigene Tailnet einladen.
2. Adresse für die Spieler: die Tailscale-IP des Servers (`tailscale ip -4`,
   `100.x.y.z`) oder sein MagicDNS-Name.
3. Optional nur über Tailscale lauschen – in `compose.yaml`:
   ```yaml
   ports:
     - "100.x.y.z:28086:28086/tcp"
     - "100.x.y.z:28086:28086/udp"
     - "127.0.0.1:28087:28087"
   ```
4. Mit `tailscale ping <spieler-gerät>` prüfen, dass die Verbindung direkt ist
   („via <IP>“) und nicht über ein DERP-Relay läuft – sonst steigt der Ping.

## 6. Logs

```sh
docker compose logs -f beacon          # Anmeldungen, Fehler, Sperren
docker compose logs --since 1h beacon
```

Ausführlicher: `log_level = "debug"` in `config.toml` und
`docker compose restart beacon`. Die Logs sind auf 3 × 10 MB begrenzt.

## 7. Update

```sh
# Entwicklungs-PC: neues Binary bauen (siehe 1.) und nach /srv/docker/beacon kopieren
cd /srv/docker/beacon
docker compose up -d --build
docker image prune -f                   # alte Images entfernen
```

Neue Konfigurationsschlüssel haben Standardwerte; `config.toml` muss nur
angepasst werden, wenn das Änderungsprotokoll es verlangt. Unbekannte Schlüssel
(Tippfehler) lehnt der Server beim Start mit einer Fehlermeldung ab.

## 8. Benachrichtigungen (optional, ntfy)

In `config.toml` den Abschnitt `[webhook]` einkommentieren. Der Server sendet bei
den gewählten Ereignissen (`start`, `stop`, `join`, `leave`, `launch`, `kick`)
einen HTTP-POST mit dem Text als Inhalt und dem Header `Title`, also genau das
Format von ntfy. Nur `http://` wird unterstützt (kein TLS):

- ntfy läuft auf dem Host: in `compose.yaml` `extra_hosts` einkommentieren und
  `url = "http://host.docker.internal:<ntfy-port>/<topic>"` verwenden (ntfy muss
  dafür nicht nur auf 127.0.0.1 lauschen).
- ntfy läuft in einem anderen Compose-Projekt: beide Container in ein gemeinsames
  Docker-Netz hängen und `url = "http://ntfy/<topic>"` verwenden.
- Zugriffsschutz: `token = "tk_…"` wird als `Authorization: Bearer …` gesendet.

## 9. Sichern

`config.toml` (Passwort-Schlüssel, Einstellungen) und `data/` (feste virtuelle IPs
pro Spielername) sichern; `maps/` nach Bedarf.
