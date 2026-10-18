# BFME Beacon

**Mehrspieler für „Die Schlacht um Mittelerde“ (BFME1) über deinen eigenen Server.**

Beacon funktioniert wie ein Minecraft-Server: Einer von euch betreibt den Server,
alle anderen verbinden sich mit Adresse und Passwort. Danach spielt ihr ganz
normal über das Netzwerk-Menü von BFME, als wärt ihr alle im selben Raum.

*English summary: home-server multiplayer for The Battle for Middle-earth (2004).
A Windows launcher and a small hook DLL put every player on one virtual LAN that a
password-protected Linux server relays. Developer documentation (English):
[docs/dev/](docs/dev/).*

> **Stand: frühe Version (0.1.0).** Beacon läuft, ist aber noch jung und bisher nur
> im kleinen Kreis getestet. Rückmeldungen und Fehlerberichte sind willkommen.

<!-- Screenshots: Verbinden-Seite und Lobby (z. B. docs/bilder/verbinden.png,
     docs/bilder/lobby.png) hier einfügen. -->
*Screenshots folgen.*

## Download

Die aktuelle Version gibt es unter
**[Releases](https://github.com/Floderso/bfme-beacon/releases/latest)**:

| Datei | Für wen |
|---|---|
| `Beacon-<version>-windows.zip` | Spieler (Windows): `Beacon.exe` und `wsock32.dll` |
| `beacon-server-<version>-linux-x86_64` | Server ohne Docker (Linux, 64-Bit) |
| `SHA256SUMS` | Prüfsummen aller Dateien |

Den Server gibt es außerdem als Docker-Image:
`ghcr.io/floderso/bfme-beacon-server:<version>` (oder `:latest`).

## Schnellstart für Spieler

Du brauchst BFME1, installiert über den BFME All-in-One-Launcher (Patch 1.06), und
vom Betreiber des Servers die Adresse und das Passwort.

1. **Herunterladen und entpacken:** `Beacon-<version>-windows.zip` laden und an
   einen Ort deiner Wahl entpacken, zum Beispiel nach `C:\Spiele`.
2. **Beacon starten:** `Beacon.exe` doppelklicken. Dein Browser öffnet die
   Beacon-Seite. Server-Adresse, deinen Namen und das Passwort eingeben, dann
   „Verbinden“.
3. **Spielen:** In der Lobby startet der Host alle mit „Alle starten“ (oder du
   klickst „BFME starten“). In BFME gehst du auf *Mehrspieler → Netzwerk* und
   trittst dem Spiel bei.

Ausführlich: [Anleitung für Spieler](docs/anleitung/spielen.md) ·
[Hilfe bei Problemen](docs/anleitung/fehlerbehebung.md)

## Eigenen Server betreiben

Der Server läuft auf einem Linux-Rechner mit Docker und braucht einen Port
(28086, TCP und UDP). Alles Weitere: [Anleitung für den Server](docs/anleitung/server.md).

## So funktioniert es

* `Beacon.exe` verbindet sich verschlüsselt mit dem Server und zeigt die Lobby im
  Browser (nur auf deinem PC erreichbar).
* Vor dem Spielstart legt Beacon die Datei `wsock32.dll` in den BFME-Ordner. Sie
  leitet den Netzwerkverkehr von BFME an Beacon weiter. Ohne Beacon tut sie
  nichts; die `lotrbfme.exe` wird nie verändert.
* Der Server reicht die Spielpakete zwischen allen Spielern weiter. Für BFME
  sieht das aus wie ein gemeinsames Heimnetz (virtuelles LAN `198.18.0.0/24`).

## Stand und Einschränkungen

* Nur BFME1 (nicht BFME2 oder „Der Aufstieg des Hexenkönigs“), Version 1.03 mit
  Patch 1.06 aus dem All-in-One-Launcher. Alle Spieler brauchen dieselben
  Spieldaten; Beacon zeigt Unterschiede in der Lobby an.
* Spieler: Windows 10 oder 11 (64-Bit). Server: Linux (x86_64), am einfachsten mit
  Docker.
* `Beacon.exe` und `wsock32.dll` sind noch nicht digital signiert. Windows warnt
  deshalb (SmartScreen), und Smart App Control kann sie blockieren. Eine
  Signatur ist geplant; siehe [Hilfe bei Problemen](docs/anleitung/fehlerbehebung.md).
* Die Spieloptimierungen von Open-BFME (z. B. weniger Verzögerung) sind noch nicht
  eingebaut.

## Für Entwickler

* [docs/dev/building.md](docs/dev/building.md): Toolchains, Bauen, Tests
* [docs/dev/architecture.md](docs/dev/architecture.md): Architektur und Protokolle
* Crates: [beacon-proto](crates/beacon-proto/README.md),
  [beacon-server](crates/beacon-server/README.md),
  [beacon-launcher](crates/beacon-launcher/README.md),
  [beacon-hook](crates/beacon-hook/README.md)
* Änderungen: [CHANGELOG.md](CHANGELOG.md)

## Danksagung

* [Open-BFME](https://github.com/Open-BFME/Open-BFME-1) (GPL-3.0): Ohne die
  Rekonstruktion der BFME1-Engine durch Open-BFME gäbe es Beacon nicht. Das
  Patch-Bündel in [patches/](patches/README.md) stammt aus Open-BFME.

## Lizenz und Hinweise

BFME Beacon ist freie Software unter der
[GNU General Public License, Version 3 oder neuer](LICENSE) (GPL-3.0-or-later).
Weitere Hinweise: [NOTICE](NOTICE).

„The Battle for Middle-earth“ („Die Schlacht um Mittelerde“) ist eine Marke der
jeweiligen Rechteinhaber. Beacon ist ein inoffizielles Fan-Projekt und steht in
keiner Verbindung zu Electronic Arts. **Beacon enthält und verteilt keine
Spieldateien**; jeder Spieler braucht seine eigene Installation.
