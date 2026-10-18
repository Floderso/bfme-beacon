# Änderungsprotokoll

Alle wichtigen Änderungen an BFME Beacon. Das Format folgt
[Keep a Changelog](https://keepachangelog.com/de/1.1.0/), die Versionsnummern
folgen [Semantic Versioning](https://semver.org/lang/de/).

## [Unveröffentlicht]

### Neu

* **Spielversion / Mod für die ganze Lobby:** Der Host wählt eine Version aus der
  Bibliothek des BFME-Workshop-Launchers (zum Beispiel Patch 2.22 oder Legends of
  the 3rd Age mit Patch 1.06) und eine Sprachvariante. Jedes Beacon bereitet
  genau diese Dateien vor (aus dem Zwischenspeicher des Workshop-Launchers, dem
  BFME-Ordner oder selbst gewählten Ordnern, jede Datei per MD5 geprüft) und
  startet BFME aus einem eigenen Instanzordner mit harten Verknüpfungen. Die
  eigene BFME-Installation bleibt unverändert; ohne Auswahl gilt Vanilla wie
  bisher. Die Lobby zeigt pro Spieler, ob er bereit ist; „Alle starten“ wartet,
  bis alle bereit sind. Speicherort, Import-Ordner und „Aufräumen“ in den
  Einstellungen; `Beacon.exe mods list|prepare` für die Kommandozeile.
* **beacon-server:** nimmt die Spielversion des Hosts an, prüft sie, verteilt
  sie an alle und lässt „Alle starten“ erst zu, wenn alle bereit sind.
* Download fehlender Dateien aus dem BFME Workshop ist eingebaut, aber
  abgeschaltet, bis das BFME-Foundation-Team zustimmt.

## [0.1.0] - 2026-10-18

Erste öffentliche Version.

### Neu

* **Beacon.exe** (Spieler, Windows): Bedienung im Browser (deutsch) mit Symbol im
  Infobereich; Anmeldung mit Server-Adresse, Name und Passwort („Passwort merken“
  speichert nur einen verschlüsselten Schlüssel); Warnung bei geänderter
  Server-Identität; Lobby mit Ping, Paketverlust, Bereit-Status, Chat und
  Kartenpool; Abgleich der Spieldaten mit dem Host; Karten-Download vom Server;
  Start von BFME mit Fenstermodus und Auflösung; „Alle starten“ für den Host;
  BFME-LAN-Name wird übernommen und lässt sich wiederherstellen; automatische
  Wiederverbindung, auch während eines Spiels.
* **wsock32.dll** (32-Bit, im BFME-Ordner): leitet den LAN-Verkehr von BFME an
  Beacon weiter (virtuelles LAN `198.18.0.0/24`); ohne Beacon ohne Wirkung;
  beantwortet die Firewall-Abfrage von BFME selbst; Testmodus für zwei
  BFME-Instanzen auf einem PC.
* **beacon-server** (Linux, Docker): ein Port (28086, TCP und UDP); Passwort mit
  Argon2id und Noise-Verschlüsselung; verschlüsseltes Relay mit mehrfach
  gesendeten Paketen gegen Paketverlust; Lobby mit Host-Rolle, Chat, Kick und
  „Alle starten“; Kartenverzeichnis mit Prüfsummen; feste virtuelle IP pro
  Spielername; Status-Endpunkt; Schutz gegen Fehlversuche und Überlast;
  optionale Benachrichtigungen (ntfy).
* Anleitungen auf Deutsch für Spieler und Server-Betreiber, Entwicklerdoku auf
  Englisch.
* Automatische Builds: Windows-Paket, statischer Linux-Server,
  Docker-Image `ghcr.io/floderso/bfme-beacon-server`, Prüfsummen.

### Bekannte Einschränkungen

* `Beacon.exe` und `wsock32.dll` sind nicht digital signiert: SmartScreen warnt,
  Smart App Control kann sie blockieren.
* Nur BFME1 1.03 mit Patch 1.06 (All-in-One-Launcher).
* Die Spieloptimierungen von Open-BFME sind noch nicht eingebaut.
* Das Docker-Image gibt es nur für x86_64.

[0.1.0]: https://github.com/Floderso/bfme-beacon/releases/tag/v0.1.0
