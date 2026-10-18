# Hilfe bei Problemen

Die meisten Meldungen in Beacon erklären sich selbst. Hier findest du mehr Hilfe zu
den häufigsten Problemen. Die Anleitung zum Spielen steht in [spielen.md](spielen.md).

* [Windows blockiert Beacon.exe](#windows-blockiert-beaconexe)
* [Firewall](#firewall)
* [Server nicht erreichbar](#server-nicht-erreichbar)
* [Falsches Passwort](#falsches-passwort)
* [Server-Identität geändert](#server-identität-geändert)
* [Fremde wsock32.dll im Spielordner](#fremde-wsock32dll-im-spielordner)
* [Spiel nicht gefunden](#spiel-nicht-gefunden)
* [BFME startet nicht](#bfme-startet-nicht)
* [Ruckeln und Verbindungsabbrüche](#ruckeln-und-verbindungsabbrüche)
* [Andere Spieldaten („weicht ab“)](#andere-spieldaten-weicht-ab)
* [Wo finde ich die Logs?](#wo-finde-ich-die-logs)

## Windows blockiert Beacon.exe

**Warum passiert das?** Beacon ist ein neues Programm und noch nicht digital
signiert. Windows kennt es deshalb noch nicht und ist vorsichtig. Das ist kein
Virenfund. Lade Beacon trotzdem nur von der offiziellen Seite herunter:
<https://github.com/Floderso/bfme-beacon/releases>.

### SmartScreen: „Der Computer wurde durch Windows geschützt“

Diese Meldung kommt beim ersten Start einer heruntergeladenen Datei, die Windows
noch nicht kennt.

1. Klicke auf **„Weitere Informationen“**.
2. Klicke auf **„Trotzdem ausführen“**.

Danach fragt Windows für diese Datei nicht mehr.

### Smart App Control

Smart App Control ist eine Schutzfunktion von Windows 11. Sie lässt nur Programme
starten, die Microsoft als vertrauenswürdig kennt oder die digital signiert sind.
Ein neues, unsigniertes Programm wie Beacon kann sie blockieren. Anders als bei
SmartScreen gibt es dann **keinen „Trotzdem ausführen“-Knopf und keine Ausnahme
für einzelne Programme**.

So merkst du es:

* Windows meldet beim Start von `Beacon.exe`, dass Smart App Control die App
  blockiert hat, oder
* Beacon meldet: „Smart App Control hat den Start von BFME blockiert.“ Dann hat
  Windows die `wsock32.dll` im BFME-Ordner blockiert.

So prüfst du, ob Smart App Control an ist: **Windows-Sicherheit → App- &
Browsersteuerung → Smart App Control**. Dort steht „Ein“, „Auswertung“ oder „Aus“.

Was du tun kannst:

* **Auf die signierte Version warten.** Wir wollen Beacon digital signieren lassen
  (für Open-Source-Projekte gibt es das kostenlos). Signierte Programme lässt
  Smart App Control normalerweise zu.
* **Auf einem anderen PC spielen**, auf dem Smart App Control aus ist.
* **Smart App Control nicht einfach ausschalten.** Es schützt dich vor
  Schadsoftware. Wichtig: Je nach Windows-Version lässt es sich danach nur durch
  eine Neuinstallation von Windows wieder einschalten. Überlege dir das gut; wir
  empfehlen es nicht.

**BFME startet gar nicht mehr, auch ohne Beacon?** Wenn Smart App Control die
`wsock32.dll` blockiert, startet BFME nicht, solange sie im BFME-Ordner liegt.
Lösche dann die `wsock32.dll` im BFME-Ordner (dort, wo `lotrbfme.exe` liegt).
Danach startet BFME wieder wie vorher.

### Virenscanner meldet Beacon

Manche Virenscanner sind bei neuen, unsignierten Programmen misstrauisch, besonders
bei einer DLL, die Netzwerkfunktionen umleitet. Prüfe, dass du Beacon von der
offiziellen Seite hast. Du kannst die Datei dem Hersteller deines Virenscanners
als Fehlalarm melden. Der Quellcode von Beacon ist öffentlich.

## Firewall

**Du musst nichts in der Firewall freigeben**, und du brauchst keine
Administratorrechte.

* BFME prüft beim Klick auf „Mehrspieler“ die Windows-Firewall und bleibt ohne
  Administratorrechte sonst hängen. Beacon beantwortet diese Abfrage automatisch.
  Deine Windows-Einstellungen bleiben dabei unverändert.
* BFME spricht nur mit Beacon auf deinem eigenen PC. Beacon baut nur ausgehende
  Verbindungen zum Server auf.

Fragt Windows trotzdem, ob BFME oder Beacon im Netzwerk kommunizieren darf, spielt
deine Antwort für Beacon keine Rolle.

## Server nicht erreichbar

Beacon meldet zum Beispiel „Server nicht erreichbar“ oder „Unter dieser Adresse
antwortet kein Beacon-Server“. Prüfe der Reihe nach:

1. **Adresse und Port richtig?** Vertipper sind der häufigste Grund. Ohne Port
   nimmt Beacon 28086.
2. **Läuft der Server?** Frag den Betreiber.
3. **Funktioniert dein Internet?**
4. **Läuft der Server über ein VPN** (zum Beispiel Tailscale)? Dann muss das VPN
   auch auf deinem PC eingeschaltet sein.
5. Der Betreiber muss den Port **28086 für TCP und UDP** freigeben
   (siehe [Anleitung für den Server](server.md#6-erreichbarkeit)).

**Verbunden, aber kein Ping oder 100 % Verlust?** Dann kommt TCP durch, aber UDP
nicht. Der Betreiber muss den Port auch für **UDP** freigeben.

## Falsches Passwort

* Achte auf Groß- und Kleinschreibung.
* Nach mehreren Fehlversuchen sperrt der Server deine Internet-Adresse für kurze
  Zeit (ab einer Minute, bei weiteren Fehlversuchen länger). Warte und versuche
  es dann noch einmal.
* Hat der Betreiber das Passwort geändert, passt dein gemerktes Passwort nicht
  mehr. Gib das neue Passwort ein. Unter „Zuletzt benutzte Server“ kannst du ein
  gemerktes Passwort auch mit **„Passwort vergessen“** löschen.

## Server-Identität geändert

Beim ersten Verbinden merkt sich Beacon die Identität des Servers. Ändert sie sich
später, stoppt Beacon die Anmeldung, **bevor** es dein Passwort benutzt.

Das passiert, wenn der Betreiber das Passwort geändert oder den Server neu
eingerichtet hat. Es kann aber auch heißen, dass sich jemand als dieser Server
ausgibt.

1. **Frag den Betreiber**, ob er etwas geändert hat.
2. Nur wenn die Änderung gewollt war: Klicke auf **„Identität zurücksetzen“** und
   verbinde dich mit dem (neuen) Passwort.

## Fremde wsock32.dll im Spielordner

Beacon meldet, dass im BFME-Ordner schon eine fremde `wsock32.dll` liegt. Sie
stammt von einem anderen Tool oder Mod. Beacon überschreibt sie nicht.

* Benenne die fremde Datei um (zum Beispiel in `wsock32.dll.alt`) und starte BFME
  noch einmal über Beacon.
* Das andere Tool funktioniert dann vielleicht nicht mehr. Brauchst du es wieder,
  lösche Beacons `wsock32.dll` und gib der alten Datei ihren Namen zurück.

## Spiel nicht gefunden

Beacon sucht BFME über die Angaben, die der Installer in Windows hinterlegt hat.
Hast du BFME kopiert oder verschoben, findet Beacon es vielleicht nicht.

1. Öffne **„Einstellungen“**.
2. Trage bei **„Eigener Spielordner“** den Ordner ein, in dem `lotrbfme.exe` liegt.
3. Klicke auf **„Speichern“**.

Unter **„Diagnose“** siehst du, welchen Ordner und welche Spielversion Beacon
erkannt hat. Warnt Beacon vor einer unbekannten Version, ist deine `lotrbfme.exe`
nicht die Version aus dem All-in-One-Launcher.

## BFME startet nicht

* **„Als Administrator ausführen“** ist für `lotrbfme.exe` eingestellt: Rechtsklick
  auf `lotrbfme.exe` → „Eigenschaften“ → „Kompatibilität“ → Haken entfernen.
  Beacon kann das Spiel sonst nicht starten.
* **Smart App Control** hat blockiert: siehe [oben](#smart-app-control).
* **BFME läuft schon:** Beende es zuerst.

## Ruckeln und Verbindungsabbrüche

* **Nimm ein LAN-Kabel statt WLAN**, am besten bei allen Spielern und vor allem
  beim Server. Jedes Spielpaket läuft über den Server. Schwankungen im WLAN spüren
  deshalb alle.
* Schau in der Lobby auf **Ping** und **Verlust**. Hohe Werte bei einem Spieler
  bremsen meist das ganze Spiel.
* Beende große Downloads, Streams oder Cloud-Uploads während des Spiels.
* Läuft der Server über ein VPN wie Tailscale: Die Verbindung sollte direkt sein.
  Läuft sie über einen Umweg (bei Tailscale „DERP“), steigt der Ping.
* Kurze Abbrüche fängt Beacon ab und verbindet sich selbst neu. Startet der
  Betreiber den Server neu, verbindet sich Beacon danach von allein.

## Andere Spieldaten („weicht ab“)

BFME lässt dich nur beitreten, wenn alle Spieler genau dieselben Spieldateien
haben. Beacon vergleicht deine Dateien vor dem Spiel mit denen des Hosts und zeigt
„✓ wie Host“ oder „✗ weicht ab“. Ein Klick zeigt dir, welche Dateien sich
unterscheiden.

Häufige Gründe:

* ein anderer Patch-Stand (nicht 1.06),
* ein Mod oder geänderte Dateien im BFME-Ordner (zum Beispiel im Ordner `Data`),
* eine andere Spielversion.

Gleiche deinen Stand an den des Hosts an, zum Beispiel über den
All-in-One-Launcher.

## Wo finde ich die Logs?

* In Beacon: **„Diagnose“ → „Log-Ordner öffnen“**.
* Oder direkt: `%APPDATA%\Beacon\logs` (Windows-Taste + R, eingeben, Enter).

Dort liegen `beacon-….log` (Beacon selbst) und `hook-….log` (der Netzwerkteil in
BFME). Beacon behält jeweils die zehn neuesten.

Wenn du Hilfe brauchst, schick dem Betreiber die neueste `beacon-….log` und
`hook-….log`. Sie enthalten unter anderem die Server-Adresse und Spielernamen,
aber kein Passwort.
