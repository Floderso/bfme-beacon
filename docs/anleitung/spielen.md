# BFME mit Beacon spielen

Diese Anleitung ist für Spieler. Du brauchst etwa zehn Minuten. Wenn etwas nicht
klappt, schau in die [Hilfe bei Problemen](fehlerbehebung.md).

## Was du brauchst

* Einen PC mit **Windows 10 oder 11** (64-Bit).
* **„Die Schlacht um Mittelerde“ (BFME1)**, installiert über den
  **BFME All-in-One-Launcher**, mit **Patch 1.06**. Alle Mitspieler brauchen
  genau denselben Stand. Mods nur, wenn alle dieselben haben.
* Vom Betreiber des Servers: die **Server-Adresse** (zum Beispiel
  `mein-server.de` oder `203.0.113.5:28086`) und das **Passwort**.

## 1. Herunterladen und entpacken

1. Öffne die Seite
   [Releases](https://github.com/Floderso/bfme-beacon/releases/latest) und lade
   `Beacon-<version>-windows.zip` herunter.
   Warnt dein Browser, dass die Datei selten heruntergeladen wird? Dann wähle
   „Beibehalten“. Beacon ist neu, deshalb kennt der Browser die Datei noch nicht.
2. Klicke mit der rechten Maustaste auf die ZIP-Datei und wähle
   **„Alle extrahieren …“**.
3. Wähle als Ziel einen Ordner deiner Wahl, zum Beispiel `C:\Spiele`.
   Danach gibt es den Ordner `C:\Spiele\Beacon` mit diesen Dateien:
   * `Beacon.exe` – das Programm
   * `wsock32.dll` – die Netzwerk-Erweiterung für BFME
   * `LIESMICH.txt` und `LICENSE.txt`

`Beacon.exe` und `wsock32.dll` müssen im selben Ordner bleiben. Entpacke Beacon
nicht direkt in den BFME-Ordner.

## 2. Beacon starten

Doppelklicke `Beacon.exe`.

* Beim ersten Start zeigt Windows vielleicht **„Der Computer wurde durch Windows
  geschützt“**. Klicke auf **„Weitere Informationen“** und dann auf
  **„Trotzdem ausführen“**. Mehr dazu (auch zu Smart App Control) steht in der
  [Hilfe bei Problemen](fehlerbehebung.md#windows-blockiert-beaconexe).
* Dein Browser öffnet die **Beacon-Seite**. Sie läuft nur auf deinem PC.
* Beacon läuft im Hintergrund weiter, auch wenn du den Browser schließt. Du
  findest es im **Infobereich** der Taskleiste (unten rechts, ein kleines
  Leuchtfeuer). Klick darauf öffnet die Seite wieder, Rechtsklick → „Beenden“
  beendet Beacon.

## 3. Mit dem Server verbinden

Auf der Seite **„Verbinden“**:

1. **Server-Adresse** eingeben. Ohne Port nimmt Beacon automatisch 28086.
2. **Spielername** eingeben (höchstens 12 Zeichen). So heißt du auch in BFME.
3. **Passwort** eingeben.
4. Wenn du willst: **„Passwort merken“** anhaken. Beacon speichert dann nicht dein
   Passwort, sondern einen daraus berechneten Schlüssel, verschlüsselt für dein
   Windows-Konto. Beim nächsten Mal musst du nichts mehr eingeben.
5. Auf **„Verbinden“** klicken.

Beim ersten Verbinden merkt sich Beacon die Identität des Servers. Ändert sie sich
später, warnt Beacon dich, bevor es dein Passwort benutzt
(siehe [„Server-Identität geändert“](fehlerbehebung.md#server-identität-geändert)).

## 4. In der Lobby

Nach dem Verbinden siehst du die **Lobby**:

* **Spieler** mit Ping und Paketverlust. Der Host hat eine Krone.
* **Spieldaten:** „✓ wie Host“ heißt, deine Spieldateien passen. Bei
  „✗ weicht ab“ lässt BFME dich nicht beitreten
  (siehe [Andere Spieldaten](fehlerbehebung.md#andere-spieldaten-weicht-ab)).
* **Chat** und **Kartenpool:** Mit **„Karten synchronisieren“** lädt Beacon die
  Karten des Servers in deinen BFME-Kartenordner.
* **„Bereit“** zeigt den anderen, dass du startklar bist.

## 5. Spiel starten

1. Der Host klickt **„Alle starten“**. BFME startet dann bei allen, die
   „Automatisch starten, wenn der Host startet“ eingeschaltet haben (Standard).
   Du kannst BFME auch selbst mit **„BFME starten“** öffnen.
2. In BFME gehst du auf **Mehrspieler → Netzwerk** (englische Version:
   *Multiplayer → Network*).
3. Einer erstellt dort ein Spiel, meistens der Host. Alle anderen treten bei.
   Ab hier spielt ihr ganz normal.

Wichtig:

* **Starte BFME immer über Beacon.** Startest du BFME über den Desktop oder den
  All-in-One-Launcher, sieht es die anderen Beacon-Spieler nicht.
* **Lass Beacon während des Spiels laufen.** Beendest du Beacon, verlierst du die
  Verbindung zum Spiel.

## Einstellungen

Unter **„Einstellungen“** kannst du unter anderem festlegen:

* Fenstermodus und Auflösung
* „Shellmap aus“: überspringt das animierte Hauptmenü, BFME startet schneller
* „Name ins Spiel übernehmen“ (siehe unten)
* „Automatisch starten, wenn der Host startet“
* „Eigener Spielordner“, falls Beacon BFME nicht selbst findet

## Was Beacon an deinem PC ändert

Beacon wird nicht installiert. Es legt keine Dienste, keinen Autostart und keine
Registry-Einträge an. Diese Dinge ändert es:

### Die Datei `wsock32.dll` im BFME-Ordner

Vor jedem Spielstart kopiert Beacon seine `wsock32.dll` in den BFME-Ordner (dort,
wo `lotrbfme.exe` liegt), falls sie fehlt oder veraltet ist. Sie leitet den
Netzwerkverkehr von BFME an Beacon weiter.

* **Ohne Beacon tut sie nichts.** Startest du BFME ohne Beacon, gibt sie alles
  unverändert an Windows weiter. BFME verhält sich dann wie vorher.
* Die `lotrbfme.exe` verändert Beacon nie.
* Liegt dort schon eine fremde `wsock32.dll` (von einem anderen Tool), überschreibt
  Beacon sie nicht.

**Entfernen:** BFME und Beacon beenden, dann `wsock32.dll` im BFME-Ordner löschen.
Lösche nur diese eine Datei im BFME-Ordner. Die `wsock32.dll` von Windows liegt
woanders (`C:\Windows\SysWOW64`) und bleibt unberührt.

### Dein LAN-Name in BFME (`Network.ini`)

Ist „Name ins Spiel übernehmen“ eingeschaltet (Standard), setzt Beacon vor jedem
Start deinen BFME-LAN-Namen auf deinen Beacon-Namen. Dazu ändert es die Datei
`Network.ini` in deinem BFME-Benutzerordner (meist
`%APPDATA%\My Battle for Middle-earth Files`; der genaue Ort steht unter
„Diagnose“). Den alten Namen sichert Beacon beim ersten Mal.

**Zurücksetzen:** „Einstellungen“ → **„Ursprünglichen Namen wiederherstellen“**.

### Karten

„Karten synchronisieren“ speichert die Karten des Servers in deinem
BFME-Kartenordner. Beacon notiert sie in der Datei `beacon-maps.json` im selben
Ordner. Deine eigenen Karten überschreibt Beacon nie.

### Der Datenordner `%APPDATA%\Beacon`

Hier speichert Beacon deine Einstellungen (`config.json`), die gemerkten Server und
Schlüssel, den gesicherten LAN-Namen und die Logs (`logs\`). Du öffnest ihn mit
`Windows-Taste + R`, dann `%APPDATA%\Beacon` eingeben und Enter drücken.

## Beacon aktualisieren

1. Beacon beenden (Infobereich → Rechtsklick → „Beenden“).
2. Die neue ZIP-Datei herunterladen und wie oben entpacken. Die alten Dateien
   darfst du überschreiben.
3. Beacon starten. Deine Einstellungen bleiben erhalten. Die neue `wsock32.dll`
   kopiert Beacon beim nächsten Spielstart selbst in den BFME-Ordner.

Spielt alle mit derselben Beacon-Version. Ist deine zu alt, sagt dir das der
Server beim Verbinden.

## Beacon vollständig entfernen

1. „Einstellungen“ → **„Ursprünglichen Namen wiederherstellen“**.
2. Beacon beenden.
3. `wsock32.dll` im BFME-Ordner löschen.
4. Den Ordner `%APPDATA%\Beacon` löschen.
5. Den Beacon-Ordner (mit `Beacon.exe`) löschen.

Heruntergeladene Karten bleiben im BFME-Kartenordner. Welche es sind, steht in
`beacon-maps.json`.
