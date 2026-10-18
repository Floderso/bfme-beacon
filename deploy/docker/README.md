# Beispiel für einen Docker-Host

Diese Dateien sind eine Vorlage für `beacon-server` auf einem Linux-Rechner mit
Docker und Docker Compose. Die vollständige Anleitung (Passwort, Karten, Ports,
Erreichbarkeit, Updates, Sicherung) steht in
[docs/anleitung/server.md](../../docs/anleitung/server.md).

| Datei | Zweck |
|---|---|
| `compose.yaml` | Dienst `beacon` mit dem fertigen Image `ghcr.io/floderso/bfme-beacon-server` |
| `config.toml` | Server-Einstellungen; Passwort wird mit `set-password` eingetragen |
| `.dockerignore` | nur für das Selbstbauen: hält `maps/`, `data/` und `config.toml` aus dem Build-Kontext |

Kurzfassung:

```sh
sudo mkdir -p /opt/beacon && sudo chown "$USER": /opt/beacon
cd /opt/beacon                              # oder ein anderer Ordner
# compose.yaml und config.toml aus diesem Ordner hierher kopieren
mkdir -p maps data
sudo chown 1000:1000 data                   # Benutzer aus compose.yaml (user:)
# Passwort setzen (Anleitung, Abschnitt 3), dann:
docker compose up -d
```
