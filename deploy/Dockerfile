# BFME Beacon – Server-Image
#
# Enthält nur das statisch gelinkte Linux-Binary (musl): keine Shell, kein
# Paketmanager, nichts, was man angreifen oder aktualisieren müsste.
#
# 1. Binary bauen (Entwicklungs-PC, Repo-Wurzel):
#      cargo build -p beacon-server --release --target x86_64-unknown-linux-musl
#    Ergebnis: <target-dir>/x86_64-unknown-linux-musl/release/beacon-server
# 2. Binary (Name: beacon-server) und dieses Dockerfile zusammen mit
#    homelab-beacon/compose.yaml nach /srv/docker/beacon kopieren.
# 3. Bauen und starten: cd /srv/docker/beacon && docker compose up -d --build
#    (ohne Compose: docker build -t beacon-server:local .)
#
# COPY --chmod braucht BuildKit (Standard seit Docker 23).
FROM scratch

COPY --chmod=0555 beacon-server /beacon-server

# Konfiguration wird von compose.yaml nach /config.toml eingebunden;
# `run` und `health` finden sie über diese Variable.
ENV BEACON_CONFIG=/config.toml

# Unprivilegierter Benutzer wie bei den anderen Homelab-Diensten.
USER 1000:1001
WORKDIR /

# 28086 TCP+UDP: Spieler (Steuerkanal + Relay); 28087 TCP: Status/Health (nur lokal).
EXPOSE 28086/tcp 28086/udp 28087/tcp

# SIGTERM (docker stop) beendet den Server sauber: Spieler bekommen eine
# Meldung, Relay-Sitzungen ein BYE. SIGHUP liest die Karten neu ein.
ENTRYPOINT ["/beacon-server"]
CMD ["run"]
