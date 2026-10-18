# BFME Beacon – Server-Image
#
# Enthält nur das statisch gelinkte Linux-Binary (musl): keine Shell, kein
# Paketmanager, nichts, was man angreifen oder aktualisieren müsste.
#
# Fertige Images baut die Release-Pipeline (.github/workflows/release.yml):
#   ghcr.io/floderso/bfme-beacon-server:<version> und :latest
#
# Selbst bauen (Repo-Wurzel):
#   cargo build -p beacon-server --release --target x86_64-unknown-linux-musl
#   mkdir -p ctx && cp <target-dir>/x86_64-unknown-linux-musl/release/beacon-server ctx/
#   docker build -f deploy/Dockerfile -t beacon-server:local ctx
# oder mit Compose: siehe deploy/docker/compose.yaml (Abschnitt `build`).
#
# COPY --chmod braucht BuildKit (Standard seit Docker 23).
FROM scratch

LABEL org.opencontainers.image.title="bfme-beacon-server" \
      org.opencontainers.image.description="BFME Beacon: Lobby- und Relay-Server für BFME1 (Heimserver-Mehrspieler)" \
      org.opencontainers.image.source="https://github.com/Floderso/bfme-beacon" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

COPY --chmod=0555 beacon-server /beacon-server

# Konfiguration wird von compose.yaml nach /config.toml eingebunden;
# `run`, `set-password` und `health` finden sie über diese Variable.
ENV BEACON_CONFIG=/config.toml

# Unprivilegierter Benutzer (compose.yaml kann ihn mit `user:` ändern).
USER 1000:1000
WORKDIR /

# 28086 TCP+UDP: Spieler (Steuerkanal + Relay); 28087 TCP: Status/Health (nur lokal).
EXPOSE 28086/tcp 28086/udp 28087/tcp

# SIGTERM (docker stop) beendet den Server sauber: Spieler bekommen eine
# Meldung, Relay-Sitzungen ein BYE. SIGHUP liest die Karten neu ein.
ENTRYPOINT ["/beacon-server"]
CMD ["run"]
