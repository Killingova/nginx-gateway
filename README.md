# NGINX API Gateway

Zentraler Reverse Proxy / API-Gateway fuer die Plattform.
Das Gateway ist der einzige externe Eintrittspunkt und leitet Anfragen kontrolliert an interne Services weiter (`auth-service`, `profile-service`).

## Zweck / Boundary
- Einziger externer Einstiegspunkt fuer HTTP/HTTPS.
- Routet kontrolliert zu internen Services im Docker-Netz.
- Kein direkter Public-Zugriff auf Auth/Profile/DB.

## Aktueller Stand (2026-02-12 17:57:26 CET)

- Container `nginx-gateway` laeuft `healthy`.
- `GET https://127.0.0.1:8443/healthz` liefert `200`.
- Upstream-Checks sind gruen:
  - `GET https://127.0.0.1:8443/auth/healthz` -> `200`
  - `GET https://127.0.0.1:8443/health/profile` -> `200`
- Auth Rate-Limit-Key ist final tenant-aware: `tenant + ip + route` (mind. `login`/`refresh` getrennt).
- Gateway `limit_req` liefert jetzt konsistent `429` (kein irrefuehrendes `503` mehr).

## Security Contract
- TLS-Termination und Header-Hygiene am Gateway.
- Tenant-aware Rate Limits und Edge-AuthZ (`auth_request`) fuer geschuetzte Pfade.
- Metrics bleiben isoliert (`:18080`), `/metrics` auf Public Listener liefert `404`.

Der Fokus liegt auf:

* klarer Trennung von Gateway <-> Services
* Transport-/TCP-Optimierung (Keep-Alive, Timeouts)
* Security by Default (Rate Limits, Header, CORS)
* wartbarer, modularer Konfiguration

---

## Architektur (Kurzueberblick)

```
Client
  |
  |  HTTP/TCP (Keep-Alive)
  v
NGINX Gateway (Port 8080 + 443/8443 extern)
  |
  +--> auth-service:3000      (intern, Docker-Netz)
  |
  +--> profile-service:4000   (intern, Docker-Netz)
```

* Extern offen: nur das Gateway (`127.0.0.1:8080`, `127.0.0.1:443`, `127.0.0.1:8443`)
* Intern: Kommunikation ausschliesslich ueber das Docker-Netz `paradox_net`
* Keine direkte Service- oder DB-Exposition vorgesehen

---

## Projektstruktur

```
nginx-gateway/
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── api_gateway.conf
├── api_conf.d/
│   ├── 00_health.conf
│   ├── 10_auth.conf
│   ├── 20_profile.conf
│   ├── 25_authz.conf
│   ├── 90_errors.conf
│   ├── 95_security.conf
│   └── 99_metrics.conf
├── conf.d/
│   ├── gateway.server.conf
│   ├── gateway.shared.inc
│   └── 99_metrics.server.conf
└── README.md
```

### Dateirollen

**Dockerfile**
Baut ein schlankes NGINX-Image (Alpine) mit statischer Konfiguration.

**docker-compose.yml**
Startet das Gateway im externen Docker-Netz `paradox_net`.
Host-Ports:
-> `127.0.0.1:8080` (HTTP Redirect auf HTTPS),
-> `127.0.0.1:443` (HTTPS canonical),
-> `127.0.0.1:8443` (HTTPS),
-> `127.0.0.1:18080` (interne Metrics fuer Host-Checks).

**nginx.conf**
Globale Basis:

* Worker / Events
* Logging
* TCP-Optimierung (Keep-Alive, Timeouts)
* Rate-Limit-Zonen
* Security-Header
* Proxy-Defaults
  -> bindet `api_gateway.conf` ein

**api_gateway.conf**

* Definiert Upstreams
* Header-/Tenant-/CORS-Maps
* Request-ID/Tracing-Variablen
* Tenant-aware Rate-Limit Keys

**api_conf.d/**
Feature-Routing und Sicherheits-Snippets (modular, versionsfaehig).

**conf.d/gateway.server.conf**

* zentraler `server {}`-Block
* CORS, Tenant Enforcement, Error Envelope, Includes

---

## Routing (aktueller Stand)

### Auth-Service

```
/auth/healthz  -> auth-service:/healthz (alias)
/auth/login    -> auth-service:3000 (public, tenant-guarded)
/auth/refresh  -> auth-service:3000 (public, tenant-guarded)
/auth/me       -> auth-service:3000 (protected via auth_request)
/auth/logout   -> auth-service:3000 (protected via auth_request)
/auth/sessions*-> auth-service:3000 (protected via auth_request)
/auth/*        -> auth-service:3000 (weitere Auth-Routen, tenant-guarded)
```

Cookie/CSRF-Matrix (Contract):
- Aktuell: kein Cookie-authenticated Endpoint am Gateway erzwungen (Bearer-Flow aktiv).
- Sobald `/auth/refresh` auf Cookie-Auth umgestellt wird:
  - CSRF-Schutz wird verpflichtend (`X-CSRF-Token` + Origin/Referer-Pruefung im Auth-Service).
  - Fail-closed bleibt aktiv (Verify/Introspection-Ausfall => `503`).

### Profile-Service

```
/profiles/*    -> profile-service:4000
```

---

## Health- & Status-Endpoints

Die Healthchecks sind explizit getrennt (kein Wildcard-Routing).

### Gateway (ohne Upstream-Abhaengigkeit)

```
GET /healthz
-> 200
-> {"status":"ok","service":"nginx-gateway"}
```

### Gateway Readiness (minimal upstream check)

```
GET /readyz
-> 200 wenn Gateway + minimaler upstream check erfolgreich
-> 503 wenn dependency nicht bereit
```

### Auth-Service

```
GET /health/auth
-> proxy -> auth-service:/healthz
```

### Profile-Service

```
GET /health/profile
-> proxy -> profile-service:/health
```

### Metrics (isoliert)

```
GET /metrics (public listener)
-> 404

GET http://127.0.0.1:18080/metrics
-> stub_status
```

**Ziel:**

* Gateway-Liveness unabhaengig von Backends
* gezielte Upstream-Diagnose
* saubere Trennung fuer spaetere K8s / Monitoring-Systeme

---

## Transport- & TCP-Optimierung (bewusst gesetzt)

Im Gateway umgesetzt:

* Keep-Alive (Client <-> NGINX)
  reduziert TCP-Handshakes
* Keep-Alive (NGINX <-> Upstream)
  vermeidet Connection-Flood intern
* Timeouts
  verhindern haengende Socket-States (`CLOSE_WAIT`, `SYN_SENT`)
* Buffering & Limits
  Schutz gegen langsame Clients / Missbrauch

Diese Einstellungen sind direkt aus Transport-/TCP-Grundlagen abgeleitet.

---

## Security-Mechanismen

* Rate Limiting

  * Auth-Endpoints (Brute-Force-Schutz)
  * Tenant-aware Auth-Limits (Tenant+IP)
  * Allgemeine API-Limits
* CORS-Whitelist

  * kontrolliert ueber `map`
  * korrekte Preflight-Responses (`204`, `Vary`, `Max-Age`)
* Security Header

  * `X-Frame-Options`
  * `X-Content-Type-Options`
  * `Referrer-Policy`
  * `Permissions-Policy`
  * `Content-Security-Policy` (`default-src 'self'`, `script-src 'self'`, `frame-ancestors 'none'`, u. a.)
* Header-Hygiene

  * Weitergabe nur relevanter Proxy-Header
  * Smuggling-Schutz fuer sensible Header
* Edge AuthZ via `auth_request`

  * `/_auth_verify` delegiert Token-/Tenant-/Scope-/Role-Pruefung an Auth-Service
  * `/profiles/*` erzwingt method-basierte Scopes (`profile:read`/`profile:write`)
  * `/auth/me`, `/auth/logout`, `/auth/sessions*` sind explizit protected
  * Introspection-/Verify-Ausfall ist fail-closed (`503`), kein fail-open
* Trusted Header Contract

  * Clients duerfen keine trusted Identity-Header setzen (`X-User-Id`, Rollenheader).
  * `X-Tenant-Id` wird am Gateway auf UUID-Pattern validiert/kanonisiert.
  * Upstreams sollen nur Gateway-trusted Headern vertrauen.
* Stable Error Envelope

  * JSON Fehler statt NGINX-HTML Defaults
  * Request-ID in Gateway-Fehlerantworten

---

## Gateway <-> Service Forward Contract

Gateway garantiert:

* `X-Request-Id` ist immer gesetzt (uebernommen oder erzeugt).
* `X-Tenant-Id` wird nur kanonisiert/validiert weitergereicht (kein raw passthrough).
* `X-Forwarded-Proto` und `X-Forwarded-Host` werden kontrolliert gesetzt.
* Kein Forwarding von Client-seitig untrusted Identity-Headern als trusted User-Identity.

Service garantiert:

* Tenant wird serverseitig weiterhin validiert (Defense in depth).
* Service-Fehler bleiben im JSON-Vertrag.
* Keine blinde Vertrauensannahme auf ungepruefte Forwarded Header.

---

## Ops

### Starten

```bash
cd nginx-gateway
docker compose up -d --build
```

**Voraussetzung:**
Externes Netzwerk existiert:

```bash
docker network create paradox_net
```

### Uebliche Debug-Kommandos

```bash
# Konfiguration testen
docker exec -it nginx-gateway nginx -t

# Live-Konfiguration anzeigen (inkl. includes)
docker exec -it nginx-gateway nginx -T

# Logs
docker logs nginx-gateway --tail 200

# HTTP/HTTPS
curl -i http://127.0.0.1:8080/healthz
curl -k -i https://127.0.0.1:8443/healthz

# SPA Catch-all method safety
curl -i -X PUT http://127.0.0.1:8080/

# AuthZ am Edge fuer protected APIs
curl -i http://127.0.0.1:8080/profiles/me -H "X-Tenant-Id: 189aa6cf-1ebb-4b76-a134-bc3c35f1df24"

# Metrics isoliert
curl -i http://127.0.0.1:8080/metrics
curl -i http://127.0.0.1:18080/metrics
```

---

## Erweiterung: Neue Services

1. Upstream in `api_gateway.conf` anlegen
2. Neue Datei in `api_conf.d/XX_service.conf`
3. Pfad -> Upstream routen
4. Container ins `paradox_net` haengen

Kein bestehender Code muss geaendert werden.

## DoD Checks
```bash
curl -k -i https://127.0.0.1:8443/healthz
curl -k -i https://127.0.0.1:8443/auth/healthz
curl -k -i https://127.0.0.1:8443/health/profile
curl -i http://127.0.0.1:18080/metrics
curl -k -i https://127.0.0.1:8443/metrics
```

Erwartung:
- Gateway- und Upstream-Health `200`.
- Metrics auf Public-Listener nicht verfuegbar.

## Guardrails
- Keine direkten Service-Ports nach aussen.
- Keine unvalidierten Tenant-Header an Upstreams durchreichen.
- Security-/Error-Standards bleiben zentral im Gateway.

---

## Geplanter naechster Schritt (TODO)

* Optional: HTTP->HTTPS Redirect fuer PROD erzwingen
* Prometheus Exporter statt `stub_status` (optional)
* Trennung in `public_net` und internes Service-Netz (`paradox_net`) haerten
* Optionales internes mTLS (Gateway -> Services) evaluieren
* Vorbereitung fuer K8s / Ingress-Migration

---

## OSI-Schichten in der Plattform (Lernnotizen)

### 2) Data Link Layer - Ethernet, MAC, Frames

Module:

* Ethernet & MAC-Adressen
* Unicast / Multicast / Broadcast
* Zerlegen eines Ethernet-Frames
* Sicherungsschicht

Fuer deine Plattform:

* Docker nutzt das vollautomatisch

Was hier passiert:

* Docker-Bridge = virtueller Switch
* Jeder Container hat:

  * eigene MAC
  * eigene IP im Docker-Netz

Warum wichtig?

* Broadcasts bleiben im Docker-Netz
* Container sehen sich nur im gleichen Network (paradox_net)

Relevanz: 2/5
(Erklaert, warum dein internes Netz sicher & schnell ist)

### 3) Netzwerk-Schicht - IP, Routing, Geraete

Module:

* Router
* Server & Clients
* Geraete fuer die Vernetzung

Das ist 1:1 deine Plattform

| Konzept aus dem Kurs | Bei dir |
| --- | --- |
| Router | NGINX |
| Server | auth-service, profile-service |
| Client | Browser / curl |
| Netzwerk | paradox_net |
| NAT | Docker Host |

Du hast gebaut:

* NGINX = Edge Router
* Docker-Netz = internes LAN
* Nur Port 8080 offen -> alles andere intern

Relevanz: 4/5
(Das ist Architektur-Kernwissen)

### 4) Transport Layer - dein staerkstes Kapitel

Module:

* TCP
* Zerlegung von Segmenten
* TCP-Flags
* Drei-Wege-Handshake
* Socket-Zustaende

Das ist der wichtigste Teil fuer NGINX

Was du bereits richtig umgesetzt hast:

| TCP-Theorie | Deine Config |
| --- | --- |
| Handshake reduzieren | keepalive |
| Socket-Leaks vermeiden | client_*_timeout |
| Verbindungswiederverwendung | proxy_http_version 1.1 |
| TIME_WAIT reduzieren | keepalive_requests |
| Schutz vor haengenden Verbindungen | proxy_read_timeout |

Typische Probleme, die du jetzt lesen kannst:

| Log / Symptom | Bedeutung |
| --- | --- |
| connection refused | Service down |
| 504 Gateway Timeout | Upstream haengt |
| viele kurze Requests | fehlendes Keep-Alive |
| unhealthy | falsche Readyz-Logik |

Relevanz: 5/5
Das ist deine operative Superkraft

### 5) Anwendungsschicht - HTTP, APIs, Reverse Proxy

Module:

* Server & Clients
* TCP/IP
* Warum Vernetzung wichtig ist

Hier passiert deine ganze Plattform-Logik

Du hast bereits:

* Reverse Proxy
* API-Routing
* Rate-Limiting
* CORS
* Security-Header
* Health-Checks

Relevanz: 5/5
Hier baust du echte Systeme

---

## Was dein NGINX-Gateway jetzt ist (fachlich korrekt)

Du kannst das so dokumentieren:

Rolle des NGINX-Containers ("die Tuer")

NGINX Gateway ist:

* Edge-Router
* Reverse Proxy
* Security-Boundary
* Performance-Optimierer
* Observability-Punkt

Er uebernimmt:

* TCP-Verbindungsmanagement
* Request-Weiterleitung
* Rate-Limiting
* CORS-Kontrolle
* Health-Aggregation

Aktuelle Architektur (vereinfacht)

```
Internet / Browser
        |
        | TCP (Keep-Alive)
        v
+------------------+
|   NGINX Gateway  |  <- EINZIGE offene Tuer
|  :8080 / :443    |
+------------------+
        |
        | internes Docker-Netz (paradox_net)
        |
  +------------+    +----------------+
  | auth-svc   |    | profile-svc    |
  | :3000      |    | :4000          |
  +------------+    +----------------+
        |
     +--------+
     |  DB    |
     +--------+
```

Health-Strategie (Production-faehig)

| Endpoint | Bedeutung |
| --- | --- |
| /healthz | Gateway lebt |
| /health/auth | Auth erreichbar |
| /health/profile | Profile erreichbar |

* sauber getrennt
* keine Wildcards
* Gateway bleibt erreichbar, auch wenn Backends down sind

Sicherheitsstatus (sehr wichtig): OK

* Nur NGINX exposed
* Internes Docker-Netz
* Rate-Limit auf Auth
* Kein direkter DB-Zugriff von aussen

To-Do (naechster Schritt)

* DB-Port nicht nach aussen publishen
* profile-service nicht nach aussen publishen
* HTTPS (TLS) aktivieren

Was du JETZT sinnvoll als Naechstes lernen / bauen kannst

1) Monitoring (Transport-Ebene sichtbar machen)

* stub_status oder Prometheus Exporter
* aktive Verbindungen
* waiting / reading / writing

2) TLS + HTTP/2

* weniger Handshakes
* bessere Browser-Performance

3) Ready/Liveness-Checks in Services

* /livez ohne DB
* /readyz mit DB & Redis
