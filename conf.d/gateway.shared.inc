default_type application/json;
limit_conn conn_limit 80;
proxy_intercept_errors on;

# ---------------------------
# Security + Correlation Headers
# ---------------------------
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy no-referrer always;
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), microphone=()" always;
add_header Content-Security-Policy "frame-ancestors 'none'" always;
add_header X-Request-Id $gateway_request_id always;

# ---------------------------
# Stable JSON Errors (Gateway)
# ---------------------------
error_page 400 = @gw_err_400;
error_page 401 = @gw_err_401;
error_page 403 = @gw_err_403;
error_page 404 = @gw_err_404;
error_page 405 = @gw_err_405;
error_page 413 = @gw_err_413;
error_page 429 = @gw_err_429;
error_page 500 = @gw_err_500;
error_page 502 = @gw_err_502;
error_page 503 = @gw_err_503;
error_page 504 = @gw_err_504;

# ---------------------------
# CORS zentral am Gateway
# - Upstream CORS ausblenden
# - Allow-Origin NUR setzen, wenn Allowlist matcht ($cors_origin != "")
# ---------------------------
# Upstream-Header ausblenden, die zentral am Gateway gesetzt werden.
proxy_hide_header X-Frame-Options;
proxy_hide_header X-Content-Type-Options;
proxy_hide_header Referrer-Policy;
proxy_hide_header Permissions-Policy;
proxy_hide_header Content-Security-Policy;
proxy_hide_header Strict-Transport-Security;
proxy_hide_header X-Request-Id;
proxy_hide_header Vary;

proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Credentials;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Access-Control-Allow-Methods;

add_header Access-Control-Allow-Credentials $cors_allow_credentials always;
add_header Access-Control-Allow-Headers "Authorization,Content-Type,Accept,Origin,X-Request-ID,X-Tenant-Id,x-tenant-id" always;
add_header Access-Control-Allow-Methods "GET,POST,PUT,PATCH,DELETE,OPTIONS" always;
add_header Access-Control-Max-Age 600 always;
add_header Vary "Origin,Access-Control-Request-Method,Access-Control-Request-Headers" always;

# Allow-Origin nur wenn erlaubt (via map -> variable)
add_header Access-Control-Allow-Origin $cors_allow_origin always;

# Preflight immer tenant-free (Skip ist bereits auch im http-level map drin,
# aber hier beantworten wir es sofort und schnell.)
if ($request_method = OPTIONS) {
  return 204;
}

# ---------------------------
# Header-smuggling Schutz
# ---------------------------
if ($header_smuggling_detected) {
  return 400;
}

# ---------------------------
# Debug (tenant-free)
# ---------------------------
location = /debug/tenant {
  return 200 '{"tenant_from_header":"$tenant_from_header","tenant_missing":"$tenant_missing","tenant_allowed":"$tenant_allowed","tenant_unknown":"$tenant_unknown","skip_tenant_check":"$skip_tenant_check","tenant_reject_missing":"$tenant_reject_missing","tenant_reject_unknown":"$tenant_reject_unknown","host":"$host","x_tenant_id":"$http_x_tenant_id"}\n';
}

location = /__whoami {
  return 200 '{"tenant":"$tenant_from_header","host":"$host","x_tenant_id":"$http_x_tenant_id"}\n';
}

# ---------------------------
# Tenant Enforcement (global)
# - $tenant_reject_* ist im http-level bereits:
#   reject_missing = (NOT skip) AND (tenant_missing)
#   reject_unknown = (NOT skip) AND (tenant_unknown)
# ---------------------------
# Tenant fehlt
if ($tenant_reject_missing) {
  return 400;
}

# Tenant unbekannt
if ($tenant_reject_unknown) {
  return 403;
}

# ---------------------------
# Forwarding Headers
# ---------------------------
proxy_set_header Host                $host;
proxy_set_header X-Real-IP           $remote_addr;
proxy_set_header X-Forwarded-For     $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Host    $host;
proxy_set_header X-Forwarded-Proto   $scheme;

proxy_set_header X-Request-Id        $gateway_request_id;

# Auth weiterreichen (deine Vorgabe)
proxy_set_header Authorization       $http_authorization;

# Tenant: UUID-validierter Headerwert (oder leer)
proxy_set_header X-Tenant-Id         $tenant_from_header;
proxy_set_header x-tenant-id         $tenant_from_header;

# ---------------------------
# Routes (Location Snippets)
# ---------------------------
include /etc/nginx/api_conf.d/*.conf;
