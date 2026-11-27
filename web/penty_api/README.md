# Penty Integration API (`penty_api`)

Token-authenticated JSON API that lets [Penty](https://github.com/regrews/Penty) drive reNgine end to end.
Mounted at **`/api/v1/penty/`**. The app is self-contained. The only changes to reNgine itself are
one line in `INSTALLED_APPS` and one `path()` in `reNgine/urls.py`, which keeps upstream merges painless.

## Setup

```bash
docker exec rengine-web-1 python3 manage.py migrate penty_api
# service account (no UI password) with the penetration_tester role
docker exec rengine-web-1 python3 manage.py shell -c "
from django.contrib.auth.models import User; from rolepermissions.roles import assign_role
u,_=User.objects.get_or_create(username='penty-service'); u.set_unusable_password(); u.save(); assign_role(u,'penetration_tester')"
docker exec rengine-web-1 python3 manage.py penty_api create-token --user penty-service --name penty-prod   # printed once
docker compose restart web celery          # celery must load the app for webhooks
```

Other commands: `list-tokens`, `revoke-token --id N`, `show-config`,
`set-webhook --enable --secret-from-env VAR [--allowed-prefix https://penty.example/]`, `set-webhook --disable`.

## Authentication & errors

- `Authorization: Bearer rgp_…` header. Only the SHA-256 of the token is stored.
- Session cookies and Basic auth are **not** accepted on this API.
- `401` is returned for a missing, invalid or revoked token, or an inactive user. It is never a login redirect.
- `403` is returned when the token user's reNgine role lacks the permission. Starting scans and subscans needs `initiate_scans_subscans`.
- Errors have the shape `{"error": "...", "field": "..."}` (the `field` key is optional). Status codes: `400` validation, `404` not found, `409` conflict.
- List endpoints are paginated: `{"count", "next", "previous", "results"}`, with `?page=` and `?page_size=` (default 100, max 500).

Status codes (scans, subscans, activities): `-1 initiated`, `0 failed`, `1 running`, `2 success`, `3 aborted`.
Severity: `-1 unknown`, `0 info`, `1 low`, `2 medium`, `3 high`, `4 critical`.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `health/` | DB, celery workers (ping), active scan count, reNgine version |
| GET | `tasks-catalog/` | engine task names, subscan-capable tasks, installed subdomain tools |
| GET / POST | `projects/` | POST `{name}` → slugified. Idempotent: `201` created / `200` existing |
| GET / POST | `targets/` | `?project_slug=&search=`. POST `{project_slug, name, description?}`. `name` can be a domain, IP or URL. Wildcards are stripped. CIDR is rejected. Idempotent. `409` if the name belongs to another project |
| GET / PATCH / DELETE | `targets/{id}/` | PATCH `{description}`. DELETE returns `409` while scans are running |
| GET / POST | `engines/` | POST `{name, yaml_configuration}`. The YAML must be a mapping with at least one task key |
| GET / PUT / PATCH / DELETE | `engines/{id}/` | Built-in engines are read-only (`403`). Engines used by scans cannot be deleted (`409`), because deleting would cascade and remove scan history |
| GET / POST | `scans/` | Filters `?target_id=&project_slug=&status=&external_ref=`. POST: see below |
| GET / DELETE | `scans/{id}/` | Detail includes `progress` and `counts`. DELETE: not while running. Results dir is removed (path-guarded) |
| POST | `scans/{id}/stop/` | Same steps as the UI abort: status=aborted, revoke celery tasks, close running activities |
| GET | `scans/{id}/activity/` | Task-level log (ScanActivity) |
| GET | `scans/{id}/results/vulnerabilities/` | `?severity_min=N&include_http=0` (drops request/response/curl) |
| GET | `scans/{id}/results/subdomains/` | Technologies, WAF, IPs + ports. `?alive_only=1` |
| GET | `scans/{id}/results/endpoints/` | On-demand, can be large |
| GET | `scans/{id}/results/ports/` | Open ports **seen in this scan** (naabu output file), `{available, count, results:[{host, ip, port, protocol, tls}]}` |
| GET / POST | `subscans/` | Filters `?scan_id=&celery_task_id=&external_ref=`. POST: see below |
| GET | `subscans/{id}/` | |
| POST | `subscans/{id}/stop/` | |
| GET | `subscans/{id}/results/{vulnerabilities,subdomains,endpoints,ports}/` | Only what that subscan produced |

### Start a scan — `POST scans/`

```json
{
  "target_id": 1,
  "engine_id": 10,
  "imported_subdomains": ["www.example.com"],
  "out_of_scope_subdomains": ["vpn.example.com"],
  "starting_point_path": "/app",
  "excluded_paths": ["/logout"],
  "external_ref": "penty-scanrun-<guid>",
  "callback_url": "https://penty.example/api/integrations/rengine/webhook"
}
```

- The response is `201` with the scan in `initiated` state.
- Duplicate and case variants in the lists are removed. Lists may also be given as comma or newline separated strings.
- The celery task is enqueued **after** the DB commit.
- "Only these hosts" mode: use an engine **without** `subdomain_discovery`. reNgine skips tasks that are not in the engine.
- Imported subdomains must belong to the target's registrable domain. reNgine filters out the rest.

### Subscans — `POST subscans/`

```json
{"subdomain_ids": [12, 13], "tasks": ["vulnerability_scan"], "engine_id": 10, "external_ref": "retest-…", "callback_url": "…"}
```

- The response is `202 {"queued": [{"subdomain_id", "task", "celery_task_id"}]}`.
- The `SubScan` row is created by the worker. Find it with `GET subscans/?celery_task_id=…`.
- Allowed tasks: `port_scan, osint, dir_file_fuzz, fetch_url, vulnerability_scan, waf_detection, screenshot`.

## Webhook (optional; Penty also polls)

When a scan or subscan started through this API reaches `failed`, `success` or `aborted`, and both the webhook and the link's `callback_url` are set:

```
POST <callback_url>
X-Penty-Timestamp: <unix seconds>
X-Penty-Signature: sha256=<hex HMAC_SHA256(secret, "<timestamp>.<raw body>")>
{"event":"scan.finished","kind":"scan","status":2,"status_name":"success","external_ref":"…","scan_id":5,"subscan_id":null,"sent_at":"…"}
```

- Delivery is attempted twice with a 4 s timeout and no redirects. Each status is sent once.
- A delivery failure never affects the scan.
- The receiver should reject timestamps older than ~5 minutes.

## Known reNgine data caveats

- `IpAddress` and `Port` rows are global, not per scan. Ports accumulate over time, so a closed port is not removed.
  The ports listed under a subdomain are therefore "ever seen", not "seen in this scan".
  Use `results/ports/` for per-scan truth (port-closed detection).
- Technology names come from httpx/wappalyzer. The version is embedded when known (`Nginx:1.18.0`).
- `Domain.name` is globally unique, so a host can belong to only one reNgine project.

## Tests

```bash
docker exec rengine-web-1 python3 manage.py test penty_api
```
