"""Plain dict builders for API output.

Kept explicit (no ModelSerializer magic) so the wire format is stable and documented
in README.md. Querysets passed in here are expected to be prefetched by the caller.
"""
import yaml

from penty_api.constants import SCAN_STATUS_NAMES, SEVERITY_NAMES, ENGINE_TASKS


def _dt(value):
    return value.isoformat() if value else None


def status_name(value):
    return SCAN_STATUS_NAMES.get(value, 'unknown')


def project_dict(p):
    return {'id': p.id, 'name': p.name, 'slug': p.slug, 'insert_date': _dt(p.insert_date)}


def target_dict(d):
    return {
        'id': d.id,
        'name': d.name,
        'description': d.description,
        'project_slug': d.project.slug if d.project_id else None,
        'ip_address_cidr': d.ip_address_cidr,
        'insert_date': _dt(d.insert_date),
        'last_scan_date': _dt(getattr(d, 'start_scan_date', None)),
    }


def engine_tasks_from_yaml(yaml_text):
    try:
        data = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError:
        return []
    return [k for k in data.keys() if k in ENGINE_TASKS] if isinstance(data, dict) else []


def engine_dict(e, include_yaml=False, scan_count=None):
    out = {
        'id': e.id,
        'name': e.engine_name,
        'is_default': bool(e.default_engine),
        'tasks': engine_tasks_from_yaml(e.yaml_configuration),
    }
    if scan_count is not None:
        out['scan_count'] = scan_count
    if include_yaml:
        out['yaml_configuration'] = e.yaml_configuration
    return out


def link_dict(link):
    if not link:
        return None
    return {
        'external_ref': link.external_ref,
        'callback_url': link.callback_url,
        'last_notified_status': link.last_notified_status,
        'last_delivery_at': _dt(link.last_delivery_at),
        'last_delivery_ok': link.last_delivery_ok,
        'last_delivery_error': link.last_delivery_error or None,
    }


def scan_dict(scan, progress=None, link=None):
    out = {
        'id': scan.id,
        'target': {'id': scan.domain_id, 'name': scan.domain.name},
        'project_slug': scan.domain.project.slug if scan.domain.project_id else None,
        'engine': {'id': scan.scan_type_id, 'name': scan.scan_type.engine_name},
        'status': scan.scan_status,
        'status_name': status_name(scan.scan_status),
        'start_scan_date': _dt(scan.start_scan_date),
        'stop_scan_date': _dt(scan.stop_scan_date),
        'error_message': scan.error_message,
        'tasks': list(scan.tasks or []),
        'initiated_by': scan.initiated_by.username if scan.initiated_by_id else None,
        'config': {
            'imported_subdomains': list(scan.cfg_imported_subdomains or []),
            'out_of_scope_subdomains': list(scan.cfg_out_of_scope_subdomains or []),
            'starting_point_path': scan.cfg_starting_point_path or '',
            'excluded_paths': list(scan.cfg_excluded_paths or []),
        },
    }
    if progress is not None:
        out['progress'] = progress
    if link is not None:
        out['penty'] = link_dict(link)
    return out


def subscan_dict(sub, link=None):
    out = {
        'id': sub.id,
        'scan_id': sub.scan_history_id,
        'subdomain': {'id': sub.subdomain_id, 'name': sub.subdomain.name},
        'task': sub.type,
        'engine_id': sub.engine_id,
        'status': sub.status,
        'status_name': status_name(sub.status),
        'start_scan_date': _dt(sub.start_scan_date),
        'stop_scan_date': _dt(sub.stop_scan_date),
        'error_message': sub.error_message,
        'celery_task_id': (sub.celery_ids or [None])[0],
    }
    if link is not None:
        out['penty'] = link_dict(link)
    return out


def activity_dict(a):
    return {
        'id': a.id,
        'name': a.name,
        'title': a.title,
        'status': a.status,
        'status_name': status_name(a.status),
        'time': _dt(a.time),
        'error_message': a.error_message,
    }


def vulnerability_dict(v, include_http=True):
    out = {
        'id': v.id,
        'scan_id': v.scan_history_id,
        'source': v.source,
        'name': v.name,
        'severity': v.severity,
        'severity_name': SEVERITY_NAMES.get(v.severity, 'unknown'),
        'type': v.type,
        'template': v.template,
        'template_id': v.template_id,
        'template_url': v.template_url,
        'matcher_name': v.matcher_name,
        'http_url': v.http_url,
        'subdomain': {'id': v.subdomain_id, 'name': v.subdomain.name} if v.subdomain_id else None,
        'endpoint_id': v.endpoint_id,
        'target_id': v.target_domain_id,
        'description': v.description,
        'impact': v.impact,
        'remediation': v.remediation,
        'extracted_results': list(v.extracted_results or []),
        'cvss_metrics': v.cvss_metrics,
        'cvss_score': v.cvss_score,
        'cve_ids': [c.name for c in v.cve_ids.all()],
        'cwe_ids': [c.name for c in v.cwe_ids.all()],
        'tags': [t.name for t in v.tags.all()],
        'references': [r.url for r in v.references.all()],
        'discovered_date': _dt(v.discovered_date),
        'open_status': v.open_status,
    }
    if include_http:
        out['curl_command'] = v.curl_command
        out['request'] = v.request
        out['response'] = v.response
    return out


def subdomain_dict(s):
    return {
        'id': s.id,
        'scan_id': s.scan_history_id,
        'target_id': s.target_domain_id,
        'name': s.name,
        'is_imported': s.is_imported_subdomain,
        'is_important': bool(s.is_important),
        'http_url': s.http_url,
        'http_status': s.http_status,
        'page_title': s.page_title,
        'webserver': s.webserver,
        'content_type': s.content_type,
        'content_length': s.content_length,
        'response_time': s.response_time,
        'cname': s.cname,
        'is_cdn': bool(s.is_cdn),
        'cdn_name': s.cdn_name,
        'discovered_date': _dt(s.discovered_date),
        'technologies': sorted({t.name for t in s.technologies.all() if t.name}),
        'waf': [w.name for w in s.waf.all()],
        'ip_addresses': [
            {
                'address': ip.address,
                'is_cdn': ip.is_cdn,
                'is_private': ip.is_private,
                'ports': sorted(
                    ({'number': p.number, 'service_name': p.service_name, 'is_uncommon': p.is_uncommon}
                     for p in ip.ports.all()),
                    key=lambda x: x['number']),
            }
            for ip in s.ip_addresses.all()
        ],
    }


def endpoint_dict(e):
    return {
        'id': e.id,
        'scan_id': e.scan_history_id,
        'subdomain_id': e.subdomain_id,
        'http_url': e.http_url,
        'http_status': e.http_status,
        'page_title': e.page_title,
        'content_type': e.content_type,
        'content_length': e.content_length,
        'webserver': e.webserver,
        'is_default': bool(e.is_default),
        'technologies': sorted({t.name for t in e.techs.all() if t.name}),
        'discovered_date': _dt(e.discovered_date),
    }
