from reNgine.definitions import (
    ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK,
)

SCAN_STATUS_NAMES = {
    INITIATED_TASK: 'initiated',
    FAILED_TASK: 'failed',
    RUNNING_TASK: 'running',
    SUCCESS_TASK: 'success',
    ABORTED_TASK: 'aborted',
}
ACTIVE_STATUSES = (INITIATED_TASK, RUNNING_TASK)
TERMINAL_STATUSES = (FAILED_TASK, SUCCESS_TASK, ABORTED_TASK)

SEVERITY_NAMES = {-1: 'unknown', 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

# Top-level YAML keys reNgine treats as tasks (EngineType.tasks = yaml keys).
ENGINE_TASKS = {
    'subdomain_discovery': 'Subdomain discovery (subfinder, amass, ctfr, ...)',
    'http_crawl': 'HTTP probing / crawl with httpx (status, title, technologies)',
    'port_scan': 'Port scan (naabu)',
    'osint': 'OSINT (emails, metadata, dorks, employees)',
    'dir_file_fuzz': 'Directory & file fuzzing (ffuf)',
    'fetch_url': 'URL gathering (gau, gospider, hakrawler, katana ...)',
    'vulnerability_scan': 'Vulnerability scan (nuclei, dalfox, crlfuzz, s3scanner)',
    'waf_detection': 'WAF detection (wafw00f)',
    'screenshot': 'Screenshots (EyeWitness)',
}

# Tasks reNgine can run as a subscan on a single subdomain (initiate_subscan → globals()[task]).
SUBSCAN_TASKS = (
    'port_scan', 'osint', 'dir_file_fuzz', 'fetch_url',
    'vulnerability_scan', 'waf_detection', 'screenshot',
)

VULNERABILITY_SCAN_TOOLS = ('nuclei', 'dalfox', 'crlfuzz', 's3scanner')

# Scan results are written here by start_scan_ui (results_dir='/usr/src/scan_results').
RESULTS_ROOTS = ('/usr/src/scan_results',)
