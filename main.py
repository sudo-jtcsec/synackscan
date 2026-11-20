import sys,requests,time,os,shutil,getpass,subprocess,json,re,socket,ipaddress,ssl
from collections import defaultdict
from urllib.parse import urlsplit
from pathlib import Path
from database import ReconDB, DEFAULT_DB_PATH, run_db_cli
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

debug = True
context = {}

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <module>")
    sys.exit(1)

module = sys.argv[1]

CONFIG_ENV_FILE = Path.home() / ".config" / "synackscan" / "env"
TOKEN_ENV_NAME = "SYNACK_BEARER"
ROOT_URL_ENV_NAME = "SYNACK_ROOT_URL"
NUCLEI_ISERVER_ENV_NAME = "NUCLEI_ISERVER"
SLACK_WEBHOOK_ENV_NAME = "SLACK_WEBHOOK_URL"
BOT_SEVERITIES_ENV_NAME = "BOT_SEVERITIES"
EXCLUDED_TARGETS_ENV_NAME = "EXCLUDED_TARGETS"

DEFAULT_ROOT_URL = "https://platform.synack.us"
DEFAULT_NUCLEI_ISERVER = "w4.to"


def loadEnvFile():
    values = {}

    if not CONFIG_ENV_FILE.exists():
        return values

    try:
        for line in CONFIG_ENV_FILE.read_text().splitlines():
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    except Exception as e:
        if debug:
            print(f"Unable to read {CONFIG_ENV_FILE}: {e}")

    return values


def saveEnvValue(key, value):
    values = loadEnvFile()
    values[key] = value

    CONFIG_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)

    content = "".join(
        f"{env_key}={env_value}\n"
        for env_key, env_value in values.items()
    )

    CONFIG_ENV_FILE.write_text(content)
    os.chmod(CONFIG_ENV_FILE, 0o600)
    os.environ[key] = value


def loadEnvValue(key):
    value = os.environ.get(key, "").strip()

    if value:
        return value

    value = loadEnvFile().get(key, "").strip()

    if value:
        os.environ[key] = value
        return value

    return None


def excludedTargetCodenames():
    """Read a comma-separated, case-insensitive skip list from the env file.

    Re-read for each target refresh so bot runs can pick up changes without restart.
    """
    raw = loadEnvFile().get(EXCLUDED_TARGETS_ENV_NAME, '')
    # Explicit process environment overrides the persisted configuration.
    if EXCLUDED_TARGETS_ENV_NAME in os.environ:
        raw = os.environ[EXCLUDED_TARGETS_ENV_NAME]
    return {name.strip().casefold() for name in raw.split(',') if name.strip()}


def isExcludedTarget(codename):
    return str(codename or '').strip().casefold() in excludedTargetCodenames()


platform_url = loadEnvValue(ROOT_URL_ENV_NAME)

if not platform_url:
    platform_url = DEFAULT_ROOT_URL
    saveEnvValue(ROOT_URL_ENV_NAME, platform_url)

platform_url = platform_url.rstrip("/")

nuclei_iserver = loadEnvValue(NUCLEI_ISERVER_ENV_NAME)

if not nuclei_iserver:
    nuclei_iserver = DEFAULT_NUCLEI_ISERVER
    saveEnvValue(NUCLEI_ISERVER_ENV_NAME, nuclei_iserver)

nuclei_iserver = nuclei_iserver.strip()


def nucleiScanArgs():
    """Build validated Nuclei runtime flags for every scanning code path.

    Process environment takes precedence over ~/.config/synackscan/env.
    Values are read at invocation time so long-running bot scans can pick up
    configuration changes from the env file between iterations.
    """
    settings = (
        ("NUCLEI_CONCURRENCY", "-c", 50, 1, 1000),
        ("NUCLEI_RATE_LIMIT", "-rl", 10, 1, 100000),
        ("NUCLEI_BULK_SIZE", "-bs", 8, 1, 1000),
        ("NUCLEI_TIMEOUT", "-timeout", 5, 1, 3600),
        ("NUCLEI_RETRIES", "-retries", 0, 0, 20),
    )
    arguments = []
    for key, flag, default, minimum, maximum in settings:
        raw = loadEnvValue(key)
        try:
            value = default if raw is None else int(raw)
        except ValueError as exc:
            raise ValueError(f"Invalid {key}={raw!r}: expected an integer") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"Invalid {key}={value}: allowed range {minimum}..{maximum}")
        arguments.extend((flag, str(value)))
    return arguments

# Local SQLite database. DB queries can run without Synack authentication.
db = ReconDB(DEFAULT_DB_PATH)

if module == "db":
    db.close()
    run_db_cli(DEFAULT_DB_PATH, sys.argv[2:])
    sys.exit(0)


def botSeverities():
    raw = loadEnvFile().get(BOT_SEVERITIES_ENV_NAME) or os.environ.get(BOT_SEVERITIES_ENV_NAME) or 'critical,high,medium'
    allowed = {'critical','high','medium','low','info','unknown'}
    values = [v.strip().lower() for v in raw.split(',') if v.strip()]
    if not values or any(v not in allowed for v in values):
        raise ValueError('Invalid BOT_SEVERITIES; use comma-separated Nuclei severity names')
    return list(dict.fromkeys(values))


def botSlack(event, codename=None, severity=None):
    # Privacy boundary: NEVER pass Nuclei finding objects, URLs, template IDs,
    # response data, or exception strings into Slack messages.
    webhook = loadEnvFile().get(SLACK_WEBHOOK_ENV_NAME) or os.environ.get(SLACK_WEBHOOK_ENV_NAME)
    if not webhook:
        return
    def safe(value):
        return re.sub(r'[^A-Za-z0-9_.-]', '_', str(value or ''))[:100]
    if event == 'new':
        message = f'New target registered: {safe(codename)}'
    elif event == 'match':
        message = f'Template matched: {safe(codename)} | severity: {safe(severity)}'
    elif event == 'auth':
        message = 'Synack bearer token authentication failed'
    else:
        return
    try:
        response = requests.post(webhook, json={'text': message}, timeout=8)
        if response.status_code >= 300:
            print(f'[bot][slack] HTTP {response.status_code}', flush=True)
    except requests.RequestException:
        print('[bot][slack] Notification failed', flush=True)


def log(message):
    if debug:
        print(message)


def validateBearer(token):
    test_headers = {"Authorization": "Bearer " + token}

    try:
        resp = requests.get(
            platform_url + "/api/profiles/me",
            headers=test_headers,
            verify=False,
            timeout=10
        )

        if resp.status_code != 200:
            return False

        j = resp.json()

        if j.get("user_id") == "8pm493i9kc":
            return True

        return False

    except Exception as e:
        if debug:
            print("Error validating bearer:", e)
        return False


def saveBearer(token):
    saveEnvValue(TOKEN_ENV_NAME, token)


def loadSavedBearer():
    return loadEnvValue(TOKEN_ENV_NAME)


def getBearer():
    """
    Bearer priority:

      1. --bearer <token> explicit override
      2. SYNACK_BEARER already present in environment
      3. Previously saved ~/.config/synackscan/env token
      4. Secure interactive prompt

    Every token is validated before use. A newly supplied valid token is
    persisted for subsequent runs.
    """

    token = None

    # Optional explicit override that does not collide with module arguments.
    if "--bearer" in sys.argv:
        try:
            bearer_index = sys.argv.index("--bearer")
            token = sys.argv[bearer_index + 1].strip()
        except (ValueError, IndexError):
            print("Usage error: --bearer requires a token.")
            sys.exit(1)

        print("Checking supplied bearer token...")

        if validateBearer(token):
            print("Bearer token valid.")
            saveBearer(token)
            return token

        print("Supplied bearer token is invalid or expired.")

    # Otherwise use current env or persisted env file.
    token = loadSavedBearer()

    if token:
        print("Checking saved bearer token...")

        if validateBearer(token):
            print("Saved bearer token valid.")
            return token

        print("Saved bearer token is invalid or expired.")

    if module == 'bot':
        # No interactive prompts or credential leakage in unattended mode.
        botSlack('auth')
        return None

    # Nothing usable was found. Prompt until a valid bearer is supplied,
    # then replace the persisted value.
    while True:
        token = getpass.getpass("Synack bearer token: ").strip()

        if not token:
            print("Bearer token cannot be empty.")
            continue

        print("Checking bearer token...")

        if validateBearer(token):
            print("Bearer token valid. Saving for subsequent runs.")
            saveBearer(token)
            return token

        print("Invalid or expired bearer token. Try again.")


bearer = getBearer()
headers = {"Authorization": "Bearer " + (bearer or '')}


def checkLoginStatus():
    resp = requests.get(platform_url+"/api/profiles/me",headers=headers,verify=False)
    if resp.status_code == 200:
        j = resp.json()
        if j["user_id"] == '8pm493i9kc':
            return True
        else:
            return False
    else:
        return False


def getAllTargets(context):
    status = checkLoginStatus()
    log("getAllTargets Auth: "+str(status))
    if status:
        resp = requests.get(platform_url+"/api/targets/registered_summary",headers=headers,verify=False)
        if resp.status_code == 200:
            targets = resp.json()
            if not isinstance(targets, list):
                print('[targets] Unexpected registered target response; refusing to scan.', flush=True)
                return False
            excluded = excludedTargetCodenames()
            skipped = [target for target in targets if isinstance(target, dict)
                       and str(target.get('codename') or '').strip().casefold() in excluded]
            context['targetlist'] = [target for target in targets if isinstance(target, dict)
                                     and str(target.get('codename') or '').strip().casefold() not in excluded]
            for target in skipped:
                print(f"[targets][excluded] Skipping {target.get('codename')}", flush=True)
            db.sync_targets(context['targetlist'])
            return True
    return False


def getCodenameFromSlug(context, slug):
    for i in range(len(context['targetlist'])):
        if context['targetlist'][i]['id'].lower() == slug.lower():
            return(context['targetlist'][i]['codename'])


def getTargetID(context, codename):
    for i in range (len(context['targetlist'])):
        if context['targetlist'][i]['codename'].lower() == codename.lower():
            return(context['targetlist'][i]['id'])


def getTargetInfo(context, codename):
    for i in range (len(context['targetlist'])):
        if context['targetlist'][i]['codename'].lower() == codename.lower():
            return(context['targetlist'][i])


def registerAllTargets():
    status = checkLoginStatus()
    log("registerAllTargets Auth: "+str(status))

    if status:
        pageNum = 1
        next_page = True
        unregistered_slugs = []

        while next_page:
            url_slugs = (
                "/api/targets?"
                "filter%5Bprimary%5D=unregistered&"
                "filter%5Bsecondary%5D=all&"
                "filter%5Bcategory%5D=all&"
                "sorting%5Bfield%5D=dateUpdated&"
                "sorting%5Bdirection%5D=desc&"
                "pagination%5Bpage%5D=" + str(pageNum)
            )

            response = requests.get(
                platform_url + url_slugs,
                headers=headers,
                verify=False
            )

            jsonResponse = response.json()

            if len(jsonResponse) != 0:
                for item in jsonResponse:
                    if not isinstance(item, dict) or not item.get('slug'):
                        continue
                    if isExcludedTarget(item.get('codename')):
                        print(f"[register][excluded] Skipping {item.get('codename')}", flush=True)
                        continue
                    unregistered_slugs.append(str(item["slug"]))
                pageNum += 1
            else:
                next_page = False

        for slug in unregistered_slugs:
            url_register_slug = (
                platform_url +
                "/api/targets/" +
                slug +
                "/signup"
            )

            payload = {
                "ResearcherListing": {
                    "terms": 1
                }
            }

            print("Registering:", url_register_slug)

            try:
                response = requests.post(
                    url_register_slug,
                    headers=headers,
                    json=payload,
                    verify=False,
                    timeout=15
                )

                print(
                    f"Signup response for {slug}: "
                    f"{response.status_code} {response.text}"
                )

            except Exception as e:
                print(f"Signup request failed for {slug}: {e}")

        # Refresh the registered target list after signup attempts.
        getAllTargets(context)

        for slug in unregistered_slugs:
            codename = getCodenameFromSlug(context, slug)

            if codename is None:
                log(
                    "Signup attempted but target is not present "
                    "in registered_summary: " + slug
                )
            else:
                log("Successfully registered "+str(codename))


def connectToTarget(codename):
    if isExcludedTarget(codename):
        raise ValueError(f"Target {codename} is excluded by {EXCLUDED_TARGETS_ENV_NAME}")
    slug = getTargetID(context,codename)
    url_launchpoint = "/api/launchpoint"
    data = {"listing_id":slug}
    response = requests.put(platform_url+url_launchpoint,headers=headers,verify=False, data=data)
    time.sleep(3)
    return response.status_code


def getCurrentTargetSlug():
    url_launchpoint = "/api/launchpoint"
    response = requests.get(platform_url+url_launchpoint,headers=headers,verify=False)
    try:
        jsonResponse = response.json()
    except:
        return(1)
    if jsonResponse['slug']:
        return(jsonResponse['slug'])



def reverseResolveIP(ip_address):
    """
    Attempt reverse DNS (PTR) resolution for a scoped IP.

    Returns a normalized hostname without a trailing dot, or None if the
    address is invalid or no PTR record can be resolved.
    """
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return None

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip_address)
    except (socket.herror, socket.gaierror, OSError):
        return None

    hostname = str(hostname or "").strip().rstrip(".").lower()

    if not hostname:
        return None

    return hostname

# Host-target TLS virtual-host discovery. All active probes connect only to
# the originally scoped IP; candidate names are never appended to Nuclei scope.
MAX_VHOST_PROBES_PER_IP = 100
MAX_CHAOS_SUBDOMAINS_PER_DOMAIN = 2000
VHOST_PROBE_TIMEOUT = 5

# Only this run's httpx-confirmed IPs may contribute vhosts to Nuclei.
# Do not use previously stored vhost observations for an IP that failed
# the current precheck.
VHOST_LIVE_HTTPS_IPS = {}
# Run-local eligible host/IP pairs. Never reuse stale rows from a past scan.
VHOST_CURRENT_ELIGIBLE = {}
VHOST_DISCOVERY_STATS = {}


def findHttps443IPs(codename, addresses):
    """Batch HTTPS-only HTTP checks against scoped IPs before TLS discovery.

    An HTTP response on https://IP:443 qualifies the IP for certificate
    discovery; plain HTTP on 443 or HTTPS on other ports does not.
    All probes are to the original IP and do not follow redirects.
    """
    ips = set()
    for value in addresses:
        try:
            ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    if not ips:
        return set()
    ordered = sorted(ips)
    cmd = [
        'httpx', '-json', '-silent', '-no-color',
        '-nfs',                  # never fall back from HTTPS to HTTP
        '-t', '30', '-rl', '10', '-timeout', '3', '-retries', '0',
    ]
    inputs = '\n'.join(f'https://[{ip}]:443' if ':' in ip else f'https://{ip}:443' for ip in ordered) + '\n'
    print(f'[{codename}][httpx][443] Checking HTTPS for {len(ordered)} scoped IP(s)...', flush=True)
    try:
        result = subprocess.run(
            cmd, input=inputs, capture_output=True, text=True,
            timeout=max(45, min(180, len(ordered) * 4))
        )
    except FileNotFoundError:
        print(f'[{codename}][httpx][443] httpx executable missing; skipping SAN/CN discovery', flush=True)
        return set()
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f'[{codename}][httpx][443] Precheck failed: {type(exc).__name__}: {exc}; skipping SAN/CN discovery', flush=True)
        return set()
    if result.returncode != 0:
        print(f'[{codename}][httpx][443] Exit {result.returncode}: {result.stderr[-350:].strip()}; skipping discovery', flush=True)
        return set()
    passed = set()
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
            url = urlsplit(str(row.get('url') or ''))
            host = str(ipaddress.ip_address(url.hostname or ''))
            status = int(row.get('status_code') or 0)
            if url.scheme == 'https' and url.port in (None, 443) and host in ips and 100 <= status <= 599:
                passed.add(host)
        except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
            continue
    print(f'[{codename}][httpx][443] HTTPS responsive: {len(passed)}/{len(ordered)}; '
          f'skipping {len(ordered) - len(passed)} unreachable IP(s)', flush=True)
    return passed


def validDnsName(name):
    name = str(name or "").strip().rstrip(".").lower()
    if len(name) > 253 or not name or "*" in name:
        return None
    labels = name.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return name


def getCertificateDnsNames(ip_address):
    """Collect DNS SANs and DNS CNs from the *default* TLS certificate on IP:443.

    Does not rely on certificate validity or require a hostname to negotiate TLS.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip_address, 443), timeout=VHOST_PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock) as tls:
                cert_bytes = tls.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_bytes)
        names = set()
        try:
            names.update(cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        names.update(attr.value for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
        output = set()
        wildcards = set()
        for name in names:
            name = str(name).lower().strip().rstrip('.')
            if name.startswith('*.'):
                suffix = validDnsName(name[2:])
                if suffix:
                    wildcards.add(suffix)
            else:
                validated = validDnsName(name)
                if validated:
                    output.add(validated)
        return sorted(output), sorted(wildcards)
    except Exception as exc:
        print(f"[tls] {ip_address}:443 certificate unavailable: {type(exc).__name__}: {exc}", flush=True)
        return [], []


def chaosSubdomains(domain):
    """Use the documented Chaos API. Only return concrete DNS names."""
    # Chaos API credentials are managed exclusively by SynackScan's env file.
    key = (loadEnvFile().get('PDCP_API_KEY') or '').strip()
    if not key:
        print(f"[chaos] skipping {domain}: PDCP_API_KEY not configured", flush=True)
        return []
    try:
        resp = requests.get(
            f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
            headers={'Authorization': key}, timeout=12
        )
        resp.raise_for_status()
        data = resp.json()
        names = set()
        for value in (data.get('subdomains') or [])[:MAX_CHAOS_SUBDOMAINS_PER_DOMAIN]:
            if not isinstance(value, str):
                continue
            name = value.strip().lower().rstrip('.')
            if not name or '*' in name:
                continue
            if not name.endswith('.' + domain):
                name += '.' + domain
            name = validDnsName(name)
            if name:
                names.add(name)
        return sorted(names)
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        print(f"[chaos] {domain}: {type(exc).__name__}: {exc}", flush=True)
        return []


def matchesWildcard(hostname, domain):
    """A certificate *.example.com only matches one label beneath example.com."""
    if not hostname.endswith('.' + domain):
        return False
    prefix = hostname[:-(len(domain) + 1)]
    return bool(prefix) and '.' not in prefix


def probeHostOnScopedIP(ip_address, hostname):
    """Pin TCP to scoped IP while using candidate hostname for TLS SNI and HTTP Host."""
    pool = urllib3.HTTPSConnectionPool(
        ip_address, port=443, server_hostname=hostname,
        cert_reqs=ssl.CERT_NONE, assert_hostname=False,
        timeout=urllib3.Timeout(connect=VHOST_PROBE_TIMEOUT, read=VHOST_PROBE_TIMEOUT),
        retries=False, maxsize=1, block=True
    )
    try:
        response = pool.request(
            'GET', '/', headers={'Host': hostname, 'User-Agent': 'SynackScan-vhost-check/1.0'},
            assert_same_host=False, redirect=False, preload_content=False
        )
        try:
            status = response.status
            location = response.headers.get('Location', '')[:200]
            server = response.headers.get('Server', '')[:100]
            # Do not follow redirect or download full response bodies.
            return {'status_code': status, 'location': location, 'server': server}
        finally:
            response.release_conn()
    except (urllib3.exceptions.HTTPError, OSError, ValueError) as exc:
        return {'error': f'{type(exc).__name__}: {str(exc)[:100]}'}
    finally:
        pool.close()


def discoverScopedIPVhosts(codename, ip_address):
    """Certificate SAN/CN + Chaos wildcard discovery; only test on the scoped IP."""
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return
    names, wildcard_domains = getCertificateDnsNames(ip_address)
    print(f"[{codename}][tls] {ip_address}:443 SAN/CN={len(names)} wildcard={len(wildcard_domains)}", flush=True)
    for domain in wildcard_domains:
        db.store_vhost_observation(codename, ip_address, '*.' + domain,
                                   'certificate-wildcard', {})
    candidates = set(names)
    candidate_sources = {name: 'certificate' for name in names}
    for domain in wildcard_domains:
        results = chaosSubdomains(domain)
        matched = [name for name in results if matchesWildcard(name, domain)]
        candidates.update(matched)
        for hostname in matched:
            candidate_sources.setdefault(hostname, 'chaos-wildcard')
        print(f"[{codename}][chaos] *.{domain}: {len(results)} discovered; "
              f"{len(matched)} single-label wildcard matches", flush=True)
    # Baseline only once per scoped IP, using identical SNI/Host settings and
    # the same HTTP method, path, and TLS pinning as candidate probes.
    baseline_name = 'doesnotexist.target.tld'
    baseline = probeHostOnScopedIP(ip_address, baseline_name)
    baseline_status = baseline.get('status_code')
    if baseline_status is None:
        print(f"[{codename}][vhost] {ip_address}:443 baseline "
              f"{baseline_name} failed: {baseline.get('error')}; "
              "candidate vhosts will not be scanned", flush=True)
    else:
        print(f"[{codename}][vhost] {ip_address}:443 baseline "
              f"{baseline_name} HTTP {baseline_status}", flush=True)

    stats = {'tested': 0, 'baseline_matches': 0, 'different_status': 0,
             'connection_errors': 0, 'eligible': 0, 'capped': max(0, len(candidates) - MAX_VHOST_PROBES_PER_IP)}
    for hostname in sorted(candidates)[:MAX_VHOST_PROBES_PER_IP]:
        stats['tested'] += 1
        observation = probeHostOnScopedIP(ip_address, hostname)
        status = observation.get('status_code')
        # Require both probes to have valid HTTP responses and distinct statuses.
        # All observations are retained, but only distinct candidates enter Nuclei.
        is_distinct = baseline_status is not None and status is not None and status != baseline_status
        observation['baseline_status_code'] = baseline_status
        observation['is_distinct'] = bool(is_distinct)
        if status is None:
            stats['connection_errors'] += 1
        elif baseline_status is not None and status == baseline_status:
            stats['baseline_matches'] += 1
        elif is_distinct:
            stats['different_status'] += 1
            stats['eligible'] += 1
            VHOST_CURRENT_ELIGIBLE.setdefault(codename, set()).add((ip_address, hostname))
        db.store_vhost_observation(
            codename, ip_address, hostname, candidate_sources[hostname], observation
        )
        if status is not None:
            verdict = 'ELIGIBLE' if is_distinct else 'SKIP (baseline match/unavailable)'
            print(f"[{codename}][vhost] {ip_address}:443 SNI/Host={hostname} "
                  f"HTTP {status} baseline={baseline_status} {verdict} "
                  f"Location={observation['location']!r}", flush=True)
        else:
            print(f"[{codename}][vhost] {ip_address}:443 SNI/Host={hostname} "
                  f"{observation.get('error')} SKIP", flush=True)
    if len(candidates) > MAX_VHOST_PROBES_PER_IP:
        print(f"[{codename}][vhost] capped to {MAX_VHOST_PROBES_PER_IP} "
              f"of {len(candidates)} candidates", flush=True)
    total = VHOST_DISCOVERY_STATS.setdefault(codename, {
        'tested': 0, 'baseline_matches': 0, 'different_status': 0,
        'connection_errors': 0, 'eligible': 0, 'capped': 0
    })
    for key, value in stats.items():
        total[key] += value
    print(f"[{codename}][vhost][summary] {ip_address}:443 tested={stats['tested']} "
          f"baseline_matches={stats['baseline_matches']} different_status={stats['different_status']} "
          f"errors={stats['connection_errors']} eligible={stats['eligible']} capped={stats['capped']}",
          flush=True)


def getScope(context, codename, discover_hosts=True):
    target = getTargetInfo(context, codename)

    if target is None:
        print(f"[{codename}] Unable to find target metadata.")
        return []

    ttype = ""

    try:
        category_name = target['category']['name'].lower()
    except (KeyError, TypeError, AttributeError):
        print(f"[{codename}] Target category is missing or invalid.")
        return []

    if category_name == "host":
        ttype = "host"

    if category_name == "web application":
        ttype = "webapp"

    url_scope = (
        "/api/asset/v2/assets?"
        "listingUid%5B%5D=" + target['id'] +
        "&organizationUid%5B%5D=" + target['organization_id'] +
        "&assetType%5B%5D=" + ttype +
        "&active=true&sort=location&sortDir=asc&page=1&perPage=500"
    )

    try:
        response = requests.get(
            platform_url + url_scope,
            headers=headers,
            verify=False,
            timeout=15
        )
    except Exception as e:
        print(f"[{codename}] Scope request failed: {e}")
        return []

    if response.status_code != 200:
        print(
            f"[{codename}] Scope request returned HTTP "
            f"{response.status_code}: {response.text[:300]}"
        )
        return []

    try:
        scopedata = response.json()
    except Exception:
        print(
            f"[{codename}] Scope response was not valid JSON: "
            f"{response.text[:300]}"
        )
        return []

    if not isinstance(scopedata, list):
        print(
            f"[{codename}] Unexpected scope response type "
            f"{type(scopedata).__name__}: {str(scopedata)[:300]}"
        )
        return []

    scope = []
    seen = set()
    host_ip_candidates = set()
    # Reset run-local eligibility even if the scope query has no usable hosts.
    VHOST_LIVE_HTTPS_IPS[codename] = set()
    VHOST_CURRENT_ELIGIBLE[codename] = set()
    VHOST_DISCOVERY_STATS[codename] = {
        'tested': 0, 'baseline_matches': 0, 'different_status': 0,
        'connection_errors': 0, 'eligible': 0, 'capped': 0
    }

    def add_scope_value(value, asset_type):
        value = str(value or "").strip()

        if not value or value in seen:
            return

        scope.append(value)
        seen.add(value)
        db.upsert_asset(codename, value, asset_type)

    for asset in scopedata:
        if not isinstance(asset, dict):
            print(
                f"[{codename}] Skipping unexpected scope item: "
                f"{str(asset)[:200]}"
            )
            continue

        host = asset.get("host")

        if isinstance(host, dict):
            ip_address = host.get("ipAddress")

            if ip_address:
                ip_address = str(ip_address).strip()

                add_scope_value(ip_address, "host-ip")

                if category_name == "host" and discover_hosts:
                    resolved_hostname = reverseResolveIP(ip_address)

                    if resolved_hostname:
                        add_scope_value(
                            resolved_hostname,
                            "host-rdns"
                        )

                        print(
                            f"[{codename}][resolve] "
                            f"{ip_address} -> {resolved_hostname}",
                            flush=True
                        )

                    # Defer TLS work until a single batched httpx HTTPS precheck.
                    try:
                        host_ip_candidates.add(str(ipaddress.ip_address(ip_address)))
                    except ValueError:
                        pass

        webapp = asset.get("webApplication")

        if isinstance(webapp, dict):
            url = webapp.get("url")

            if url:
                add_scope_value(url, "webapp")

    if category_name == 'host' and discover_hosts and host_ip_candidates:
        responsive = findHttps443IPs(codename, host_ip_candidates)
        VHOST_LIVE_HTTPS_IPS[codename] = responsive
        for scoped_ip in sorted(responsive):
            discoverScopedIPVhosts(codename, scoped_ip)

    folder_path = (
        "/home/AMBERJACK/8pm493i9kc/"
        "automation/bulkcommand/data/" + codename
    )
    os.makedirs(folder_path, exist_ok=True)

    with open(os.path.join(folder_path, "scope.txt"), "w") as f:
        for key in scope:
            f.write(f"{key}\n")

    return scope


def checkWebappPath(target,path,matcher):
    try:
        headers = {"User-Agent": "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0"}
        response = requests.get(target+path,verify=False,headers=headers, timeout=5)

        if matcher in response.text:
            return True
        else:
            return False
    except:
        return False


def runHttpxFingerprint(codename, scope):
    """
    Run one httpx process against the complete current target scope.

    Stores HTTP metadata and httpx-reported technologies in SQLite.
    Output is machine-readable JSON and is not written as an intermediate
    file.
    """
    if not scope:
        return

    cmd = [
        "httpx",
        "-json",
        "-silent",
        "-td",  # Populate JSON `tech` with Wappalyzer fingerprints.
        "-rl", "10"
    ]

    print(
        f"[{codename}][fingerprint] Running httpx against "
        f"{len(scope)} scoped asset(s)...",
        flush=True
    )

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        if proc.stdin:
            proc.stdin.write("\n".join(scope) + "\n")
            proc.stdin.close()

        if proc.stdout:
            for line in proc.stdout:
                line = line.strip()

                if not line:
                    continue

                try:
                    observation = json.loads(line)
                except json.JSONDecodeError:
                    continue

                db.store_http_observation(codename, observation)

                scan_target = (
                    observation.get("url")
                    or observation.get("input")
                    or ""
                )

                for technology in observation.get("tech", []) or []:
                    db.store_technology(
                        codename=codename,
                        asset=scan_target,
                        technology=str(technology),
                        source="httpx",
                        detector=str(technology),
                        tags=[],
                    )

                print(
                    f"[{codename}][httpx] "
                    f"{observation.get('status_code', '-')} "
                    f"{observation.get('url') or observation.get('input')}",
                    flush=True
                )

        stderr = proc.stderr.read().strip() if proc.stderr else ""
        returncode = proc.wait()

        if returncode != 0:
            print(
                f"[{codename}][httpx][debug] "
                f"httpx exited with status {returncode}",
                flush=True
            )

            if stderr:
                for line in stderr.splitlines()[-10:]:
                    print(
                        f"[{codename}][httpx][debug] {line.strip()}",
                        flush=True
                    )

    except FileNotFoundError:
        print(
            f"[{codename}][httpx] httpx executable not found in PATH.",
            flush=True
        )

    except Exception as e:
        print(
            f"[{codename}][httpx][debug] Error running httpx: {e}",
            flush=True
        )


def parseNucleiTechnologyFinding(finding, available_tags):
    """Recognize both generic named matchers and standalone technology templates.

    Generic tech-detect findings identify the product through matcher-name;
    standalone *-detect templates usually have no named matcher, so use their
    human-readable info.name and keep the template ID as detector provenance.
    """
    if not isinstance(finding, dict):
        return None
    scan_target = normalizeDetectedTarget(finding)
    if not scan_target:
        return None
    matcher = str(finding.get('matcher-name') or finding.get('matcher_name') or '').strip()
    template_id = str(finding.get('template-id') or finding.get('templateID') or '').strip()
    info = finding.get('info') if isinstance(finding.get('info'), dict) else {}
    if matcher:
        technology = matcher
        source = 'nuclei-tech-detect'
        detector = matcher
    elif template_id:
        technology = str(info.get('name') or template_id).strip()
        # Display product names without the generic " - Detect" suffix.
        technology = re.sub(r'\s*[-–:]\s*Detect(?:ion)?\s*$', '', technology, flags=re.I).strip()
        source = 'nuclei-technology-template'
        detector = template_id
    else:
        return None
    tags = resolveTechTags(matcher or template_id, available_tags)
    return scan_target, technology, source, detector, tags


def storeTechDetectionForFingerprint(codename, finding, available_tags):
    """Store all matched Nuclei technology detections, including no-matcher templates."""
    parsed = parseNucleiTechnologyFinding(finding, available_tags)
    if parsed is None:
        return None
    scan_target, technology, source, detector, tags = parsed
    technology_id = db.store_technology(codename=codename, asset=scan_target,
                                        technology=technology, source=source,
                                        detector=detector, tags=tags)
    if technology_id is None:
        raise RuntimeError(f'Technology persistence failed for {detector} @ {scan_target}')
    print(f'[{codename}][tech][stored][{source}] {technology} '
          f'({detector}) @ {scan_target}', flush=True)
    return parsed


def fingerprint(codename,target,path):
    folder_path = "/home/AMBERJACK/8pm493i9kc/automation/bulkcommand/data/"+codename
    os.makedirs(folder_path, exist_ok=True)
    folder_path = "/home/AMBERJACK/8pm493i9kc/automation/bulkcommand/data/"+codename+"/content"
    os.makedirs(folder_path, exist_ok=True)
    folder_path = "/home/AMBERJACK/8pm493i9kc/automation/bulkcommand/data/"+codename+"/headers"
    os.makedirs(folder_path, exist_ok=True)

    if "://" not in target:
        target = "https://"+target+"/"
    target = target.replace("http://", "https://")
    target = target+path

    filename = target.replace("https://", "").replace(".", "_").replace("/", "-").replace("?", "+").replace("*", "")

    try:
        response = requests.get(target,verify=False, timeout=5)
        with open("/home/AMBERJACK/8pm493i9kc/automation/bulkcommand/data/"+codename+"/headers/"+filename, "w") as f:
            for key, value in response.headers.items():
                f.write(f"{key}: {value}\n")
        with open("/home/AMBERJACK/8pm493i9kc/automation/bulkcommand/data/"+codename+"/content/"+filename, "w") as f:
            f.write(response.text)
    except:
        pass


def doFingerprint(context, target_filter=None, batch_size=None):
    """
    Full collection/indexing pass.

    Per eligible Host/Web Application target:
      - connect and verify Synack launchpoint
      - retrieve/expand scope (including Host reverse DNS)
      - save raw HTTP headers and response bodies to disk
      - run batched httpx and store metadata + httpx technologies
      - run batched Nuclei tech-detect and store fingerprints/tags

    This does not run smartscan follow-on vulnerability templates.
    """
    available_tags = getAvailableNucleiTags()

    selected = [
        target for target in context.get('targetlist', [])
        if isinstance(target, dict)
        and ((target.get('category') or {}).get('name') or '').strip().lower()
        in ('host', 'web application')
        and target.get('codename')
        and (not target_filter or str(target['codename']).casefold() == target_filter.casefold())
    ]
    if target_filter and not selected:
        print(f'[fingerprint] No matching eligible target: {target_filter}', flush=True)
        return
    total = len(selected)
    print(f'[fingerprint] Processing {total} target(s)', flush=True)

    for position, target in enumerate(selected, start=1):
        codename = target['codename']
        target_started_at = time.perf_counter()
        try:

            if not checkLoginStatus():
                print("Synack authentication is no longer valid.", flush=True)
                return

            print(
                f"[{position}/{total}][{codename}] Connecting to Synack target...",
                flush=True
            )

            connect_status = connectToTarget(codename)

            if connect_status < 200 or connect_status >= 300:
                print(
                    f"[{codename}] Failed to connect to target "
                    f"(HTTP {connect_status})",
                    flush=True
                )
                continue

            cslug = getCurrentTargetSlug()

            if cslug == 1:
                print(
                    f"[{codename}] Unable to determine current target.",
                    flush=True
                )
                continue

            cname = getCodenameFromSlug(context, cslug)

            if cname != codename:
                print(
                    f"[{codename}] Target switch verification failed "
                    f"(current target: {cname})",
                    flush=True
                )
                continue

            print(f"[{codename}] Connected.", flush=True)

            scope = getScope(context, codename)

            if not scope:
                continue

            # Preserve existing raw body/header collection.
            print(
                f"[{codename}][fingerprint] Saving raw content for "
                f"{len(scope)} scoped asset(s)...",
                flush=True
            )

            for asset in scope:
                fingerprint(codename, asset, "")

            # Structured HTTP metadata + httpx technology fingerprints.
            runHttpxFingerprint(codename, scope)

            # All informational Nuclei technology fingerprints, no follow-on templates.
            print(
                f"[{codename}][fingerprint] Running all Nuclei technology detection templates...",
                flush=True
            )

            def on_tech_finding(finding):
                storeTechDetectionForFingerprint(
                    codename,
                    finding,
                    available_tags
                )

            tech_results = runTechDetect(scope, on_finding=on_tech_finding, batch_size=batch_size)
            if tech_results is None:
                print(f'[{codename}][fingerprint][WARNING] Nuclei tech detection '
                      'failed for one or more assets; see diagnostics above', flush=True)
            else:
                print(f'[{codename}][fingerprint][summary] '
                      f'Nuclei technology matches={len(tech_results)}', flush=True)
        finally:
            print(f"[{position}/{total}][{codename}] Scan elapsed: {time.perf_counter() - target_started_at:.2f} seconds", flush=True)


def doScan(context,filter,path,matcher):
    for target in context['targetlist']:
        passthru = 0
        if target['codename'] == filter:
            passthru = 1
        if filter == "all":
            passthru = 1

        if passthru ==1:
            status = checkLoginStatus()
            if status:
                connectToTarget(target['codename'])
                cslug = getCurrentTargetSlug()
                cname = getCodenameFromSlug(context,cslug)
                if cname == target['codename']:
                    scope = getScope(context,target['codename'])
                    log("Starting "+target['codename'])
                    for s in scope:
                        if "://" not in s:
                            s = "https://"+s+"/"
                        s = s.replace("http://", "https://")
                        #log("  trying "+s+path)
                        status = checkWebappPath(s,path,matcher)
                        if status:
                            print(target['codename']+" found "+s)


def doShellCommand(context,command):
    for target in context['targetlist']:
        status = checkLoginStatus()
        if status:
            connectToTarget(target['codename'])
            cslug = getCurrentTargetSlug()
            cname = getCodenameFromSlug(context,cslug)
            if cname == target['codename']:
                scope = getScope(context,target['codename'])
                log("Starting "+target['codename'])
                for s in scope:
                    os.system(command+" "+s)


def _streamNucleiFindings(cmd, scope, codename, vhost=None):
    """Run Nuclei once and persist its JSONL findings without losing hostname context."""
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE if scope is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        if scope is not None and proc.stdin:
            proc.stdin.write("\n".join(scope) + "\n")
            proc.stdin.close()
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(finding, dict):
                continue
            if vhost is None:
                new = db.store_bot_finding(codename, finding)
                if new:
                    print(f"[{codename}][nuclei] "
                          f"{finding.get('template-id', '-')}: "
                          f"{finding.get('matched-at', finding.get('host', '-'))}", flush=True)
            else:
                ip, hostname = vhost
                new = db.store_vhost_nuclei_finding(codename, ip, hostname, finding)
                if new:
                    print(f"[{codename}][nuclei][vhost] {hostname} @ {ip}:443 "
                          f"{finding.get('template-id', '-')}: "
                          f"{finding.get('matched-at', finding.get('host', '-'))}", flush=True)
        stderr = proc.stderr.read().strip() if proc.stderr else ''
        code = proc.wait()
        if code != 0:
            print(f"[{codename}][nuclei] Exit {code} "
                  f"{('vhost='+vhost[1]) if vhost else 'original-scope'}", flush=True)
            if stderr:
                print(f"[{codename}][nuclei][debug] " + " | ".join(stderr.splitlines()[-4:])[:600], flush=True)
        return code == 0
    except FileNotFoundError:
        print("nuclei executable not found in PATH", flush=True)
        return False
    except (OSError, ValueError) as exc:
        print(f"[{codename}][nuclei] {type(exc).__name__}: {exc}", flush=True)
        return False


def runNucleiTemplate(context, template_path, category_filter="all", nuclei_kind="auto", target_filter=None, skip_existing_discovery=False):
    """Scan current scope and, for Host targets, eligible IP-pinned vhosts.

    --skip-discovery suppresses PTR/TLS/Chaos and candidate probing, instead
    loading previously qualified IP/hostname pairs from the fingerprint DB.
    Every pair must still belong to an IP in the current Synack scope.
    """
    template_path = os.path.expanduser(template_path)
    if nuclei_kind not in {"auto", "template", "workflow"}:
        raise ValueError(f"Invalid Nuclei input kind: {nuclei_kind}")
    if not os.path.isfile(template_path):
        print(f"Template not found: {template_path}", flush=True)
        return
    if nuclei_kind == "auto":
        try:
            yaml_text = Path(template_path).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            print(f"Unable to read Nuclei file: {exc}", flush=True)
            return
        nuclei_kind = "workflow" if re.search(r"(?m)^workflows\s*:", yaml_text) else "template"
    nuclei_flag = "-w" if nuclei_kind == "workflow" else "-t"
    if category_filter not in {"all", "host", "web"}:
        raise ValueError(f"Invalid category: {category_filter}")
    selected = []
    for target in context.get('targetlist', []):
        if target_filter and str(target.get('codename', '')).casefold() != target_filter.casefold():
            continue
        category = ((target.get('category') or {}).get('name') or '').strip().lower()
        if category_filter == 'host' and category != 'host':
            continue
        if category_filter == 'web' and category != 'web application':
            continue
        selected.append(target)
    if target_filter and not selected:
        print(f"[nuclei] No matching target: {target_filter} (category={category_filter})", flush=True)
        return
    print(f"[nuclei] {nuclei_kind}; category={category_filter}; targets={len(selected)}", flush=True)
    base_cmd = ['nuclei', nuclei_flag, template_path,
                *nucleiScanArgs(), '-iserver', nuclei_iserver, '-silent', '-nc', '-jsonl', '-dr']
    for position, target in enumerate(selected, start=1):
        if not checkLoginStatus():
            print('Synack authentication is no longer valid.', flush=True)
            return
        codename = target['codename']
        target_started_at = time.perf_counter()
        try:
            print(f"[{position}/{len(selected)}][{codename}] Connecting to Synack target...", flush=True)
            try:
                connect_status = connectToTarget(codename)
            except requests.RequestException as exc:
                print(f"[{codename}] Launchpoint request failed: {type(exc).__name__}: {exc}", flush=True)
                continue
            print(f"[{codename}] Launchpoint HTTP {connect_status}", flush=True)
            if not 200 <= connect_status < 300:
                print(f"[{codename}] Connection failed (HTTP {connect_status})", flush=True)
                continue
            try:
                cslug = getCurrentTargetSlug()
            except requests.RequestException as exc:
                print(f"[{codename}] Launchpoint verification request failed: {type(exc).__name__}: {exc}", flush=True)
                continue
            cname = getCodenameFromSlug(context, cslug) if cslug != 1 else None
            if cname != codename:
                print(f"[{codename}] Target switch verification failed (expected={codename}, current={cname}, slug={cslug})", flush=True)
                continue
            print(f"[{codename}] Connected. Verified launchpoint: {cslug}", flush=True)
            category = ((target.get('category') or {}).get('name') or '').strip().lower()
            skip_discovery = skip_existing_discovery and category == 'host'
            if skip_discovery:
                print(f"[{codename}][vhost] Discovery disabled; using saved SQLite vhosts "
                      "with current Synack IP scope.", flush=True)
            try:
                scope = getScope(context, codename, discover_hosts=not skip_discovery)
            except requests.RequestException as exc:
                print(f"[{codename}] Scope retrieval failed: {type(exc).__name__}: {exc}", flush=True)
                continue
            if not scope:
                print(f"[{codename}] No active scoped assets returned; skipping Nuclei.", flush=True)
                continue
            # Zero vhost matches is a completed discovery too. Persist the marker.
            if category == 'host' and not skip_discovery:
                db.mark_host_discovery_completed(codename)
            print(f"[{codename}] Scope loaded: {len(scope)} assets. Starting Nuclei.", flush=True)
            stats = VHOST_DISCOVERY_STATS.get(codename)
            if not skip_discovery and stats is not None and category == 'host':
                print(f"[{codename}][vhost] Discovery complete: candidates_tested={stats['tested']} "
                      f"baseline_matches={stats['baseline_matches']} different_status={stats['different_status']} "
                      f"connection_errors={stats['connection_errors']} "
                      f"eligible_for_nuclei={len(VHOST_CURRENT_ELIGIBLE.get(codename, set()))} "
                      f"capped={stats['capped']}", flush=True)
            _streamNucleiFindings(base_cmd, scope, codename)
            category = ((target.get('category') or {}).get('name') or '').strip().lower()
            if category != 'host':
                continue
            authorized_ips = set()
            for asset in scope:
                try:
                    authorized_ips.add(str(ipaddress.ip_address(asset)))
                except ValueError:
                    continue
            # Keep all connections pinned to IPs in the CURRENT Synack scope.
            # With --skip-discovery, reuse qualified vhost observations from
            # fingerprint; never run Chaos, PTR, certificate or baseline probes.
            rows = db.get_vhosts_for_nuclei(codename)
            seen = set()
            approved = VHOST_CURRENT_ELIGIBLE.get(codename, set())
            accepted_pairs = []
            for row in rows:
                ip = row['ip']
                hostname = row['hostname']
                if ip not in authorized_ips or (ip, hostname) in seen:
                    continue
                # Normal mode only uses pairs validated THIS run. Cached mode
                # intentionally reuses previously qualified DB pairs.
                if not skip_discovery and (
                        ip not in VHOST_LIVE_HTTPS_IPS.get(codename, set()) or
                        (ip, hostname) not in approved):
                    continue
                if not validDnsName(hostname) or hostname.startswith('*.'):
                    continue
                seen.add((ip, hostname))
                accepted_pairs.append((ip, hostname))
            source = 'saved SQLite observations' if skip_discovery else 'current discovery'
            print(f"[{codename}][nuclei][vhost] Accepted pairs from {source}: "
                  f"{len(accepted_pairs)}", flush=True)
            if skip_discovery and not accepted_pairs:
                print(f"[{codename}][nuclei][vhost] No qualifying saved vhosts for "
                      "current scoped IPs. Original scoped assets were scanned.", flush=True)
            for ip, hostname in sorted(accepted_pairs):
                print(f"[{codename}][nuclei][vhost][accepted] {ip}:443 SNI/Host={hostname}", flush=True)
            for ip, hostname in sorted(accepted_pairs):
                print(f"[{codename}][nuclei][vhost] scanning {hostname} @ {ip}:443", flush=True)
                vhost_cmd = base_cmd + [
                    '-u', f'https://{ip}', '-sni', hostname, '-H', f'Host: {hostname}', '-nh'
                ]
                _streamNucleiFindings(vhost_cmd, None, codename, vhost=(ip, hostname))

        finally:
            print(f"[{position}/{len(selected)}][{codename}] Scan elapsed: {time.perf_counter() - target_started_at:.2f} seconds", flush=True)

# Run every informational technology template under this directory.
TECH_DETECT_DIRECTORY = os.path.expanduser('~/nuclei-templates/http/technologies')


# Explicit mappings for detector names that do not match the most useful
# Nuclei template tag directly.
TECH_TAG_ALIASES = {
    "atlassian-jira": ["jira"],
    "atlassian-confluence": ["confluence"],
    "microsoft-sharepoint": ["sharepoint"],
    "microsoft-iis": ["iis"],
    "wordpress": ["wordpress"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "jenkins": ["jenkins"],
    "grafana": ["grafana"],
    "gitlab": ["gitlab"],
    "sonarqube": ["sonarqube"],
    "nexus-repository-manager": ["nexus"],
    "apache-tomcat": ["tomcat"],
    "tomcat": ["tomcat"],
    "jboss": ["jboss"],
    "wildfly": ["wildfly"],
    "spring-boot": ["springboot", "spring-boot"],
    "phpmyadmin": ["phpmyadmin"],
    "roundcube": ["roundcube"],
    "zabbix": ["zabbix"],
    "nagios": ["nagios"],
    "fortinet-fortigate": ["fortinet", "fortigate"],
    "palo-alto-networks": ["paloalto"],
    "citrix-netscaler": ["citrix", "netscaler"],
    "vmware-vcenter": ["vcenter", "vmware"],
    "vmware-esxi": ["esxi", "vmware"],
    "kibana": ["kibana"],
    "elasticsearch": ["elasticsearch"],
    "apache-solr": ["solr"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "postgresql": ["postgresql"],
    "mysql": ["mysql"],
}

# Prefixes which are commonly vendor qualifiers in tech-detect matcher names.
# For "atlassian-jira", for example, "jira" is generally the useful Nuclei tag.
TECH_VENDOR_PREFIXES = {
    "atlassian",
    "microsoft",
    "amazon",
    "aws",
    "apache",
    "oracle",
    "ibm",
    "adobe",
    "vmware",
    "cisco",
    "citrix",
    "fortinet",
    "jetbrains",
}


GENERIC_TECH_TAGS = {
    "api",
    "app",
    "application",
    "cloud",
    "css",
    "framework",
    "font",
    "http",
    "https",
    "js",
    "javascript",
    "library",
    "platform",
    "proxy",
    "server",
    "service",
    "services",
    "ui",
    "web",
}


def getAvailableNucleiTags():
    """
    Ask the installed Nuclei/templates for the currently available tags.

    Example Nuclei output:
        wordpress (956)
        jira (42)

    Returns a set containing just the tag names.
    """
    try:
        result = subprocess.run(
            ["nuclei", "-silent", "-iserver", nuclei_iserver, "-tgl"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except FileNotFoundError:
        print("nuclei executable not found in PATH.")
        return set()

    tags = set()

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        # Current Nuclei typically emits: "tag (count)".
        match = re.match(r"^([^\s]+)(?:\s+\(\d+\))?$", line)

        if match:
            tags.add(match.group(1).lower())

    return tags


def buildTechTagCandidates(matcher_name):
    """
    Build candidate Nuclei tags from a tech-detect matcher name.

    Examples:
        istio-envoy
            -> istio-envoy, istio, envoy

        atlassian-jira
            -> atlassian-jira, atlassian, jira

        apache-tomcat-manager
            -> apache-tomcat-manager
               apache, tomcat, manager
               apache-tomcat, tomcat-manager

    We split on common separators but keep dots inside tokens so values such
    as asp.net remain intact.
    """
    matcher = (matcher_name or "").strip().lower()

    if not matcher:
        return []

    candidates = []
    seen = set()

    def add(value):
        value = value.strip().lower()

        if value and value not in seen:
            candidates.append(value)
            seen.add(value)

    # Exact matcher always gets first priority.
    add(matcher)

    # Split on separators commonly used by tech-detect matcher names.
    parts = [
        p for p in re.split(r"[-_:]+", matcher)
        if p
    ]

    # Individual components.
    for part in parts:
        add(part)

    # Contiguous combinations, preserving '-' as the Nuclei tag separator.
    # For apache-tomcat-manager this tests:
    #   apache-tomcat
    #   tomcat-manager
    # as well as the exact full matcher above.
    if len(parts) > 1:
        for width in range(2, len(parts)):
            for start_index in range(0, len(parts) - width + 1):
                add("-".join(parts[start_index:start_index + width]))

    # Existing explicit aliases remain useful for names that cannot be derived
    # mechanically.
    for alias in TECH_TAG_ALIASES.get(matcher, []):
        add(alias)

    return candidates


def resolveTechTags(matcher_name, available_tags):
    """
    Resolve a tech-detect matcher to locally available Nuclei tags.

    Rules:
      1. Generate exact/split/compound candidates.
      2. Keep only tags that actually exist in the local Nuclei library.
      3. Reject generic tags that would cause overly broad/unrelated scans.
      4. Return all remaining useful candidates in priority order.

    Actual runnable-template validation still happens later via
    `nuclei -tags <tag> -tl`.
    """
    available_tags = {
        str(tag).strip().lower()
        for tag in available_tags
        if str(tag).strip()
    }

    resolved = []

    for candidate in buildTechTagCandidates(matcher_name):
        if candidate in GENERIC_TECH_TAGS:
            continue

        if candidate not in available_tags:
            continue

        if candidate not in resolved:
            resolved.append(candidate)

    return resolved


def normalizeDetectedTarget(finding):
    """
    Prefer Nuclei's matched URL and normalize it to scheme://host[:port].

    This gives follow-up template scans a proper HTTP(S) target instead of
    feeding them a bare hostname from the JSON `host` field.

    Example:
        matched-at = https://help.naep.ed.gov/login.jsp
        returns    = https://help.naep.ed.gov
    """
    matched = (
        finding.get("matched-at")
        or finding.get("matched_at")
        or finding.get("url")
        or finding.get("input")
        or finding.get("host")
        or ""
    )

    matched = str(matched).strip()

    if not matched:
        return None

    if "://" in matched:
        try:
            parts = urlsplit(matched)

            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}"
        except Exception:
            pass

        return matched

    # If Nuclei only gave us a hostname/IP, default to HTTPS just like the
    # existing fingerprint flow.
    return "https://" + matched


def runTechDetect(scope, on_finding=None, batch_size=None):
    """Run all informational technology templates against the full scope by default.

    Optionally split into batches with fingerprint --batch-size N. Every JSONL
    match is logged and passed to the persistence callback. A failed batch is
    retried asset-by-asset for diagnostic visibility.
    """
    if not scope:
        return []
    if not os.path.isdir(TECH_DETECT_DIRECTORY):
        print(f'[tech-detect][error] Missing directory: {TECH_DETECT_DIRECTORY}', flush=True)
        return None

    import tempfile

    assets = list(dict.fromkeys(str(v).strip() for v in scope if str(v).strip()))
    if not assets:
        return []
    if batch_size is None:
        batch_size = len(assets)  # Default: one Nuclei process for the entire scope.
    if not isinstance(batch_size, int) or batch_size < 1:
        print(f'[tech-detect][error] Invalid batch size: {batch_size!r}', flush=True)
        return None

    batches = [assets[i:i + batch_size] for i in range(0, len(assets), batch_size)]
    findings = []
    completed = 0
    failed = 0
    total = len(assets)
    print(f'[tech-detect] Running informational technology templates: '
          f'assets={total}, batch_size={batch_size}, batches={len(batches)}', flush=True)

    def run_batch(batch, label):
        """Return True only when subprocess, parsing and persistence succeed."""
        nonlocal completed
        cmd = ['nuclei', '-t', TECH_DETECT_DIRECTORY, '-severity', 'info',
               *nucleiScanArgs(), '-iserver', nuclei_iserver, '-silent', '-jsonl', '-nc', '-dr']
        input_file_path = None
        matches = 0
        parse_errors = 0
        storage_errors = 0
        process = None
        try:
            # A real -l file avoids ambiguity around stdin/target parsing.
            # Use -u when only one asset is present, matching the known-good test.
            if len(batch) == 1:
                cmd += ['-u', batch[0]]
            else:
                with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                                 prefix='synackscan-nuclei-',
                                                 suffix='.txt', delete=False) as handle:
                    handle.write('\n'.join(batch) + '\n')
                    input_file_path = handle.name
                cmd += ['-l', input_file_path]

            print(f'[tech-detect][{label}] START assets={len(batch)} '
                  f'first={batch[0]}', flush=True)
            with tempfile.TemporaryFile(mode='w+t', encoding='utf-8') as errors:
                process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=errors,
                                           text=True, bufsize=1)
                for raw in process.stdout:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        if not isinstance(finding, dict):
                            raise ValueError('not a JSON object')
                    except (ValueError, TypeError) as exc:
                        parse_errors += 1
                        print(f'[tech-detect][{label}][parse-error] '
                              f'{type(exc).__name__}: {line[:160]}', flush=True)
                        continue
                    matches += 1
                    detector = finding.get('template-id') or finding.get('templateID') or '?'
                    matched = (finding.get('matched-at') or finding.get('matched_at')
                               or finding.get('host') or '?')
                    print(f'[tech-detect][{label}][MATCH] {detector} @ {matched}', flush=True)
                    try:
                        if on_finding is not None:
                            on_finding(finding)
                        findings.append(finding)
                    except Exception as exc:
                        storage_errors += 1
                        print(f'[tech-detect][{label}][storage-error] {detector}: '
                              f'{type(exc).__name__}: {exc}', flush=True)
                code = process.wait()
                errors.seek(0)
                stderr = errors.read().strip()
            ok = code == 0 and not parse_errors and not storage_errors
            if ok:
                completed += len(batch)
            print(f'[tech-detect][{label}][{"done" if ok else "FAILED"}] '
                  f'assets={len(batch)} matches={matches} exit={code} '
                  f'parse_errors={parse_errors} storage_errors={storage_errors}', flush=True)
            if not ok and stderr:
                print(f'[tech-detect][{label}][stderr] '
                      + ' | '.join(stderr.splitlines()[-8:])[-1600:], flush=True)
            return ok
        except (OSError, ValueError) as exc:
            print(f'[tech-detect][{label}][FAILED] '
                  f'{type(exc).__name__}: {exc}', flush=True)
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            return False
        finally:
            if input_file_path is not None:
                try:
                    os.unlink(input_file_path)
                except OSError:
                    pass

    for index, batch in enumerate(batches, 1):
        label = f'{index}/{len(batches)}'
        if run_batch(batch, label):
            continue
        if len(batch) == 1:
            failed += 1
            continue
        print(f'[tech-detect][{label}] Retrying failed batch per asset...', flush=True)
        for offset, asset in enumerate(batch, 1):
            if not run_batch([asset], f'{label}:retry-{offset}/{len(batch)}'):
                failed += 1

    print(f'[tech-detect][summary] assets={total} completed={completed} '
          f'failed={failed} findings={len(findings)}', flush=True)
    return None if failed else findings


def getTemplatesForTag(tag):
    """
    Return the list of templates Nuclei would select for a given tag.

    Used as a preflight so smartscan does not launch a follow-up scan for
    technology tags that have no runnable templates.
    """
    cmd = [
        "nuclei",
        "-tags", tag,
        "-tl",
        "-iserver", nuclei_iserver,
        "-silent",
        "-nc"
    ]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        print("nuclei executable not found in PATH.", flush=True)
        return [], "nuclei executable not found in PATH."

    templates = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    stderr = result.stderr.strip()

    return templates, stderr


def runTaggedNuclei(codename, tag, hosts):
    """
    Run all installed Nuclei templates matching one tag against a batch of
    hosts.

    Preflight the tag with `-tl` first. If no templates are selected, skip it.
    Findings are streamed to stdout. On failure, concise stderr is printed for
    debugging. Nothing is written to the database.
    """
    hosts = sorted(set(hosts))

    if not hosts:
        return True

    templates, preflight_error = getTemplatesForTag(tag)

    if not templates:
        if preflight_error:
            print(
                f"[{codename}][{tag}][debug] preflight error: "
                f"{preflight_error}",
                flush=True
            )
        else:
            print(
                f"[{codename}][{tag}] skipping - "
                "no runnable templates for tag",
                flush=True
            )
        return not bool(preflight_error)

    print(
        f"[{codename}][{tag}][debug] "
        f"{len(templates)} template(s) selected",
        flush=True
    )

    cmd = [
        "nuclei",
        "-tags", tag,
        *nucleiScanArgs(),
        "-iserver", nuclei_iserver,
        "-silent",
        "-nc"
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        if proc.stdin:
            proc.stdin.write("\n".join(hosts) + "\n")
            proc.stdin.close()

        if proc.stdout:
            for line in proc.stdout:
                line = line.rstrip()

                if line:
                    print(
                        f"[{codename}][{tag}] {line}",
                        flush=True
                    )

        stderr = ""
        if proc.stderr:
            stderr = proc.stderr.read().strip()

        returncode = proc.wait()

        if returncode != 0:
            print(
                f"[{codename}][{tag}][debug] "
                f"Nuclei exited with status {returncode}",
                flush=True
            )

            if stderr:
                lines = [
                    line.strip()
                    for line in stderr.splitlines()
                    if line.strip()
                ]

                for line in lines[-10:]:
                    print(
                        f"[{codename}][{tag}][debug] {line}",
                        flush=True
                    )

        return returncode == 0

    except FileNotFoundError:
        print(
            f"[{codename}][{tag}][debug] "
            "nuclei executable not found in PATH.",
            flush=True
        )

        return False

    except Exception as e:
        print(
            f"[{codename}][{tag}][debug] "
            f"Error running Nuclei: {e}",
            flush=True
        )
        return False


def runSmartScan(context, target_filter=None, new_only=False):
    """
    Target-by-target smart scan with streaming tech detection.
    """

    available_tags = getAvailableNucleiTags()

    if not available_tags:
        print("Unable to retrieve available Nuclei template tags.", flush=True)
        return

    matched_target = False
    selected = []
    for target in context.get('targetlist', []):
        if not isinstance(target, dict):
            continue
        codename = target.get('codename', '')
        if target_filter and codename.lower() != target_filter.lower():
            continue
        matched_target = True
        category_name = ((target.get('category') or {}).get('name') or '').strip().lower()
        if category_name not in ('host', 'web application'):
            if target_filter:
                print(f"[{codename}] Target is category '{category_name}', "
                      'smartscan only supports Host and Web Application targets.', flush=True)
            continue
        if new_only and db.has_completed_smartscan(codename):
            print(f"[{codename}][smartscan] skipping - previously completed", flush=True)
            continue
        selected.append(target)

    total = len(selected)
    print(f'[smartscan] Processing {total} target(s)', flush=True)
    for position, target in enumerate(selected, start=1):
        codename = target['codename']
        target_started_at = time.perf_counter()
        try:

            if not checkLoginStatus():
                print("Synack authentication is no longer valid.", flush=True)
                return

            print(f"[{position}/{total}][{codename}] Connecting to Synack target...", flush=True)

            connect_status = connectToTarget(codename)

            if connect_status < 200 or connect_status >= 300:
                print(
                    f"[{codename}] Failed to connect to target "
                    f"(HTTP {connect_status})",
                    flush=True
                )
                continue

            cslug = getCurrentTargetSlug()

            if cslug == 1:
                print(f"[{codename}] Unable to determine current target.", flush=True)
                continue

            cname = getCodenameFromSlug(context, cslug)

            if cname != codename:
                print(
                    f"[{codename}] Target switch verification failed "
                    f"(current target: {cname})",
                    flush=True
                )
                continue

            print(f"[{codename}] Connected.", flush=True)

            scope = getScope(context, codename)

            if not scope:
                continue

            print(
                f"[{codename}] Running tech detection against "
                f"{len(scope)} scoped asset(s)...",
                flush=True
            )

            scan_run_id = db.start_smartscan(codename)
            scan_success = True
            scan_error = None

            hosts_by_tag = defaultdict(set)

            def handleTechFinding(finding):
                parsed = storeTechDetectionForFingerprint(codename, finding, available_tags)
                if parsed is None:
                    return
                scan_target, technology, _source, _detector, tags = parsed
                for tag in tags:
                    hosts_by_tag[tag].add(scan_target)
                    print(f'[{codename}][tech] {technology} -> {tag} @ {scan_target}', flush=True)

            try:
                tech_results = runTechDetect(scope, on_finding=handleTechFinding)
                if tech_results is None:
                    scan_success = False
                    scan_error = "tech-detect failed"

                if scan_success:
                    for tag in sorted(hosts_by_tag):
                        host_count = len(hosts_by_tag[tag])
                        print(
                            f"[{codename}][smartscan] running tag "
                            f"{tag} against {host_count} host(s)",
                            flush=True
                        )
                        if not runTaggedNuclei(codename, tag, hosts_by_tag[tag]):
                            scan_success = False
                            scan_error = f"tag scan failed: {tag}"

            except Exception as exc:
                scan_success = False
                scan_error = str(exc)
                print(f"[{codename}][smartscan] error: {exc}", flush=True)
            finally:
                db.finish_smartscan(scan_run_id, scan_success, scan_error)
                print(f"[{codename}][smartscan] {'completed' if scan_success else 'failed'}", flush=True)
        finally:
            print(f"[{position}/{total}][{codename}] Scan elapsed: {time.perf_counter() - target_started_at:.2f} seconds", flush=True)


    if target_filter and not matched_target:
        print(f"Target not found: {target_filter}", flush=True)


def runBotNuclei(codename, scope):
    """Stream JSONL matches into local SQLite; send metadata-only Slack alerts."""
    severities = botSeverities()
    cmd = [
        'nuclei', '-severity', ','.join(severities),
        *nucleiScanArgs(), '-iserver', nuclei_iserver, '-jsonl', '-silent', '-nc',
    ]
    print(f'[{codename}][bot] Nuclei severities: {",".join(severities)}; assets={len(scope)}', flush=True)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        if proc.stdin:
            proc.stdin.write('\n'.join(scope) + '\n')
            proc.stdin.close()
        for line in proc.stdout:
            try:
                finding = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(finding, dict):
                continue
            severity = str((finding.get('info') or {}).get('severity') or finding.get('severity') or '').lower()
            if severity not in severities:
                continue
            inserted = db.store_bot_finding(codename, finding)
            if inserted:
                botSlack('match', codename, severity)
                print(f'[{codename}][nuclei] {severity} match stored in SQLite', flush=True)
        errors = proc.stderr.read() if proc.stderr else ''
        code = proc.wait()
        if code != 0:
            print(f'[{codename}][nuclei] exited with status {code}', flush=True)
        return code == 0
    except Exception as exc:
        print(f'[{codename}][nuclei] Failed: {type(exc).__name__}', flush=True)
        return False


def runBotTarget(context, codename):
    """Run a full fingerprint then severity-based scan on one registered target."""
    target = getTargetInfo(context, codename)
    if not target or (target.get("category") or {}).get("name", "").lower() not in ("host", "web application"):
        raise RuntimeError("Unsupported or unavailable target category")
    if not checkLoginStatus():
        raise RuntimeError("Synack bearer token expired")

    print(f"[{codename}][bot] Connecting", flush=True)
    status = connectToTarget(codename)
    if not 200 <= status < 300:
        raise RuntimeError(f"Target connection failed: HTTP {status}")
    slug = getCurrentTargetSlug()
    current = getCodenameFromSlug(context, slug) if slug != 1 else None
    if current != codename:
        raise RuntimeError(f"Target switch mismatch: expected {codename}, got {current}")
    scope = getScope(context, codename)
    if not scope:
        raise RuntimeError("No target scope available")

    print(f"[{codename}][bot] Fingerprinting {len(scope)} assets", flush=True)
    for asset in scope:
        fingerprint(codename, asset, "")
    runHttpxFingerprint(codename, scope)
    available_tags = getAvailableNucleiTags()
    def on_finding(finding):
        storeTechDetectionForFingerprint(codename, finding, available_tags)
    if runTechDetect(scope, on_finding=on_finding) is None:
        raise RuntimeError("Nuclei tech-detect failed")
    if not runBotNuclei(codename, scope):
        raise RuntimeError("Severity-filtered Nuclei scan failed")


def registerUnregisteredBotTargets():
    """Register available unregistered listings; return successful signup IDs.

    Only call this after validating the current bearer. Never send API response
    bodies or target content to Slack.
    """
    slugs = []
    page = 1
    while True:
        response = requests.get(
            platform_url + "/api/targets",
            headers=headers,
            params={
                "filter[primary]": "unregistered",
                "filter[secondary]": "all",
                "filter[category]": "all",
                "sorting[field]": "dateUpdated",
                "sorting[direction]": "desc",
                "pagination[page]": page,
            },
            verify=False,
            timeout=20,
        )
        response.raise_for_status()
        items = response.json()
        if not isinstance(items, list):
            raise RuntimeError("Unexpected unregistered target response")
        if not items:
            break
        for item in items:
            if not isinstance(item, dict) or not item.get('slug'):
                continue
            if isExcludedTarget(item.get('codename')):
                print(f"[bot][register][excluded] Skipping {item.get('codename')}", flush=True)
                continue
            slugs.append(str(item['slug']))
        page += 1
        if page > 1000:
            raise RuntimeError("Unregistered target pagination exceeded limit")

    succeeded = []
    for slug in dict.fromkeys(slugs):
        try:
            response = requests.post(
                platform_url + "/api/targets/" + slug + "/signup",
                headers=headers,
                json={"ResearcherListing": {"terms": 1}},
                verify=False,
                timeout=20,
            )
            if 200 <= response.status_code < 300:
                succeeded.append(slug)
                print(f"[bot][register] Registered {slug}", flush=True)
            else:
                print(f"[bot][register] Signup failed for {slug}: HTTP {response.status_code}", flush=True)
        except requests.RequestException as exc:
            print(f"[bot][register] Signup request failed for {slug}: {type(exc).__name__}", flush=True)
    print(f"[bot][register] available={len(slugs)} registered={len(succeeded)}", flush=True)
    return succeeded


def runBot(context, interval=600, once=False):
    """Poll every interval, scanning newly registered and unfinished targets."""
    if interval < 60:
        raise ValueError("Poll interval must be at least 60 seconds")
    print(f"[bot] Checking registered targets every {interval}s", flush=True)
    auth_failed_notified = False
    while True:
        try:
            # Reload token from env file each poll so operators can replace it.
            saved = loadEnvFile().get(TOKEN_ENV_NAME) or os.environ.get(TOKEN_ENV_NAME) or ''
            if not saved or not validateBearer(saved):
                if not auth_failed_notified:
                    botSlack('auth')
                    auth_failed_notified = True
                print('[bot] Bearer validation failed; retrying next poll', flush=True)
                if once:
                    return 1
                time.sleep(interval)
                continue
            auth_failed_notified = False
            global headers
            headers = {'Authorization': 'Bearer ' + saved}
            # Capture pre-signup registration state for first-cycle detection.
            if not getAllTargets(context):
                print("[bot] Authentication/API fetch failed; will retry next poll", flush=True)
                if once:
                    return 1
                time.sleep(interval)
                continue
            previously_registered = {
                str(t.get("id")) for t in context.get("targetlist", [])
                if isinstance(t, dict) and t.get("id")
            }
            try:
                signed_up = registerUnregisteredBotTargets()
            except Exception as exc:
                print(f"[bot][register] Check failed: {type(exc).__name__}: {exc}", flush=True)
                signed_up = []
            if not getAllTargets(context):
                print("[bot] Unable to refresh registered targets after signup", flush=True)
            else:
                targets = context.get("targetlist", [])
                if not isinstance(targets, list):
                    print("[bot] Invalid registered target response", flush=True)
                else:
                    bootstrap = not db.bot_has_seen_targets()
                    # On first run, baseline only the targets present before
                    # this cycle's signup; keep newly registered ones pending.
                    if bootstrap:
                        baseline = [t for t in targets if str(t.get('id')) in previously_registered]
                        db.bot_sync_seen_targets(baseline, bootstrap=True)
                        print(f"[bot] Baseline initialized ({len(baseline)} existing)", flush=True)
                    newly_discovered = db.bot_sync_seen_targets(targets, bootstrap=False)
                    print(f"[bot] {len(newly_discovered)} newly registered targets", flush=True)
                    for target in newly_discovered:
                        botSlack('new', target.get('codename'))
                    pending_targets = db.bot_pending_targets(targets)
                    total_pending = len(pending_targets)
                    for position, target in enumerate(pending_targets, start=1):
                        codename = target["codename"]
                        target_started_at = time.perf_counter()
                        try:
                            print(f'[{position}/{total_pending}][{codename}][bot] Processing target', flush=True)
                            synack_id = str(target["id"])
                            if db.has_completed_smartscan(codename):
                                print(f"[{codename}][bot] Previously scanned; skipping", flush=True)
                                db.bot_set_status(synack_id, "completed")
                                continue
                            scan_id = db.start_smartscan(codename)
                            db.bot_set_status(synack_id, "scanning")
                            try:
                                runBotTarget(context, codename)
                            except KeyboardInterrupt:
                                db.finish_smartscan(scan_id, False, "Interrupted")
                                db.bot_set_status(synack_id, "failed")
                                raise
                            except Exception as exc:
                                db.finish_smartscan(scan_id, False, str(exc))
                                db.bot_set_status(synack_id, "failed")
                                print(f"[{codename}][bot] Failed: {exc}", flush=True)
                            else:
                                db.finish_smartscan(scan_id, True)
                                db.bot_set_status(synack_id, "completed")
                                print(f"[{codename}][bot] Completed", flush=True)
                        finally:
                            print(f"[{position}/{total_pending}][{codename}] Scan elapsed: {time.perf_counter() - target_started_at:.2f} seconds", flush=True)

        except KeyboardInterrupt:
            print("\n[bot] Stopped", flush=True)
            return 0
        except Exception as exc:
            print(f"[bot][error] {type(exc).__name__}: {exc}", flush=True)
        if once:
            return 0
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[bot] Stopped", flush=True)
            return 0


########## MAIN MODULES #################
if module != 'bot':
    registerAllTargets()
folder_path = "/home/AMBERJACK/8pm493i9kc/automation/bulkcommand/data"
#print(context['targetlist'])
codenames = []
for t in context.get('targetlist', []):
    codenames.append(t['codename'])
# Excluding a target from scans must never delete its existing on-disk data.
codenames.extend(excludedTargetCodenames())
for item in (os.listdir(folder_path) if module != 'bot' and os.path.isdir(folder_path) else []):
    item_path = os.path.join(folder_path, item)

    # Check if it's a directory
    if os.path.isdir(item_path):
        # If folder name not in keep_list, remove it
        if item.casefold() not in {name.casefold() for name in codenames}:
            print(f"Removing: {item_path}")
            shutil.rmtree(item_path)
        #else:

            #print(f"Keeping: {item_path}")

if module == 'bot':
    bot_interval = 600
    if '--interval' in sys.argv:
        try:
            bot_interval = int(sys.argv[sys.argv.index('--interval') + 1])
        except (IndexError, ValueError):
            sys.exit('Usage: python3 main.py bot [--interval SECONDS] [--once]')
    sys.exit(runBot(context, interval=bot_interval, once='--once' in sys.argv))

elif module == "checkin":
    registerAllTargets()

elif module == "fingerprint":
    import argparse
    parser = argparse.ArgumentParser(prog=f"{sys.argv[0]} fingerprint")
    parser.add_argument("--target", "-t", metavar="CODENAME",
                        help="Fingerprint only the specified Synack target")
    parser.add_argument("--batch-size", type=int, metavar="N",
                        help="Optional number of assets per Nuclei process (default: all assets together)")
    parser.add_argument("--bearer", help="Synack bearer token (existing option)")
    args = parser.parse_args(sys.argv[2:])
    if args.batch_size is not None and args.batch_size < 1:
        parser.error("--batch-size must be a positive integer")
    doFingerprint(context, target_filter=args.target, batch_size=args.batch_size)

elif module == "exec":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} exec <bearer> <command>")
        sys.exit(1)

    print("Execute Shell Command: "+sys.argv[3])
    doShellCommand(context,sys.argv[3])

elif module == "nuclei":
    import argparse
    parser = argparse.ArgumentParser(prog=f"{sys.argv[0]} nuclei")
    parser.add_argument("template_path", help="Path to a Nuclei YAML template or workflow")
    kind = parser.add_mutually_exclusive_group()
    kind.add_argument("--template", action="store_const", const="template", dest="nuclei_kind",
                      help="Force template mode (-t)")
    kind.add_argument("--workflow", action="store_const", const="workflow", dest="nuclei_kind",
                      help="Force workflow mode (-w)")
    parser.set_defaults(nuclei_kind="auto")
    parser.add_argument("--category", choices=("all", "host", "web"), default="all",
                        help="Synack target category (default: all)")
    parser.add_argument("--target", "-t", metavar="CODENAME",
                        help="Scan only the specified Synack target codename")
    parser.add_argument("--skip-discovery", action="store_true",
                        help="Skip PTR/TLS/Chaos discovery and scan saved DB vhosts on current scoped IPs")
    parser.add_argument("--bearer", help="Synack bearer token (existing option)")
    args = parser.parse_args(sys.argv[2:])
    runNucleiTemplate(context, args.template_path, category_filter=args.category,
                      nuclei_kind=args.nuclei_kind, target_filter=args.target,
                      skip_existing_discovery=args.skip_discovery)

elif module == "smartscan":
    target_filter = None
    new_only = "--new" in sys.argv

    # Usage:
    #   python3 main.py smartscan
    #   python3 main.py smartscan --target ARGOS-W002
    #
    # Short form:
    #   python3 main.py smartscan -t ARGOS-W002
    if "--target" in sys.argv:
        try:
            target_filter = sys.argv[sys.argv.index("--target") + 1]
        except IndexError:
            print(f"Usage: {sys.argv[0]} smartscan [--target CODENAME]")
            sys.exit(1)

    elif "-t" in sys.argv:
        try:
            target_filter = sys.argv[sys.argv.index("-t") + 1]
        except IndexError:
            print(f"Usage: {sys.argv[0]} smartscan [-t CODENAME]")
            sys.exit(1)

    runSmartScan(context, target_filter, new_only=new_only)

else:
    print("passing module")
    #print("arg1 must be a valid module. Exiting...")
    #exit()

#getAllTargets(context)
#doScan(context,"all","/SitePages/Login.aspx","Microsoft SharePoint")


try:
    db.close()
except Exception:
    pass
