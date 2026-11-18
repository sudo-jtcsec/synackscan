#!/usr/bin/env python3

import sqlite3
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "synackscan.db"


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ReconDB:
    def __init__(self, path=DEFAULT_DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.init_schema()

    def init_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                codename TEXT NOT NULL UNIQUE,
                synack_id TEXT,
                organization_id TEXT,
                category TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bot_seen_targets (
                synack_id TEXT PRIMARY KEY,
                codename TEXT NOT NULL,
                first_detected_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'discovered'
            );

            CREATE TABLE IF NOT EXISTS bot_findings (
                id INTEGER PRIMARY KEY,
                target_id INTEGER NOT NULL,
                template_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                matched_at TEXT NOT NULL,
                matched_url TEXT,
                matcher_name TEXT,
                finding_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_bot_findings_target ON bot_findings(target_id);
            CREATE INDEX IF NOT EXISTS idx_bot_findings_severity ON bot_findings(severity);

            CREATE TABLE IF NOT EXISTS smartscan_runs (
                id INTEGER PRIMARY KEY,
                target_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
                error TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_smartscan_runs_target_status
                ON smartscan_runs(target_id, status);

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY,
                target_id INTEGER NOT NULL,
                asset TEXT NOT NULL,
                asset_type TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
                UNIQUE(target_id, asset)
            );

            CREATE TABLE IF NOT EXISTS vhost_observations (
                id INTEGER PRIMARY KEY,
                target_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                discovery_source TEXT NOT NULL,
                status_code INTEGER,
                redirect_location TEXT,
                webserver TEXT,
                error TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
                UNIQUE(target_id, ip, hostname, discovery_source)
            );
            CREATE INDEX IF NOT EXISTS idx_vhost_observations_ip
                ON vhost_observations(ip);
            CREATE INDEX IF NOT EXISTS idx_vhost_observations_hostname
                ON vhost_observations(hostname);

            CREATE TABLE IF NOT EXISTS vhost_nuclei_findings (
                id INTEGER PRIMARY KEY,
                target_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                template_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                matched_url TEXT,
                matcher_name TEXT,
                finding_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_vhost_nuclei_findings_target
                ON vhost_nuclei_findings(target_id);
            CREATE INDEX IF NOT EXISTS idx_vhost_nuclei_findings_hostname
                ON vhost_nuclei_findings(hostname);

            CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY,
                asset_id INTEGER NOT NULL,
                technology TEXT NOT NULL,
                source TEXT NOT NULL,
                detector TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                UNIQUE(asset_id, technology, source, detector)
            );

            CREATE TABLE IF NOT EXISTS technology_tags (
                technology_id INTEGER NOT NULL,
                tag TEXT NOT NULL,
                FOREIGN KEY(technology_id) REFERENCES technologies(id) ON DELETE CASCADE,
                UNIQUE(technology_id, tag)
            );


            CREATE TABLE IF NOT EXISTS http_observations (
                id INTEGER PRIMARY KEY,
                asset_id INTEGER NOT NULL,
                input TEXT,
                url TEXT NOT NULL,
                host TEXT,
                ip TEXT,
                port INTEGER,
                scheme TEXT,
                method TEXT,
                status_code INTEGER,
                title TEXT,
                content_type TEXT,
                content_length INTEGER,
                redirect_location TEXT,
                webserver TEXT,
                cdn_name TEXT,
                cdn_type TEXT,
                response_time TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                UNIQUE(asset_id, url)
            );

            CREATE INDEX IF NOT EXISTS idx_targets_codename
                ON targets(codename);

            CREATE INDEX IF NOT EXISTS idx_assets_asset
                ON assets(asset);

            CREATE INDEX IF NOT EXISTS idx_assets_target
                ON assets(target_id);

            CREATE INDEX IF NOT EXISTS idx_technologies_technology
                ON technologies(technology);

            CREATE INDEX IF NOT EXISTS idx_technologies_detector
                ON technologies(detector);

            CREATE INDEX IF NOT EXISTS idx_technology_tags_tag
                ON technology_tags(tag);


            CREATE INDEX IF NOT EXISTS idx_http_observations_url
                ON http_observations(url);

            CREATE INDEX IF NOT EXISTS idx_http_observations_status
                ON http_observations(status_code);

            CREATE INDEX IF NOT EXISTS idx_http_observations_host
                ON http_observations(host);

            CREATE INDEX IF NOT EXISTS idx_http_observations_ip
                ON http_observations(ip);
            """
        )
        self.conn.commit()

    def store_bot_finding(self, codename, finding):
        """Persist full finding locally; never forward finding contents to Slack.

        Returns True only for a new unique finding.
        """
        target_id = self.ensure_target(codename)
        info = finding.get('info') or {}
        template = str(finding.get('template-id') or finding.get('templateID') or finding.get('template') or '')
        severity = str(info.get('severity') or finding.get('severity') or 'unknown').lower()
        matched_url = str(finding.get('matched-at') or finding.get('host') or '')
        matcher = str(finding.get('matcher-name') or '')
        # Stable across repeated Nuclei runs; use target + template + match path + matcher.
        identity = json.dumps([target_id, template, matched_url, matcher], separators=(',', ':'))
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()
        with self.conn:
            cur = self.conn.execute('''
                INSERT OR IGNORE INTO bot_findings
                (target_id,template_id,severity,matched_at,matched_url,matcher_name,finding_json,fingerprint)
                VALUES (?,?,?,?,?,?,?,?)
            ''', (target_id,template,severity,utcnow(),matched_url,matcher,
                  json.dumps(finding, ensure_ascii=False),fingerprint))
        return cur.rowcount > 0

    def bot_sync_seen_targets(self, targets, bootstrap=False):
        """Record registered targets and return those never seen before.

        A first-run bootstrap treats currently registered targets as baseline.
        Synack listing UID is preferred over codename for stable identity.
        """
        discovered = []
        now = utcnow()
        with self.conn:
            for target in targets:
                if not isinstance(target, dict):
                    continue
                uid = str(target.get('id') or '').strip()
                codename = str(target.get('codename') or '').strip()
                if not uid or not codename:
                    continue
                existing = self.conn.execute(
                    'SELECT 1 FROM bot_seen_targets WHERE synack_id=?', (uid,)
                ).fetchone()
                if existing:
                    self.conn.execute(
                        'UPDATE bot_seen_targets SET codename=?,last_seen_at=? WHERE synack_id=?',
                        (codename, now, uid)
                    )
                else:
                    self.conn.execute(
                        'INSERT INTO bot_seen_targets '
                        '(synack_id,codename,first_detected_at,last_seen_at,status) '
                        'VALUES (?,?,?,?,?)',
                        (uid, codename, now, now, 'baseline' if bootstrap else 'discovered')
                    )
                    if not bootstrap:
                        discovered.append(target)
        return discovered

    def bot_has_seen_targets(self):
        return self.conn.execute(
            'SELECT EXISTS(SELECT 1 FROM bot_seen_targets)'
        ).fetchone()[0] == 1

    def bot_pending_targets(self, registered_targets):
        """Only newly discovered or failed/incomplete registered targets."""
        pending = set()
        for row in self.conn.execute(
            "SELECT synack_id FROM bot_seen_targets WHERE status IN ('discovered','failed','scanning')"
        ):
            pending.add(row[0])
        return [t for t in registered_targets if isinstance(t, dict)
                and str(t.get('id') or '') in pending and t.get('codename')]

    def bot_set_status(self, synack_id, status):
        if status not in ('discovered', 'baseline', 'scanning', 'failed', 'completed'):
            raise ValueError('Invalid bot status')
        with self.conn:
            self.conn.execute('UPDATE bot_seen_targets SET status=? WHERE synack_id=?',
                              (status, str(synack_id)))

    def has_completed_smartscan(self, codename):
        row = self.conn.execute("""
            SELECT 1 FROM smartscan_runs r
            JOIN targets t ON t.id = r.target_id
            WHERE lower(t.codename) = lower(?)
              AND r.status = 'completed'
            LIMIT 1
        """, (codename,)).fetchone()
        return row is not None

    def start_smartscan(self, codename):
        target_id = self.ensure_target(codename)
        cur = self.conn.execute("""
            INSERT INTO smartscan_runs(target_id, started_at, status)
            VALUES (?, ?, 'running')
        """, (target_id, utcnow()))
        self.conn.commit()
        return cur.lastrowid

    def finish_smartscan(self, run_id, success, error=None):
        self.conn.execute("""
            UPDATE smartscan_runs
            SET finished_at=?, status=?, error=?
            WHERE id=?
        """, (utcnow(), 'completed' if success else 'failed', error, run_id))
        self.conn.commit()

    def upsert_target(self, target):
        codename = str(target.get("codename", "")).strip()
        if not codename:
            return None

        category = None
        try:
            category = target.get("category", {}).get("name")
        except AttributeError:
            pass

        now = utcnow()

        self.conn.execute(
            """
            INSERT INTO targets (
                codename, synack_id, organization_id, category,
                first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(codename) DO UPDATE SET
                synack_id=excluded.synack_id,
                organization_id=excluded.organization_id,
                category=excluded.category,
                last_seen=excluded.last_seen
            """,
            (
                codename,
                target.get("id"),
                target.get("organization_id"),
                category,
                now,
                now,
            ),
        )
        self.conn.commit()
        return self.get_target_id(codename)

    def sync_targets(self, targets):
        for target in targets or []:
            if isinstance(target, dict):
                self.upsert_target(target)

    def get_target_id(self, codename):
        row = self.conn.execute(
            "SELECT id FROM targets WHERE lower(codename)=lower(?)",
            (codename,),
        ).fetchone()
        return row["id"] if row else None

    def ensure_target(self, codename):
        target_id = self.get_target_id(codename)
        if target_id:
            return target_id

        now = utcnow()
        cur = self.conn.execute(
            """
            INSERT INTO targets(codename, first_seen, last_seen)
            VALUES (?, ?, ?)
            """,
            (codename, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def upsert_asset(self, codename, asset, asset_type=None):
        asset = str(asset or "").strip()
        if not asset:
            return None

        target_id = self.ensure_target(codename)
        now = utcnow()

        self.conn.execute(
            """
            INSERT INTO assets (
                target_id, asset, asset_type, first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target_id, asset) DO UPDATE SET
                asset_type=COALESCE(excluded.asset_type, assets.asset_type),
                last_seen=excluded.last_seen
            """,
            (target_id, asset, asset_type, now, now),
        )
        self.conn.commit()

        row = self.conn.execute(
            """
            SELECT id
            FROM assets
            WHERE target_id=? AND asset=?
            """,
            (target_id, asset),
        ).fetchone()

        return row["id"] if row else None

    def store_vhost_observation(self, codename, ip, hostname, source, observation):
        """Store pinned-IP HTTPS probe or wildcard-certificate observation."""
        target_id = self.ensure_target(codename)
        now = utcnow()
        observation = observation or {}
        with self.conn:
            self.conn.execute("""
                INSERT INTO vhost_observations
                    (target_id, ip, hostname, discovery_source, status_code,
                     redirect_location, webserver, error, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id, ip, hostname, discovery_source) DO UPDATE SET
                    status_code=excluded.status_code,
                    redirect_location=excluded.redirect_location,
                    webserver=excluded.webserver,
                    error=excluded.error,
                    last_seen=excluded.last_seen
            """, (
                target_id, str(ip), str(hostname), str(source),
                observation.get('status_code'), observation.get('location'),
                observation.get('server'), observation.get('error'), now, now
            ))

    def get_vhosts_for_nuclei(self, codename):
        """Only successful, concrete certificate/Chaos hostnames on scoped IPs."""
        return self.conn.execute("""
            SELECT DISTINCT v.ip, v.hostname
            FROM vhost_observations v
            JOIN targets t ON t.id=v.target_id
            WHERE lower(t.codename)=lower(?)
              AND v.status_code BETWEEN 200 AND 599
              AND v.hostname NOT LIKE '*.%'
              AND v.discovery_source IN ('certificate','chaos-wildcard')
            ORDER BY v.ip, v.hostname
        """, (codename,)).fetchall()

    def store_vhost_nuclei_finding(self, codename, ip, hostname, finding):
        """Persist matched Nuclei finding with target IP + virtual hostname identity."""
        target_id = self.ensure_target(codename)
        info = finding.get('info') or {}
        template = str(finding.get('template-id') or finding.get('templateID') or finding.get('template') or '')
        severity = str(info.get('severity') or finding.get('severity') or 'unknown').lower()
        matched_url = str(finding.get('matched-at') or finding.get('host') or '')
        matcher = str(finding.get('matcher-name') or '')
        identity = json.dumps([target_id, ip, hostname, template, matched_url, matcher], separators=(',', ':'))
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()
        now = utcnow()
        with self.conn:
            old = self.conn.execute(
                'SELECT 1 FROM vhost_nuclei_findings WHERE fingerprint=?',
                (fingerprint,)
            ).fetchone()
            self.conn.execute("""
                INSERT INTO vhost_nuclei_findings
                (target_id,ip,hostname,template_id,severity,matched_url,matcher_name,
                 finding_json,fingerprint,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    finding_json=excluded.finding_json
            """, (target_id, str(ip), str(hostname), template, severity, matched_url,
                  matcher, json.dumps(finding,ensure_ascii=False), fingerprint, now, now))
        return old is None

    def store_technology(
        self,
        codename,
        asset,
        technology,
        source="nuclei-tech-detect",
        detector=None,
        tags=None,
    ):
        technology = str(technology or "").strip()
        if not technology:
            return None

        asset_id = self.upsert_asset(codename, asset, "detected-url")
        if not asset_id:
            return None

        detector = str(detector or technology).strip()
        now = utcnow()

        self.conn.execute(
            """
            INSERT INTO technologies (
                asset_id, technology, source, detector,
                first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_id, technology, source, detector) DO UPDATE SET
                last_seen=excluded.last_seen
            """,
            (
                asset_id,
                technology,
                source,
                detector,
                now,
                now,
            ),
        )
        self.conn.commit()

        row = self.conn.execute(
            """
            SELECT id
            FROM technologies
            WHERE asset_id=? AND technology=? AND source=? AND detector=?
            """,
            (asset_id, technology, source, detector),
        ).fetchone()

        if not row:
            return None

        technology_id = row["id"]

        for tag in sorted(set(tags or [])):
            self.conn.execute(
                """
                INSERT OR IGNORE INTO technology_tags(technology_id, tag)
                VALUES (?, ?)
                """,
                (technology_id, tag),
            )

        self.conn.commit()
        return technology_id

    def store_http_observation(self, codename, observation):
        """
        Store/update one httpx JSON observation.

        The original input is retained as the asset relationship while
        `url` represents the URL httpx actually observed.
        """
        if not isinstance(observation, dict):
            return None

        input_value = str(
            observation.get("input")
            or observation.get("url")
            or observation.get("host")
            or ""
        ).strip()

        url = str(observation.get("url") or input_value).strip()

        if not input_value or not url:
            return None

        asset_id = self.upsert_asset(codename, input_value, "httpx-input")

        if not asset_id:
            return None

        now = utcnow()

        a_records = observation.get("a")
        ip = None

        if isinstance(a_records, list) and a_records:
            ip = str(a_records[0])
        elif observation.get("host"):
            # httpx `host` is often the resolved IP.
            ip = str(observation.get("host"))

        values = (
            asset_id,
            input_value,
            url,
            observation.get("host"),
            ip,
            observation.get("port"),
            observation.get("scheme"),
            observation.get("method"),
            observation.get("status_code"),
            observation.get("title"),
            observation.get("content_type"),
            observation.get("content_length"),
            observation.get("location"),
            observation.get("webserver"),
            observation.get("cdn_name"),
            observation.get("cdn_type"),
            observation.get("time"),
            now,
            now,
        )

        self.conn.execute(
            """
            INSERT INTO http_observations (
                asset_id, input, url, host, ip, port, scheme, method,
                status_code, title, content_type, content_length,
                redirect_location, webserver, cdn_name, cdn_type,
                response_time, first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_id, url) DO UPDATE SET
                input=excluded.input,
                host=excluded.host,
                ip=excluded.ip,
                port=excluded.port,
                scheme=excluded.scheme,
                method=excluded.method,
                status_code=excluded.status_code,
                title=excluded.title,
                content_type=excluded.content_type,
                content_length=excluded.content_length,
                redirect_location=excluded.redirect_location,
                webserver=excluded.webserver,
                cdn_name=excluded.cdn_name,
                cdn_type=excluded.cdn_type,
                response_time=excluded.response_time,
                last_seen=excluded.last_seen
            """,
            values,
        )
        self.conn.commit()

        row = self.conn.execute(
            """
            SELECT id FROM http_observations
            WHERE asset_id=? AND url=?
            """,
            (asset_id, url),
        ).fetchone()

        return row["id"] if row else None

    def rows(self, sql, params=()):
        return self.conn.execute(sql, params).fetchall()

    def close(self):
        self.conn.close()


def _print_table(headers, rows):
    rows = [list(map(lambda x: "" if x is None else str(x), row)) for row in rows]

    if not rows:
        print("No results.")
        return

    widths = [
        max(len(headers[i]), max(len(row[i]) for row in rows))
        for i in range(len(headers))
    ]

    def fmt(row):
        return "  ".join(row[i].ljust(widths[i]) for i in range(len(headers)))

    print(fmt(headers))
    print(fmt(["-" * width for width in widths]))

    for row in rows:
        print(fmt(row))


def run_db_cli(db_path, args):
    db = ReconDB(db_path)

    try:
        if not args or args[0] in ("help", "-h", "--help"):
            print(
                "Usage:\n"
                "  python3 main.py db stats\n"
                "  python3 main.py db targets [search]\n"
                "  python3 main.py db technologies\n"
                "  python3 main.py db http [search]\n"
                "  python3 main.py db vhosts [search]\n"
                "  python3 main.py db vhost-findings [search]\n"
                "  python3 main.py db tech <search>\n"
                "  python3 main.py db target <codename>\n"
                "  python3 main.py db findings [codename-or-severity]\n"
            )
            return

        command = args[0].lower()

        if command == 'vhosts':
            term = f"%{args[1]}%" if len(args) > 1 else '%'
            rows = db.rows("""
                SELECT t.codename, v.ip, v.hostname, v.discovery_source,
                       v.status_code, v.redirect_location, v.error, v.last_seen
                FROM vhost_observations v
                JOIN targets t ON t.id=v.target_id
                WHERE t.codename LIKE ? COLLATE NOCASE
                   OR v.ip LIKE ? COLLATE NOCASE
                   OR v.hostname LIKE ? COLLATE NOCASE
                ORDER BY t.codename, v.ip, v.hostname
            """, (term, term, term))
            _print_table(
                ['target','ip','hostname','source','status','redirect','error','last_seen'],
                [[r['codename'],r['ip'],r['hostname'],r['discovery_source'],
                  r['status_code'],r['redirect_location'],r['error'],r['last_seen']]
                 for r in rows]
            )
            return

        if command == 'vhost-findings':
            term = f"%{args[1]}%" if len(args) > 1 else '%'
            rows = db.rows("""
                SELECT t.codename, f.ip, f.hostname, f.severity,
                       f.template_id, f.matched_url, f.last_seen
                FROM vhost_nuclei_findings f
                JOIN targets t ON t.id=f.target_id
                WHERE t.codename LIKE ? COLLATE NOCASE
                   OR f.hostname LIKE ? COLLATE NOCASE
                   OR f.ip LIKE ? COLLATE NOCASE
                   OR f.template_id LIKE ? COLLATE NOCASE
                ORDER BY f.last_seen DESC
            """, (term,term,term,term))
            _print_table(['target','ip','hostname','severity','template','matched_url','last_seen'],
                         [[r['codename'],r['ip'],r['hostname'],r['severity'],
                           r['template_id'],r['matched_url'],r['last_seen']] for r in rows])
            return

        if command == 'findings':
            term = ('%' + args[1] + '%') if len(args) > 1 else '%'
            rows = db.rows("""
                SELECT t.codename, f.severity, f.template_id,
                       f.matched_url, f.matcher_name, f.matched_at
                FROM bot_findings f JOIN targets t ON t.id=f.target_id
                WHERE t.codename LIKE ? COLLATE NOCASE
                   OR f.severity LIKE ? COLLATE NOCASE
                   OR f.template_id LIKE ? COLLATE NOCASE
                ORDER BY f.matched_at DESC
            """, (term,term,term))
            _print_table(['target','severity','template','matched_url','matcher','first_seen'],
                         [[r['codename'],r['severity'],r['template_id'],r['matched_url'],r['matcher_name'],r['matched_at']] for r in rows])
            return

        if command == "stats":
            row = db.conn.execute(
                """
                SELECT
                    (SELECT count(*) FROM targets) AS targets,
                    (SELECT count(*) FROM assets) AS assets,
                    (SELECT count(*) FROM technologies) AS fingerprints,
                    (SELECT count(*) FROM http_observations) AS http_observations,
                    (SELECT count(DISTINCT lower(technology)) FROM technologies)
                        AS distinct_technologies
                """
            ).fetchone()

            _print_table(
                ["targets", "assets", "fingerprints", "http", "distinct_tech"],
                [[
                    row["targets"],
                    row["assets"],
                    row["fingerprints"],
                    row["http_observations"],
                    row["distinct_technologies"],
                ]],
            )
            print(f"\nDB: {db.path}")
            return

        if command == "targets":
            search = args[1] if len(args) > 1 else "%"
            if search != "%":
                search = f"%{search}%"

            rows = db.rows(
                """
                SELECT
                    t.codename,
                    COALESCE(t.category, '') AS category,
                    count(DISTINCT a.id) AS assets,
                    count(DISTINCT tech.id) AS fingerprints
                FROM targets t
                LEFT JOIN assets a ON a.target_id=t.id
                LEFT JOIN technologies tech ON tech.asset_id=a.id
                WHERE t.codename LIKE ? COLLATE NOCASE
                GROUP BY t.id
                ORDER BY t.codename COLLATE NOCASE
                """,
                (search,),
            )

            _print_table(
                ["target", "category", "assets", "fingerprints"],
                [[r["codename"], r["category"], r["assets"], r["fingerprints"]] for r in rows],
            )
            return

        if command == "technologies":
            rows = db.rows(
                """
                SELECT
                    tech.technology,
                    count(DISTINCT a.target_id) AS targets,
                    count(DISTINCT tech.asset_id) AS assets
                FROM technologies tech
                JOIN assets a ON a.id=tech.asset_id
                GROUP BY lower(tech.technology)
                ORDER BY targets DESC, assets DESC, tech.technology COLLATE NOCASE
                """
            )

            _print_table(
                ["technology", "targets", "assets"],
                [[r["technology"], r["targets"], r["assets"]] for r in rows],
            )
            return

        if command == "tech":
            if len(args) < 2:
                print("Usage: python3 main.py db tech <search>")
                return

            term = f"%{args[1]}%"

            rows = db.rows(
                """
                SELECT DISTINCT
                    t.codename,
                    a.asset,
                    tech.technology,
                    COALESCE(tt.tag, '') AS tag,
                    COALESCE(tech.detector, '') AS detector,
                    tech.last_seen
                FROM technologies tech
                JOIN assets a ON a.id=tech.asset_id
                JOIN targets t ON t.id=a.target_id
                LEFT JOIN technology_tags tt ON tt.technology_id=tech.id
                WHERE
                    tech.technology LIKE ? COLLATE NOCASE
                    OR tech.detector LIKE ? COLLATE NOCASE
                    OR tt.tag LIKE ? COLLATE NOCASE
                ORDER BY t.codename COLLATE NOCASE, a.asset
                """,
                (term, term, term),
            )

            _print_table(
                ["target", "asset", "technology", "tag", "detector", "last_seen"],
                [[
                    r["codename"],
                    r["asset"],
                    r["technology"],
                    r["tag"],
                    r["detector"],
                    r["last_seen"],
                ] for r in rows],
            )
            return

        if command == "http":
            search = args[1] if len(args) > 1 else "%"
            if search != "%":
                search = f"%{search}%"

            rows = db.rows(
                """
                SELECT
                    t.codename,
                    h.url,
                    COALESCE(h.status_code, '') AS status_code,
                    COALESCE(h.title, '') AS title,
                    COALESCE(h.webserver, '') AS webserver,
                    COALESCE(h.ip, '') AS ip,
                    COALESCE(h.cdn_name, '') AS cdn,
                    COALESCE(h.redirect_location, '') AS redirect
                FROM http_observations h
                JOIN assets a ON a.id=h.asset_id
                JOIN targets t ON t.id=a.target_id
                WHERE
                    h.url LIKE ? COLLATE NOCASE
                    OR h.title LIKE ? COLLATE NOCASE
                    OR h.webserver LIKE ? COLLATE NOCASE
                    OR h.ip LIKE ? COLLATE NOCASE
                    OR h.cdn_name LIKE ? COLLATE NOCASE
                ORDER BY t.codename COLLATE NOCASE, h.url
                """,
                (search, search, search, search, search),
            )

            _print_table(
                ["target", "url", "status", "title", "server", "ip", "cdn", "redirect"],
                [[
                    r["codename"],
                    r["url"],
                    r["status_code"],
                    r["title"],
                    r["webserver"],
                    r["ip"],
                    r["cdn"],
                    r["redirect"],
                ] for r in rows],
            )
            return

        if command == "target":
            if len(args) < 2:
                print("Usage: python3 main.py db target <codename>")
                return

            codename = args[1]

            rows = db.rows(
                """
                SELECT DISTINCT
                    a.asset,
                    COALESCE(a.asset_type, '') AS asset_type,
                    COALESCE(tech.technology, '') AS technology,
                    COALESCE(tt.tag, '') AS tag,
                    COALESCE(tech.detector, '') AS detector
                FROM targets t
                LEFT JOIN assets a ON a.target_id=t.id
                LEFT JOIN technologies tech ON tech.asset_id=a.id
                LEFT JOIN technology_tags tt ON tt.technology_id=tech.id
                WHERE lower(t.codename)=lower(?)
                ORDER BY a.asset, tech.technology
                """,
                (codename,),
            )

            _print_table(
                ["asset", "type", "technology", "tag", "detector"],
                [[
                    r["asset"],
                    r["asset_type"],
                    r["technology"],
                    r["tag"],
                    r["detector"],
                ] for r in rows],
            )
            return

        print(f"Unknown DB command: {command}")

    finally:
        db.close()
