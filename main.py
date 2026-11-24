import sqlite3
from datetime import datetime, timedelta

DB_NAME = "security_events.db"
TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_connection(db_name: str = DB_NAME) -> sqlite3.Connection:
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _ts(dt: datetime) -> str:
    return dt.strftime(TS_FORMAT)


def create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS EventSources (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT UNIQUE NOT NULL,
            location TEXT,
            type     TEXT
        );

        CREATE TABLE IF NOT EXISTS EventTypes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            type_name TEXT UNIQUE NOT NULL,
            severity  TEXT
        );

        CREATE TABLE IF NOT EXISTS SecurityEvents (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     DATETIME NOT NULL,
            source_id     INTEGER NOT NULL,
            event_type_id INTEGER NOT NULL,
            message       TEXT,
            ip_address    TEXT,
            username      TEXT,
            FOREIGN KEY (source_id)     REFERENCES EventSources(id),
            FOREIGN KEY (event_type_id) REFERENCES EventTypes(id)
        );
        """
    )
    conn.commit()


def add_event_source(conn, name: str, location: str, type_: str) -> int:
    cur = conn.execute(
        "INSERT INTO EventSources (name, location, type) VALUES (?, ?, ?)",
        (name, location, type_),
    )
    conn.commit()
    return cur.lastrowid


def add_event_type(conn, type_name: str, severity: str) -> int:
    cur = conn.execute(
        "INSERT INTO EventTypes (type_name, severity) VALUES (?, ?)",
        (type_name, severity),
    )
    conn.commit()
    return cur.lastrowid


def add_security_event(conn, source_id: int, event_type_id: int, message: str,
                       ip_address: str | None = None, username: str | None = None,
                       timestamp: datetime | None = None) -> int:
    ts = _ts(timestamp or datetime.now())
    cur = conn.execute(
        """INSERT INTO SecurityEvents
           (timestamp, source_id, event_type_id, message, ip_address, username)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (ts, source_id, event_type_id, message, ip_address, username),
    )
    conn.commit()
    return cur.lastrowid


def get_failed_logins_last_24h(conn):
    since = _ts(datetime.now() - timedelta(hours=24))
    return conn.execute(
        """SELECT e.id, e.timestamp, s.name AS source, e.ip_address, e.username, e.message
           FROM SecurityEvents e
           JOIN EventTypes t   ON t.id = e.event_type_id
           JOIN EventSources s ON s.id = e.source_id
           WHERE t.type_name = 'Login Failed' AND e.timestamp >= ?
           ORDER BY e.timestamp DESC""",
        (since,),
    ).fetchall()


def detect_bruteforce_ips(conn, threshold: int = 5):
    since = _ts(datetime.now() - timedelta(hours=1))
    return conn.execute(
        """SELECT e.ip_address, COUNT(*) AS attempts
           FROM SecurityEvents e
           JOIN EventTypes t ON t.id = e.event_type_id
           WHERE t.type_name = 'Login Failed'
             AND e.ip_address IS NOT NULL
             AND e.timestamp >= ?
           GROUP BY e.ip_address
           HAVING COUNT(*) > ?
           ORDER BY attempts DESC""",
        (since, threshold),
    ).fetchall()


def get_critical_events_last_week_by_source(conn):
    since = _ts(datetime.now() - timedelta(days=7))
    return conn.execute(
        """SELECT s.name AS source, e.timestamp, t.type_name, e.ip_address, e.message
           FROM SecurityEvents e
           JOIN EventTypes t   ON t.id = e.event_type_id
           JOIN EventSources s ON s.id = e.source_id
           WHERE t.severity = 'Critical' AND e.timestamp >= ?
           ORDER BY s.name, e.timestamp DESC""",
        (since,),
    ).fetchall()


def search_events_by_keyword(conn, keyword: str):
    return conn.execute(
        """SELECT e.id, e.timestamp, s.name AS source, t.type_name, e.message
           FROM SecurityEvents e
           JOIN EventTypes t   ON t.id = e.event_type_id
           JOIN EventSources s ON s.id = e.source_id
           WHERE e.message LIKE ?
           ORDER BY e.timestamp DESC""",
        (f"%{keyword}%",),
    ).fetchall()


def seed_data(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM EventTypes").fetchone()[0]:
        return

    for name, sev in [("Login Success", "Informational"), ("Login Failed", "Warning"),
                      ("Port Scan Detected", "Warning"), ("Malware Alert", "Critical")]:
        add_event_type(conn, name, sev)

    fw = add_event_source(conn, "Firewall_A", "192.168.1.1", "Firewall")
    web = add_event_source(conn, "Web_Server_Logs", "192.168.1.10", "Web Server")
    ids = add_event_source(conn, "IDS_Sensor_B", "192.168.1.20", "IDS")

    t_ok, t_fail, t_scan, t_mal = 1, 2, 3, 4
    now = datetime.now()

    for i in range(7):
        add_security_event(conn, web, t_fail, f"Failed login for user admin (attempt {i + 1})",
                           "203.0.113.45", "admin", now - timedelta(minutes=30 - i * 3))

    add_security_event(conn, web, t_ok, "User ivan logged in successfully",
                       "198.51.100.7", "ivan", now - timedelta(hours=2))
    add_security_event(conn, web, t_fail, "Failed login for user petro",
                       "198.51.100.23", "petro", now - timedelta(hours=5))
    add_security_event(conn, fw, t_scan, "Port scan detected: ports 20-1024 probed",
                       "192.0.2.99", None, now - timedelta(hours=3))
    add_security_event(conn, ids, t_mal, "Malware alert: trojan signature detected in traffic",
                       "10.0.0.15", "olena", now - timedelta(days=2))
    add_security_event(conn, fw, t_mal, "Malware alert: suspicious outbound connection to C2 server",
                       "10.0.0.42", None, now - timedelta(days=4))
    add_security_event(conn, ids, t_mal, "Malware alert: ransomware behaviour on host",
                       "10.0.0.77", "maria", now - timedelta(days=10))
    add_security_event(conn, fw, t_ok, "Admin logged in to firewall console",
                       "192.168.1.100", "root", now - timedelta(days=1))
    add_security_event(conn, ids, t_scan, "Port scan detected: SYN scan on 192.168.1.0/24",
                       "192.0.2.150", None, now - timedelta(hours=8))


def print_rows(title, rows):
    print(f"\n=== {title} ===")
    if not rows:
        print("(нічого не знайдено)")
    for r in rows:
        print(dict(r))


def main():
    conn = get_connection()
    create_tables(conn)
    seed_data(conn)

    try:
        vpn = add_event_source(conn, "VPN_Gateway", "192.168.1.30", "VPN")
        add_security_event(conn, vpn, 1, "VPN login success for user ivan", "198.51.100.7", "ivan")
    except sqlite3.IntegrityError:
        pass

    print_rows("Login Failed за 24 години", get_failed_logins_last_24h(conn))
    print_rows("IP з >5 невдалими входами за 1 годину", detect_bruteforce_ips(conn))
    print_rows("Critical за тиждень (за джерелом)", get_critical_events_last_week_by_source(conn))
    print_rows("Пошук за ключовим словом 'malware'", search_events_by_keyword(conn, "malware"))
    conn.close()


if __name__ == "__main__":
    main()