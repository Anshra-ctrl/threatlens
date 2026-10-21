"""ThreatLens detection engine.

Parses SSH authentication logs and flags brute-force attacks, password
spraying, possible account compromise, off-hours logins and direct root logins.
Standard library only (Python 3.8+).
"""

import random
import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Optional

# Example line this parser understands:
#   2026-10-08 02:10:05 web-01 sshd[4121]: Failed password for invalid user
#   root from 185.220.101.4 port 40022 ssh2
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# Detection thresholds
BRUTE_THRESHOLD = 5  # failures against one account...
BRUTE_WINDOW = timedelta(minutes=5)  # ...inside this window
SPRAY_USERS = 4  # distinct accounts failed from one IP
COMPROMISE_FAILS = 3  # failures right before a success
COMPROMISE_LOOKBACK = timedelta(hours=1)
OFF_HOURS = range(0, 5)  # 00:00 - 04:59
ROOT_USER = "root"

SEVERITY_POINTS = {"critical": 40, "high": 20, "medium": 8, "low": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Alert:  # pylint: disable=too-many-instance-attributes
    """One finding raised by a detection rule."""

    severity: str
    type: str
    ip: str
    user: Optional[str]
    time: str
    detail: str
    mitre_id: str
    mitre_name: str
    action: str


def _stamp(when):
    """Format a datetime the same way the logs do."""
    return when.strftime(TS_FORMAT)


def parse_log(text):
    """Return (events, skipped_line_count). Events are sorted by time."""
    events = []
    skipped = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = LINE_RE.match(line)
        if not match:
            skipped += 1
            continue
        ip = match.group("ip")
        if any(int(part) > 255 for part in ip.split(".")):
            skipped += 1
            continue
        try:
            when = datetime.strptime(match.group("ts"), TS_FORMAT)
        except ValueError:
            skipped += 1
            continue
        events.append(
            {
                "time": when,
                "host": match.group("host"),
                "ok": match.group("status") == "Accepted",
                "user": match.group("user"),
                "ip": ip,
            }
        )
    events.sort(key=lambda e: e["time"])
    return events, skipped


def _densest_window(fails):
    """Largest number of failures inside BRUTE_WINDOW: (count, start, end) or None."""
    best_count, best_start, best_end = 0, None, None
    left = 0
    for right, event in enumerate(fails):
        while event["time"] - fails[left]["time"] > BRUTE_WINDOW:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count, best_start, best_end = count, fails[left]["time"], event["time"]
    if best_count == 0:
        return None
    return best_count, best_start, best_end


def _brute_force_alerts(ip, fails):
    """Rule 1: many failed logins against ONE account in a short window."""
    per_user = defaultdict(list)
    for event in fails:
        per_user[event["user"]].append(event)
    windows = {}
    for user, user_fails in per_user.items():
        window = _densest_window(user_fails)
        if window:
            windows[user] = window
    if not windows:
        return []
    user = max(sorted(windows), key=lambda name: windows[name][0])
    count, start, end = windows[user]
    if count < BRUTE_THRESHOLD:
        return []
    seconds = max(1, int((end - start).total_seconds()))
    return [
        Alert(
            severity="high" if count >= 20 else "medium",
            type="Brute-force attack",
            ip=ip,
            user=user,
            time=_stamp(start),
            detail=f"{count} failed logins against '{user}' within {seconds} seconds.",
            mitre_id="T1110.001",
            mitre_name="Password Guessing",
            action=(
                f"Block {ip} at the firewall and enforce account lockout "
                "or key-only SSH login."
            ),
        )
    ]


def _spray_alerts(ip, fails):
    """Rule 2: failed logins spread across MANY accounts (password spraying)."""
    users = sorted({event["user"] for event in fails})
    if len(users) < SPRAY_USERS:
        return []
    shown = ", ".join(users[:5]) + (", ..." if len(users) > 5 else "")
    return [
        Alert(
            severity="high",
            type="Password spraying",
            ip=ip,
            user=None,
            time=_stamp(fails[0]["time"]),
            detail=(
                f"{len(fails)} failed logins across {len(users)} "
                f"different accounts ({shown})."
            ),
            mitre_id="T1110.003",
            mitre_name="Password Spraying",
            action=(
                f"Block {ip} and check whether any of the targeted accounts "
                "logged in successfully."
            ),
        )
    ]


def _compromise_alerts(ip, fails, wins):
    """Rule 3: a successful login right after repeated failures from the same IP."""
    fail_times = [event["time"] for event in fails]
    alerts = []
    seen_users = set()
    for success in wins:
        user = success["user"]
        if user in seen_users:
            continue
        low = bisect_left(fail_times, success["time"] - COMPROMISE_LOOKBACK)
        high = bisect_right(fail_times, success["time"])
        recent_fails = high - low
        if recent_fails >= COMPROMISE_FAILS:
            seen_users.add(user)
            alerts.append(
                Alert(
                    severity="critical",
                    type="Possible account compromise",
                    ip=ip,
                    user=user,
                    time=_stamp(success["time"]),
                    detail=(
                        f"'{user}' logged in successfully right after "
                        f"{recent_fails} failed attempts from the same address."
                    ),
                    mitre_id="T1078",
                    mitre_name="Valid Accounts",
                    action=(
                        f"Reset the password for '{user}', end active sessions "
                        "and review what the account did next."
                    ),
                )
            )
    return alerts


def _off_hours_alerts(ip, wins, skip_users):
    """Rule 4: successful logins outside working hours (skips already-compromised users)."""
    alerts = []
    seen_users = set(skip_users)
    for success in wins:
        user = success["user"]
        if user in seen_users or success["time"].hour not in OFF_HOURS:
            continue
        seen_users.add(user)
        alerts.append(
            Alert(
                severity="medium",
                type="Off-hours login",
                ip=ip,
                user=user,
                time=_stamp(success["time"]),
                detail=(
                    f"Successful login for '{user}' at "
                    f"{success['time'].strftime('%H:%M')}, outside normal working hours."
                ),
                mitre_id="T1078",
                mitre_name="Valid Accounts",
                action="Confirm with the account owner that this login was expected.",
            )
        )
    return alerts


def _root_login_alerts(ip, wins):
    """Rule 5: root should rarely log in directly over SSH (one alert per IP)."""
    root_wins = [event for event in wins if event["user"] == ROOT_USER]
    if not root_wins:
        return []
    if len(root_wins) == 1:
        detail = f"Successful login as '{ROOT_USER}' directly over SSH."
    else:
        detail = (
            f"{len(root_wins)} successful logins as '{ROOT_USER}' directly over SSH."
        )
    return [
        Alert(
            severity="high",
            type="Root login",
            ip=ip,
            user=ROOT_USER,
            time=_stamp(root_wins[0]["time"]),
            detail=detail,
            mitre_id="T1078",
            mitre_name="Valid Accounts",
            action="Disable direct root SSH login and use a normal account with sudo instead.",
        )
    ]


def _timeline(events):
    """Hourly buckets (or daily when the log spans more than a week)."""
    if not events:
        return "hour", []
    first, last = events[0]["time"], events[-1]["time"]
    by_day = (last - first) > timedelta(days=7)
    fmt = "%Y-%m-%d" if by_day else "%Y-%m-%d %H:00"
    counts = defaultdict(lambda: [0, 0])  # [failed, accepted]
    for event in events:
        counts[event["time"].strftime(fmt)][1 if event["ok"] else 0] += 1
    if by_day:
        keys = sorted(counts)
    else:
        keys = []
        cursor = first.replace(minute=0, second=0, microsecond=0)
        end = last.replace(minute=0, second=0, microsecond=0)
        while cursor <= end:
            keys.append(cursor.strftime(fmt))
            cursor += timedelta(hours=1)
    points = [
        {"label": key, "failed": counts[key][0], "accepted": counts[key][1]}
        for key in keys
    ]
    return ("day" if by_day else "hour"), points


def _risk_level(score, has_events):
    """Turn a 0-100 score into a label."""
    if not has_events:
        return "No data"
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 15:
        return "Elevated"
    return "Low"


def _recommendations(alerts):
    """Build the 'next steps' list from the kinds of alerts raised."""
    kinds = {alert.type for alert in alerts}
    recs = []
    if "Possible account compromise" in kinds:
        recs.append(
            "Reset the password of every compromised account, end its active sessions, "
            "and review what it did after the suspicious login."
        )
        recs.append("Require multi-factor authentication for remote access.")
    if kinds & {"Brute-force attack", "Password spraying"}:
        recs.append(
            "Block the attacking IP addresses at the firewall and enable automatic "
            "banning (for example fail2ban) and account lockout."
        )
        recs.append("Turn off SSH password login and require key-based authentication.")
    if "Root login" in kinds:
        recs.append(
            "Disable direct root login over SSH and use named accounts with sudo."
        )
    if "Off-hours login" in kinds:
        recs.append(
            "Confirm each off-hours login with the account owner and alert on logins "
            "outside working hours."
        )
    if not recs:
        recs.append(
            "No suspicious patterns found. Keep collecting logs and run the "
            "analysis regularly."
        )
    return recs


def _top_sources(by_ip):
    """The IPs with the most failed logins, worst first."""
    sources = []
    for ip, evs in by_ip.items():
        failed = sum(1 for event in evs if not event["ok"])
        if failed:
            sources.append(
                {
                    "ip": ip,
                    "failed": failed,
                    "accepted": len(evs) - failed,
                    "accounts": len({event["user"] for event in evs}),
                }
            )
    sources.sort(key=lambda source: (-source["failed"], source["ip"]))
    return sources[:8]


def _summary(events, skipped, alerts, unique_ips):
    """Headline numbers shown at the top of the dashboard."""
    score = min(100, sum(SEVERITY_POINTS[alert.severity] for alert in alerts))
    failed = sum(1 for event in events if not event["ok"])
    return {
        "events": len(events),
        "failed": failed,
        "accepted": len(events) - failed,
        "unique_ips": unique_ips,
        "skipped": skipped,
        "alert_count": len(alerts),
        "risk_score": score,
        "risk_level": _risk_level(score, bool(events)),
        "first_seen": _stamp(events[0]["time"]) if events else None,
        "last_seen": _stamp(events[-1]["time"]) if events else None,
    }


def analyze(text):
    """Analyze raw log text and return a JSON-serializable report."""
    events, skipped = parse_log(text)

    by_ip = defaultdict(list)
    for event in events:
        by_ip[event["ip"]].append(event)

    alerts = []
    for ip in sorted(by_ip):
        fails = [event for event in by_ip[ip] if not event["ok"]]
        wins = [event for event in by_ip[ip] if event["ok"]]
        compromise = _compromise_alerts(ip, fails, wins)
        compromised_users = {alert.user for alert in compromise}
        alerts += _brute_force_alerts(ip, fails)
        alerts += _spray_alerts(ip, fails)
        alerts += compromise
        alerts += _off_hours_alerts(ip, wins, compromised_users)
        alerts += _root_login_alerts(ip, wins)

    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.time, a.ip))
    bucket, points = _timeline(events)

    return {
        "summary": _summary(events, skipped, alerts, len(by_ip)),
        "alerts": [asdict(alert) for alert in alerts],
        "top_sources": _top_sources(by_ip),
        "timeline": {"bucket": bucket, "points": points},
        "recommendations": _recommendations(alerts),
    }


def _workday_time(rng, day):
    """A random time between 08:00 and 17:59 on the given day."""
    return day + timedelta(
        hours=rng.randint(8, 17),
        minutes=rng.randint(0, 59),
        seconds=rng.randint(0, 59),
    )


def generate_sample(seed=7):
    """Build a realistic demo log: normal traffic plus four attack patterns."""
    # Seeded random is intentional: it makes the fake demo logs repeatable.
    # Nothing security-sensitive is generated, so Bandit's B311 does not apply.
    rng = random.Random(seed)  # nosec B311
    day = datetime(2026, 10, 8)
    rows = []

    def add(when, ok, user, ip, invalid=False):
        status = "Accepted" if ok else "Failed"
        who = ("invalid user " if invalid else "") + user
        pid = rng.randint(1000, 9999)
        port = rng.randint(20000, 65000)
        rows.append(
            (
                when,
                f"{_stamp(when)} web-01 sshd[{pid}]: {status} password for {who} "
                f"from {ip} port {port} ssh2",
            )
        )

    # Normal working-day traffic (plus a few harmless typos)
    staff = [("alice", "10.0.0.21"), ("bob", "10.0.0.34"), ("carol", "10.0.0.58")]
    for _ in range(45):
        user, ip = rng.choice(staff)
        add(_workday_time(rng, day), True, user, ip)
    for _ in range(4):
        user, ip = rng.choice(staff)
        add(_workday_time(rng, day), False, user, ip)

    # Attack 1: brute force against root
    when = day + timedelta(hours=2, minutes=10)
    for _ in range(60):
        add(when, False, ROOT_USER, "185.220.101.4", invalid=True)
        when += timedelta(seconds=rng.randint(3, 7))

    # Attack 2: password spraying across many accounts
    names = [
        "admin", "test", "guest", "oracle", "ubuntu", "postgres",
        "user", "ftp", "git", "jenkins", "support", "backup",
    ]  # fmt: skip
    when = day + timedelta(hours=13, minutes=20)
    for name in names:
        for _ in range(2):
            add(when, False, name, "45.155.205.9", invalid=True)
            when += timedelta(seconds=rng.randint(15, 25))

    # Attack 3: brute force that ends in a successful login
    when = day + timedelta(hours=21, minutes=5)
    for _ in range(14):
        add(when, False, "deploy", "91.240.118.77")
        when += timedelta(seconds=rng.randint(4, 6))
    add(when, True, "deploy", "91.240.118.77")

    # Attack 4: suspicious off-hours login from a new address
    add(day + timedelta(hours=3, minutes=12, seconds=41), True, "bob", "203.0.113.50")

    rows.sort(key=lambda row: row[0])
    return "\n".join(line for _, line in rows) + "\n"
