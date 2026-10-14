"""Consent gate: nothing is cloned, read, executed, sent to an LLM, or written until a person has
explicitly authorised exactly that, for exactly this repository.

Design rules
  * Scoped:      read / execute / llm / write are separate. Consent to analyse is NOT consent to run tests or push.
  * Explicit:    typing the repository name (not "y"), an explicit flag, or a standing consent file that EXPIRES.
  * Bound:       a consent names one repository; it cannot be reused for another.
  * Honest:      the person is shown what will happen, what will not, and where results go.
  * Verified:    trust (do you actually have write access?) comes from GitHub / the filesystem, never from a
                 file or flag the requester supplies. Untrusted repos get no write scope and tests only in Docker.
  * Not in the repo: standing consent files are read from the agent side only, never from the analysed repo.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import yaml

NOTICE_VERSION = "1"
MAX_STANDING_DAYS_DEFAULT = 90
ONE_RUN_TTL = timedelta(hours=1)
DEFAULT_ALLOWED_HOSTS = ["github.com"]

SCOPES: dict[str, str] = {
    "read": "Clone the repository and READ its source files (read-only). Nothing from it is executed.",
    "execute": "RUN the repository's own tests/build inside an isolated sandbox (no network, no credentials).",
    "llm": "Send small, secret-redacted code snippets to the configured LLM provider for triage.",
    "write": "Push ONE new branch named agent/... and open a pull request. Never merges, never touches main.",
}
SCOPE_ORDER = ["read", "execute", "llm", "write"]


class ConsentError(Exception):
    """Access must not proceed."""


# ---------------------------------------------------------------------------------------------
# Repository reference (strictly validated: this string ends up in `git clone`)
# ---------------------------------------------------------------------------------------------
_URL_RX = re.compile(r"^https://(?P<host>[A-Za-z0-9.-]+)/(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$")


@dataclass
class RepoRef:
    raw: str
    kind: str                    # "url" | "local"
    slug: str                    # "owner/name"  (local: directory name)
    canonical: str               # "host/owner/name"  (local: "local:/abs/path")
    host: str = ""
    clone_url: str = ""
    path: Path | None = None

    def matches(self, name: str) -> bool:
        return name.strip().lower() in (self.slug.lower(), self.canonical.lower())


def parse_repo_ref(repo: str, allowed_hosts: list[str] | None = None) -> RepoRef:
    allowed = [h.lower() for h in (allowed_hosts or DEFAULT_ALLOWED_HOSTS)]
    raw = (repo or "").strip()
    if not raw:
        raise ConsentError("no repository given")
    if raw.startswith("-"):
        raise ConsentError("repository value looks like a command-line option")
    if any(ord(c) < 32 or c.isspace() for c in raw):
        raise ConsentError("repository value contains whitespace or control characters")
    if "://" in raw or raw.startswith("ext::") or "::" in raw:
        parts = urlsplit(raw)
        if parts.scheme != "https":
            raise ConsentError(f"only https:// repository URLs are accepted (got '{parts.scheme or raw.split('::')[0]}')")
        if parts.username or parts.password or "@" in parts.netloc:
            raise ConsentError("credentials inside the URL are not allowed (tokens would leak into logs); use AGENT_READ_TOKEN")
        if parts.query or parts.fragment or parts.port:
            raise ConsentError("URL must be plain https://host/owner/name")
        m = _URL_RX.match(raw)
        if not m or m.group("owner") in (".", "..") or m.group("name") in (".", ".."):
            raise ConsentError("expected https://<host>/<owner>/<repository>")
        host = m.group("host").lower()
        if host not in allowed:
            raise ConsentError(f"host '{host}' is not allowlisted (allowed: {', '.join(allowed)}); add it in policy consent.allowed_hosts")
        owner, name = m.group("owner"), m.group("name")
        return RepoRef(raw, "url", f"{owner}/{name}", f"{host}/{owner}/{name}".lower(), host,
                       f"https://{host}/{owner}/{name}.git")
    p = Path(raw).expanduser()
    if p.is_dir():
        p = p.resolve()
        return RepoRef(raw, "local", p.name, f"local:{p}", "", "", p)
    raise ConsentError("repository must be an https URL or an existing local directory")


# ---------------------------------------------------------------------------------------------
# Repository facts (metadata only; no code is read)
# ---------------------------------------------------------------------------------------------
@dataclass
class RepoInfo:
    source: str = "unavailable"            # github_api | local | unavailable
    visibility: str = "unknown"            # public | private | local | unknown
    owner: str = ""
    license: str = ""
    default_branch: str = ""
    archived: bool = False
    fork: bool = False
    permissions: dict = field(default_factory=dict)
    trust: str = "untrusted"               # trusted | untrusted
    trust_reason: str = "could not be verified"

    def to_dict(self) -> dict:
        return asdict(self)


def info_from_github_json(data: dict) -> RepoInfo:
    perms = data.get("permissions") or {}
    trusted = bool(perms.get("push") or perms.get("admin") or perms.get("maintain"))
    return RepoInfo(
        source="github_api", visibility="private" if data.get("private") else "public",
        owner=(data.get("owner") or {}).get("login", ""), license=((data.get("license") or {}).get("spdx_id") or ""),
        default_branch=data.get("default_branch", ""), archived=bool(data.get("archived")), fork=bool(data.get("fork")),
        permissions={k: bool(v) for k, v in perms.items()},
        trust="trusted" if trusted else "untrusted",
        trust_reason=("your token has write access" if trusted else
                      "no write access for the credentials in use (public third-party repo, or no token supplied)"),
    )


def fetch_repo_info(ref: RepoRef, token: str | None = None, timeout: int = 10) -> RepoInfo:
    if ref.kind == "local":
        mine = False
        try:
            mine = ref.path is not None and ref.path.stat().st_uid == os.geteuid()  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass
        return RepoInfo(source="local", visibility="local", owner=getpass.getuser(), trust="trusted" if mine else "untrusted",
                        trust_reason="local directory owned by the current user" if mine else "local directory not owned by the current user")
    if ref.host != "github.com":
        return RepoInfo(trust_reason=f"host {ref.host} is not queried; treated as untrusted")
    req = urllib.request.Request(f"https://api.github.com/repos/{ref.slug}", headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "maintenance-agent",
        **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return info_from_github_json(json.loads(resp.read().decode()))
    except urllib.error.HTTPError as e:
        why = {404: "not found, or private and no valid token supplied", 403: "rate-limited or forbidden"}.get(e.code, f"HTTP {e.code}")
        return RepoInfo(trust_reason=f"GitHub API: {why}")
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        return RepoInfo(trust_reason=f"GitHub API unreachable ({type(e).__name__})")


# ---------------------------------------------------------------------------------------------
# What is needed, and the notice shown to the person
# ---------------------------------------------------------------------------------------------
def needed_scopes(run_tests: bool, use_llm: bool, open_pr: bool) -> list[str]:
    s = ["read"]
    if run_tests:
        s.append("execute")
    if use_llm:
        s.append("llm")
    if open_pr:
        s.append("write")
    return [x for x in SCOPE_ORDER if x in s]


def render_notice(ref: RepoRef, scopes: list[str], info: RepoInfo, identity: str, ttl_text: str,
                  deny_read: list[str], out_dir: str) -> str:
    if info.source == "local":
        facts = []
    elif info.source == "unavailable":
        facts = ["repository details could not be fetched"]
    else:
        facts = [info.visibility, info.license or "no license detected"]
    if info.archived:
        facts.append("archived")
    if info.fork:
        facts.append("fork")
    trust_line = ("TRUSTED  - " if info.trust == "trusted" else "UNTRUSTED  - ") + info.trust_reason
    lines = [
        "=" * 78,
        " ACCESS NOTICE: please read before continuing",
        "=" * 78,
        f" The Code Maintenance Agent is about to access this repository:",
        "",
        f"   Repository : {ref.slug}   ({'; '.join([ref.host or 'local directory'] + facts)})",
        f"   Trust      : {trust_line}",
        f"   Requested by: {identity}",
        "",
        " Permissions requested (each is separate and only what is listed will be allowed):",
    ]
    for s in scopes:
        lines.append(f"   [{s:<7}] {SCOPES[s]}")
    lines += [
        "",
        " What the agent will NOT do:",
        f"   - open files that look like secrets ({', '.join(deny_read[:6])}, ...): they are only listed by name",
        "   - modify tests, CI/CD, build files, or other protected paths",
        "   - merge, approve, or push to any branch other than its own agent/... branch",
        "   - send your code to any third party" + ("" if "llm" in scopes else " (the 'llm' permission is NOT requested)"),
    ]
    if "execute" in scopes and info.trust != "trusted":
        lines.append("   - run this repository's code outside the Docker sandbox (it is untrusted)")
    lines += [
        "",
        f" Results (report, patch, audit log) are written to: {out_dir}",
        f" This consent: {ttl_text}",
        " Before this notice the agent asked GitHub's API only for repository METADATA (visibility, permissions,",
        " license). No code has been read yet.",
        "=" * 78,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------
# The consent record
# ---------------------------------------------------------------------------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_dt(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc)
    if isinstance(v, str):
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    raise ValueError("not a date")


@dataclass
class ConsentRecord:
    repo: str                       # canonical
    repo_display: str
    scopes: list[str]
    granted_by: str
    method: str                     # interactive | flag | file | programmatic
    granted_at: str
    expires_at: str
    notice_version: str = NOTICE_VERSION
    notice_sha256: str = ""
    trust: str = "untrusted"
    trust_reason: str = ""
    repo_info: dict = field(default_factory=dict)
    ci_run: str = ""

    def covers(self, scopes: list[str]) -> bool:
        return set(scopes) <= set(self.scopes)

    def is_valid(self, now: datetime | None = None) -> bool:
        return (now or _utcnow()) < _to_dt(self.expires_at)

    def to_dict(self) -> dict:
        return asdict(self)


def _identity() -> str:
    return os.environ.get("GITHUB_ACTOR") or getpass.getuser()


def _ci_run() -> str:
    if os.environ.get("GITHUB_RUN_ID") and os.environ.get("GITHUB_REPOSITORY"):
        return f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    return ""


def _make(ref: RepoRef, scopes: list[str], info: RepoInfo, who: str, method: str, granted: datetime,
          expires: datetime, notice: str) -> ConsentRecord:
    return ConsentRecord(ref.canonical, ref.slug, sorted(set(scopes), key=SCOPE_ORDER.index), who, method,
                         granted.isoformat(), expires.isoformat(), NOTICE_VERSION,
                         hashlib.sha256(notice.encode()).hexdigest(), info.trust, info.trust_reason, info.to_dict(), _ci_run())


def _enforce_trust(scopes: list[str], info: RepoInfo) -> None:
    if "write" in scopes and info.trust != "trusted":
        raise ConsentError("write access cannot be granted: you do not have verified write access to this repository "
                           f"({info.trust_reason}). Use analyze/verify modes, or supply a token that has push access.")


def from_flag(ref: RepoRef, value: str, scopes: list[str], info: RepoInfo, notice: str, now: datetime) -> ConsentRecord:
    if ":" not in value:
        raise ConsentError("--consent must look like  <owner/name>:<scope,scope>  e.g.  acme/shop:read,execute")
    name, _, granted_scopes = value.rpartition(":")
    if not ref.matches(name):
        raise ConsentError(f"--consent names '{name}', but the requested repository is '{ref.slug}'")
    given = [s.strip() for s in granted_scopes.split(",") if s.strip()]
    bad = [s for s in given if s not in SCOPES]
    if bad:
        raise ConsentError(f"unknown scope(s): {', '.join(bad)} (valid: {', '.join(SCOPE_ORDER)})")
    missing = [s for s in scopes if s not in given]
    if missing:
        raise ConsentError(f"this run needs permission(s) not granted by --consent: {', '.join(missing)}")
    return _make(ref, given, info, _identity(), "flag", now, now + ONE_RUN_TTL, notice)


def from_file(ref: RepoRef, path: str | Path, scopes: list[str], info: RepoInfo, notice: str, now: datetime,
              max_days: int = MAX_STANDING_DAYS_DEFAULT) -> ConsentRecord:
    p = Path(path)
    if ref.path is not None:   # local repo: a consent file living INSIDE the repo would be self-granted consent
        try:
            p.resolve().relative_to(ref.path)
            raise ConsentError("the consent file is inside the repository being analysed; it must live outside it")
        except ValueError:
            pass
    if not p.is_file() or p.is_symlink():
        raise ConsentError(f"consent file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")[:20_000]) or {}
        granted, expires = _to_dt(raw["granted_at"]), _to_dt(raw["expires_at"])
    except (yaml.YAMLError, KeyError, ValueError, TypeError) as e:
        raise ConsentError(f"consent file is invalid ({type(e).__name__}): needs granted_at and expires_at") from e
    if not str(raw.get("repo", "")).strip() or not ref.matches(str(raw["repo"])):
        raise ConsentError(f"consent file is for '{raw.get('repo')}', not '{ref.slug}'")
    who = str(raw.get("granted_by", "")).strip()
    if not who:
        raise ConsentError("consent file must name who granted it (granted_by)")
    if str(raw.get("notice_version")) != NOTICE_VERSION:
        raise ConsentError(f"consent file was given for notice version {raw.get('notice_version')}; current is {NOTICE_VERSION}. Re-grant it.")
    if expires <= now:
        raise ConsentError(f"consent expired on {expires.date()}; re-grant it")
    if granted > now + timedelta(days=1):
        raise ConsentError("consent file is dated in the future")
    if (expires - granted).days > max_days:
        raise ConsentError(f"standing consent may last at most {max_days} days")
    given = raw.get("scopes") or []
    if not isinstance(given, list) or any(s not in SCOPES for s in given):
        raise ConsentError("consent file has an invalid scopes list")
    missing = [s for s in scopes if s not in given]
    if missing:
        raise ConsentError(f"this run needs permission(s) not in the consent file: {', '.join(missing)}")
    return _make(ref, given, info, who, "file", granted, expires, notice)   # trust comes from `info`, never the file


def from_prompt(ref: RepoRef, scopes: list[str], info: RepoInfo, notice: str, now: datetime,
                input_fn: Callable[[str], str] = input, print_fn: Callable[[str], None] = print,
                isatty: Callable[[], bool] | None = None) -> ConsentRecord:
    if not (isatty() if isatty else sys.stdin.isatty()):
        raise ConsentError("no consent given and this is not an interactive terminal. Re-run with "
                           f"--consent {ref.slug}:{','.join(scopes)}  or  --consent-file <file>.")
    print_fn(notice)
    answer = input_fn(f"\nType the repository name ({ref.slug}) to authorise this access, anything else cancels: ").strip()
    if answer.lower() != ref.slug.lower():
        raise ConsentError("consent not given: the repository name was not confirmed")
    return _make(ref, scopes, info, _identity(), "interactive", now, now + ONE_RUN_TTL, notice)


def grant_all(repo: str, trust: str = "trusted", who: str = "programmatic", allowed_hosts: list[str] | None = None) -> ConsentRecord:
    """For callers that handle consent themselves (library use, automated tests). Not reachable from the CLI."""
    ref = parse_repo_ref(repo, allowed_hosts)
    now = _utcnow()
    info = RepoInfo(source="local", trust=trust, trust_reason="supplied by the calling program")
    return _make(ref, list(SCOPE_ORDER), info, who, "programmatic", now, now + ONE_RUN_TTL, "programmatic")


def validate_record(rec: ConsentRecord, ref: RepoRef, scopes: list[str], info: RepoInfo, now: datetime) -> ConsentRecord:
    if rec.repo.lower() != ref.canonical.lower():
        raise ConsentError(f"consent was granted for '{rec.repo_display}', not '{ref.slug}'")
    if not rec.covers(scopes):
        raise ConsentError(f"consent does not cover: {', '.join(s for s in scopes if s not in rec.scopes)}")
    if not rec.is_valid(now):
        raise ConsentError("consent has expired")
    if rec.notice_version != NOTICE_VERSION:
        raise ConsentError("consent was given for an older notice version; re-grant it")
    if not rec.granted_by.strip():
        raise ConsentError("consent has no named grantor")
    rec.trust, rec.trust_reason = info.trust, info.trust_reason       # always re-derived, never taken on trust
    return rec


def obtain_consent(ref: RepoRef, scopes: list[str], info: RepoInfo, *, record: ConsentRecord | None = None,
                   consent_flag: str | None = None, consent_file: str | None = None, interactive: bool = False,
                   deny_read: list[str] | None = None, out_dir: str = "./agent-runs", max_days: int = MAX_STANDING_DAYS_DEFAULT,
                   input_fn: Callable[[str], str] = input, print_fn: Callable[[str], None] = print,
                   isatty: Callable[[], bool] | None = None, now: datetime | None = None) -> tuple[ConsentRecord, str]:
    """Returns (record, notice_text). Raises ConsentError if consent is missing or insufficient."""
    now = now or _utcnow()
    _enforce_trust(scopes, info)
    ttl = (f"applies to THIS RUN only (expires {(now + ONE_RUN_TTL).strftime('%H:%M UTC')})"
           if not consent_file else f"standing consent from file {consent_file}, valid until it expires (max {max_days} days)")
    notice = render_notice(ref, scopes, info, _identity(), ttl, deny_read or [], out_dir)
    if record is not None:
        return validate_record(record, ref, scopes, info, now), notice
    if consent_file:
        return from_file(ref, consent_file, scopes, info, notice, now, max_days), notice
    if consent_flag:
        return from_flag(ref, consent_flag, scopes, info, notice, now), notice
    if interactive:
        return from_prompt(ref, scopes, info, notice, now, input_fn, print_fn, isatty), notice
    raise ConsentError(
        "consent required: the agent will not access a repository until a person authorises it.\n"
        f"  interactive : run in a terminal and type the repository name when asked\n"
        f"  one run     : --consent {ref.slug}:{','.join(scopes)}\n"
        f"  standing    : python -m agent consent grant <repo-url> --scopes {','.join(scopes)} --days 30 --out consents/x.yml\n"
        f"                then --consent-file consents/x.yml")


def write_consent_file(path: str | Path, ref: RepoRef, scopes: list[str], granted_by: str, days: int,
                       now: datetime | None = None, max_days: int = MAX_STANDING_DAYS_DEFAULT) -> Path:
    now = now or _utcnow()
    if not 1 <= days <= max_days:
        raise ConsentError(f"--days must be between 1 and {max_days}")
    if any(s not in SCOPES for s in scopes) or not scopes:
        raise ConsentError("invalid scopes")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {"repo": ref.slug, "scopes": scopes, "granted_by": granted_by, "granted_at": now.date().isoformat(),
            "expires_at": (now + timedelta(days=days)).date().isoformat(), "notice_version": NOTICE_VERSION}
    p.write_text("# Standing consent for the Code Maintenance Agent. Delete this file to revoke.\n"
                 "# Keep it OUTSIDE the repository being analysed. It expires automatically.\n"
                 + yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return p


def web_consent(ref: RepoRef, scopes: list[str], info: RepoInfo, typed: str, who: str, deny_read: list[str],
                out_dir: str, now: datetime | None = None) -> tuple[ConsentRecord, str]:
    """Consent given through the web UI: the person must have typed the repository name (not clicked 'OK')."""
    now = now or _utcnow()
    _enforce_trust(scopes, info)
    if not isinstance(typed, str) or typed.strip().lower() != ref.slug.lower():
        raise ConsentError("consent not given: the repository name was not confirmed")
    notice = render_notice(ref, scopes, info, who, f"applies to THIS RUN only (expires {(now + ONE_RUN_TTL).strftime('%H:%M UTC')})",
                           deny_read, out_dir)
    return _make(ref, scopes, info, who, "web", now, now + ONE_RUN_TTL, notice), notice
