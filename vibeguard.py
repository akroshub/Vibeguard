import argparse
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from patterns import scan_line_for_secrets
from remediation import RemediationConfig, remediate

logging.basicConfig(format="[VIBEGUARD] %(levelname)s — %(message)s", level=logging.INFO)
logger = logging.getLogger("vibeguard")

WATCHED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".toml", ".sh"}
IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}
IGNORED_SUFFIXES = {".example", ".template", ".sample"}
DEBOUNCE_SECONDS = 0.5


@dataclass
class GuardConfig:
    watch_path: str
    dry_run: bool = False
    remediation: RemediationConfig = field(default_factory=RemediationConfig)


def is_ignored(path: str) -> bool:
    """Return True if this file should be skipped."""
    p = Path(path)
    if p.name == ".env":
        return True
    for suffix in IGNORED_SUFFIXES:
        if p.name.endswith(suffix):
            return True
    for part in p.parts:
        if part in IGNORED_DIRS:
            return True
    if p.suffix.lower() not in WATCHED_EXTENSIONS:
        return True
    return False


def scan_file(filepath: str, config: GuardConfig) -> None:
    """Read a file and scan each line for secrets."""
    try:
        content = Path(filepath).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    except OSError as e:
        logger.error(f"Cannot read {filepath} — {e}")
        return

    for line_number, line in enumerate(content.splitlines(), start=1):
        for finding in scan_line_for_secrets(line):
            remediate(
                filepath=filepath,
                line_number=line_number,
                secret_value=finding["match"],
                pattern_name=finding["pattern_name"],
                env_var_name=finding["env_var_name"],
                description=finding["description"],
                project_root=config.watch_path,
                config=config.remediation,
            )


class _DebounceHandler(FileSystemEventHandler):
    def __init__(self, config: GuardConfig):
        super().__init__()
        self._config = config
        self._timers: dict = {}
        self._lock = threading.Lock()

    def _handle(self, path: str):
        if is_ignored(path):
            return
        with self._lock:
            existing = self._timers.pop(path, None)
            if existing:
                existing.cancel()
            timer = threading.Timer(DEBOUNCE_SECONDS, scan_file, args=(path, self._config))
            self._timers[path] = timer
            timer.start()

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)


def run_scan(config: GuardConfig) -> None:
    """One-shot scan of all existing files."""
    watch = Path(config.watch_path)
    scanned = 0
    for ext in WATCHED_EXTENSIONS:
        for p in watch.rglob(f"*{ext}"):
            if not is_ignored(str(p)):
                scan_file(str(p), config)
                scanned += 1
    print(f"\n✅ Scan complete — {scanned} files checked.")


def run_watch(config: GuardConfig) -> None:
    """Start real-time directory monitoring."""
    handler = _DebounceHandler(config)
    observer = Observer()
    observer.schedule(handler, config.watch_path, recursive=True)
    observer.start()
    print(f"🛡️  VibeGuard is active — monitoring {os.path.abspath(config.watch_path)}")
    print("Watching for: OpenAI, Anthropic, AWS, Stripe, GitHub, Google keys + high-entropy secrets")
    print("Press Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n👋 VibeGuard stopped. Stay safe.")
    observer.join()


def main():
    parser = argparse.ArgumentParser(prog="vibeguard", description="🛡️  VibeGuard — API key leak prevention")
    parser.add_argument("--path", default=".", help="Directory to monitor")
    parser.add_argument("--dry-run", action="store_true", help="Report only, do not modify files")
    parser.add_argument("--scan", action="store_true", help="One-shot scan then exit")
    args = parser.parse_args()

    watch_path = os.path.abspath(args.path)
    if not os.path.isdir(watch_path):
        print(f"❌ Path not found: {watch_path}", file=sys.stderr)
        sys.exit(1)

    config = GuardConfig(
        watch_path=watch_path,
        dry_run=args.dry_run,
        remediation=RemediationConfig(dry_run=args.dry_run),
    )

    if args.dry_run:
        print("⚠️  Dry-run mode — no files will be modified.\n")

    if args.scan:
        print(f"🔍 Scanning {watch_path} ...\n")
        run_scan(config)
    else:
        run_watch(config)


if __name__ == "__main__":
    main()
