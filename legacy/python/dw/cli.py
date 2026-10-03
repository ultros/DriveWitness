"""GUI-first entry point, automation subcommands and legacy flag aliases."""
import argparse
import json
import logging
import os
import signal
import sqlite3
import sys
from dataclasses import replace
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import __version__


class JsonLog(logging.Formatter):
    def format(self, record):
        return json.dumps({"time": datetime.now(timezone.utc).isoformat(), "level": record.levelname,
                           "component": record.name, "event": record.getMessage(),
                           "scan_id": getattr(record, "scan_id", None),
                           "exception": self.formatException(record.exc_info) if record.exc_info else None}, ensure_ascii=True)


def parser():
    p = argparse.ArgumentParser(description="DriveWitness: tamper-evident filesystem inventory")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")
    sub.add_parser("gui", help="Open the primary graphical interface")
    for name in ("list", "capabilities"):
        command = sub.add_parser(name)
        command.add_argument("--json", action="store_true")
    scan = sub.add_parser("scan")
    scan.add_argument("paths", nargs="+")
    scan.add_argument("--db")
    scan.add_argument("--config")
    scan.add_argument("--mode", choices=("quick", "verify", "forensic"))
    scan.add_argument("--performance", type=int)
    scan.add_argument("--workers", type=int)
    scan.add_argument("--blake3-threads", type=int)
    scan.add_argument("--gpu", choices=("auto", "off", "force"))
    scan.add_argument("--storage", choices=("unknown", "hdd", "ssd", "nvme", "remote"))
    scan.add_argument("--no-usn", action="store_true")
    scan.add_argument("--no-gpu", action="store_true")
    scan.add_argument("--full", action="store_true", help="Forensic dual-hash mode")
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--include", action="append", default=[])
    scan.add_argument("--anonymize", action="append", default=[])
    scan.add_argument("--anonymization-key", help="File containing at least 32 random bytes; never stored in evidence DB")
    scan.add_argument("--sign-key", help="Ed25519 private key PEM file")
    scan.add_argument("--key-password-env", help="Environment variable holding encrypted PEM password")
    scan.add_argument("--network-time", action="store_true", default=None)
    scan.add_argument("--resume", action="store_true", help="Start a new verification pass; preserve interrupted records")
    scan.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="WARNING")
    scan.add_argument("--log-file", help="Optional rotated structured application log")
    verify = sub.add_parser("verify", help="Verify stored roots/signature, or start a live verification pass")
    verify.add_argument("--db", required=True)
    verify.add_argument("--public-key", help="Trusted Ed25519 raw public key (32 bytes)")
    verify.add_argument("--live", action="store_true")
    verify.add_argument("--anonymization-key")
    verify.add_argument("--paths", nargs="+", help="Original roots for an anonymized live scan")
    verify.add_argument("--anonymize", action="append", default=[], help="Original anonymized subroots, if they cannot be inferred from --paths")
    verify.add_argument("--json", action="store_true")
    bench = sub.add_parser("benchmark")
    bench.add_argument("path")
    bench.add_argument("--json", action="store_true")
    bench.add_argument("--no-cache", action="store_true")
    export = sub.add_parser("export")
    export.add_argument("--db", required=True)
    export.add_argument("--manifest")
    export.add_argument("--errors", help="Stream errors/events to JSON Lines")
    export.add_argument("--scan-id", type=int)
    export.add_argument("--json", action="store_true")
    compare = sub.add_parser("compare")
    compare.add_argument("baseline")
    compare.add_argument("newer")
    compare.add_argument("--json", action="store_true")
    migrate = sub.add_parser("migrate", help="Add v2 tables without rewriting legacy evidence")
    migrate.add_argument("--db", required=True)
    migrate.add_argument("--json", action="store_true")
    return p


def aliases(argv):
    if "--list" in argv:
        return ["list"] + [x for x in argv if x != "--list"]
    if "--scan" in argv:
        argv = list(argv)
        argv.remove("--scan")
        return ["scan"] + argv
    return argv


def print_result(data):
    print(json.dumps(data, indent=2, ensure_ascii=True))


def scan_command(args):
    from .config import Config
    from .evidence import machine_id
    from .scanner import Scanner
    config = Config.load(args.config)
    overrides = {name: getattr(args, name) for name in ("mode", "performance", "workers", "blake3_threads", "gpu", "storage", "network_time") if getattr(args, name) is not None}
    if args.no_usn:
        overrides["usn_enabled"] = False
    if args.no_gpu:
        overrides["gpu"] = "off"
    if args.full:
        overrides["mode"] = "forensic"
    config = replace(config, **overrides).validate()
    if args.resume and (not args.db or not Path(args.db).is_file()):
        raise ValueError("--resume requires an existing --db; recovery starts a new pass")
    db = args.db or f"drive_witness_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_{machine_id()[:8]}_{os.urandom(4).hex()}.db"
    if args.log_file:
        handler = RotatingFileHandler(args.log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
        handler.setFormatter(JsonLog())
        logging.getLogger("drivewitness").addHandler(handler)
    logging.getLogger("drivewitness").setLevel(args.log_level)
    def progress(data):
        if not args.quiet and not args.json:
            print(f"\r{data['status']} {data['processed']:,}/{data['discovered']:,} files | {data['mb_per_sec']:.1f} MB/s | errors {data['errors']} | unstable {data['unstable']}   ", end="", file=sys.stderr, flush=True)
    scanner = Scanner(db, config, progress)
    old_handler = signal.signal(signal.SIGINT, lambda *_: scanner.cancel.set())
    try:
        result = scanner.run(args.paths, anonymize=args.anonymize,
                             anonymization_key=Path(args.anonymization_key).read_bytes() if args.anonymization_key else None,
                             excludes=args.exclude, includes=args.include, signing_key=args.sign_key,
                             signing_password=os.environ[args.key_password_env].encode() if args.key_password_env else None)
    finally:
        signal.signal(signal.SIGINT, old_handler)
    if not args.quiet and not args.json:
        print(file=sys.stderr)
    print_result(result)
    return 0 if result["status"] == "COMPLETED" else 130


def main(argv=None):
    argv = aliases(list(sys.argv[1:] if argv is None else argv))
    p = parser()
    args = p.parse_args(argv)
    try:
        if args.command in (None, "gui"):
            from .gui import main as gui_main
            gui_main()
        elif args.command == "scan":
            return scan_command(args)
        elif args.command == "list":
            from .windows import drives
            print_result(drives())
        elif args.command == "capabilities":
            from .windows import capabilities
            print_result({"version": __version__, **capabilities()})
        elif args.command == "benchmark":
            from .benchmark import benchmark
            print_result(benchmark(args.path, cache=not args.no_cache))
        elif args.command == "verify":
            from .evidence import connect, verify_database, verify_legacy
            if args.live:
                with connect(args.db, True) as conn:
                    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if "dw_scans" not in tables:
                        result = verify_legacy(conn)
                        print_result(result)
                        return 0 if result["valid"] else 2
                    row = conn.execute("SELECT scope FROM dw_scans WHERE status='COMPLETED' ORDER BY id DESC LIMIT 1").fetchone()
                    if not row:
                        if "files" in tables:
                            result = verify_legacy(conn)
                            print_result(result)
                            return 0 if result["valid"] else 2
                        raise ValueError("No completed baseline to verify")
                    scope = json.loads(row[0])
                live_roots = args.paths or scope["roots"]
                if any(root.startswith("hmac-sha256:") for root in live_roots):
                    raise ValueError("Anonymized live scans require --paths with the original roots")
                new_args = parser().parse_args(["scan", *live_roots, "--db", args.db, "--mode", "verify", "--no-usn"])
                new_args.include, new_args.exclude, new_args.anonymize = scope["include"], scope["exclude"], scope["anonymize"]
                new_args.anonymization_key, new_args.json = args.anonymization_key, args.json
                if scope["key_id"] and (not args.anonymization_key or
                        __import__("hashlib").sha256(Path(args.anonymization_key).read_bytes()).hexdigest() != scope["key_id"]):
                    raise ValueError("Live verification needs the original anonymization key")
                if scope["anonymize"]:
                    import hashlib
                    import hmac
                    from .scanner import normalized_root
                    from .evidence import canonical_path
                    key = Path(args.anonymization_key).read_bytes()
                    def identifier(path):
                        return "hmac-sha256:" + hmac.new(key, canonical_path(normalized_root(path)).encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
                    new_args.anonymize = args.anonymize or [root for root in live_roots if identifier(root) in scope["anonymize"]]
                    if set(map(identifier, new_args.anonymize)) != set(scope["anonymize"]):
                        raise ValueError("Supply --anonymize with the original anonymized subroots")
                return scan_command(new_args)
            result = verify_database(args.db, Path(args.public_key).read_bytes() if args.public_key else None)
            print_result(result)
            return 0 if result["valid"] else 2
        elif args.command == "export":
            from .evidence import connect, export_manifest
            if not args.manifest and not args.errors:
                raise ValueError("Specify --manifest and/or --errors")
            if args.manifest:
                export_manifest(args.db, args.manifest, args.scan_id)
            if args.errors:
                with connect(args.db, True) as conn, open(args.errors, "w", encoding="utf-8") as stream:
                    for row in conn.execute("SELECT * FROM dw_events" + (" WHERE scan_id=?" if args.scan_id else ""), (args.scan_id,) if args.scan_id else ()):
                        stream.write(json.dumps(dict(row), ensure_ascii=True) + "\n")
            print_result({"manifest": args.manifest, "errors": args.errors})
        elif args.command == "compare":
            from .scanner import compare_databases
            print_result(compare_databases(args.baseline, args.newer))
        elif args.command == "migrate":
            from .scanner import database_lock
            from .evidence import init_db
            if not Path(args.db).is_file():
                raise ValueError("Migration requires an existing database")
            with database_lock(args.db):
                conn = init_db(args.db, forensic=True)
                conn.close()
            print_result({"schema_version": 2, "legacy_records": "preserved unchanged"})
        return 0
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    except ImportError as exc:
        print(f"Missing dependency: {exc}. Install requirements.txt using this Python interpreter.", file=sys.stderr)
        return 2
