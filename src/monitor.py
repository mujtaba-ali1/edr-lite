import time
import psutil
import argparse
import json
import os
from datetime import datetime, timezone

from rule_engine import load_rules, match_rule
from colorama import Fore, Style, init

init(autoreset=True)

def utc_iso():
    return datetime.now(timezone.utc).isoformat()

class JsonlLogger:
    def __init__(self, path):
        self.path = path
        if self.path:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

    def write(self, event: dict):
        if not self.path:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            # Logging must never crash the monitor
            pass

class ProcessMonitor:
    def __init__(self, interval=1.0, rules_path=None, log_path=None, dry_run=True, quiet=False):
        self.interval = float(interval)
        self.last_pids = set()
        self.rules = load_rules(rules_path)
        self.logger = JsonlLogger(log_path)
        self.dry_run = dry_run
        self.quiet = quiet

        # Cache PID -> last known name so TERMINATED lines can show a name
        self.pid_name_cache = {}

    def scan(self):
        return {p.pid for p in psutil.process_iter(["pid"])}

    def detect_changes(self, current_pids):
        new = current_pids - self.last_pids
        gone = self.last_pids - current_pids
        for pid in new:
            yield ("CREATED", pid)
        for pid in gone:
            yield ("TERMINATED", pid)

    def _safe_get_proc_info(self, pid):
        info = {
            "pid": pid,
            "name": "<unknown>",
            "cmdline": "",
            "parent_pid": None,
            "parent_name": "",
            "username": "",
        }

        proc = psutil.Process(pid)

        try:
            info["name"] = proc.name()
        except Exception:
            pass

        try:
            cmd = proc.cmdline()
            if isinstance(cmd, list):
                info["cmdline"] = " ".join(cmd)
            else:
                info["cmdline"] = str(cmd) if cmd else ""
        except Exception:
            info["cmdline"] = ""

        try:
            info["username"] = proc.username() or ""
        except Exception:
            info["username"] = ""

        try:
            ppid = proc.ppid()
            info["parent_pid"] = ppid
            if ppid:
                try:
                    parent = psutil.Process(ppid)
                    info["parent_name"] = parent.name() or ""
                except Exception:
                    info["parent_name"] = ""
        except Exception:
            info["parent_pid"] = None
            info["parent_name"] = ""

        return info, proc

    def _should_block_termination(self, proc_info: dict) -> bool:
        name = (proc_info.get("name") or "").lower()
        pid = proc_info.get("pid")

        if pid in (0, 4):
            return True

        blocked_names = {
            "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
            "services.exe", "smss.exe", "system", "registry",
        }
        if name in blocked_names:
            return True

        if not name or name == "<unknown>":
            return True

        return False

    def alert(self, rule_id, severity, name, pid):
        sev = (severity or "MEDIUM").upper()
        color = {
            "LOW": Fore.GREEN,
            "MEDIUM": Fore.YELLOW,
            "HIGH": Fore.RED
        }.get(sev, Fore.WHITE)
        print(f"{color}[{sev}] Rule '{rule_id}' matched: {name} (PID {pid}){Style.RESET_ALL}")

    def run(self):
        print(f"Starting monitor (interval={self.interval}s)...")
        self.logger.write({
            "ts": utc_iso(),
            "type": "service_start",
            "interval": self.interval,
            "dry_run": self.dry_run,
        })

        # Baseline: prevent treating existing processes as CREATED
        self.last_pids = self.scan()

        # Prefill PID -> name cache so TERMINATED events usually have names
        for pid in list(self.last_pids):
            try:
                p = psutil.Process(pid)
                self.pid_name_cache[pid] = p.name()
            except Exception:
                self.pid_name_cache[pid] = "<unknown>"

        try:
            while True:
                time.sleep(self.interval)
                current = self.scan()

                for event, pid in self.detect_changes(current):
                    if event == "TERMINATED":
                        cached_name = self.pid_name_cache.get(pid, "<unknown>")
                        if not self.quiet:
                            print(f"TERMINATED PID={pid:<6} Name={cached_name}")

                        self.logger.write({
                            "ts": utc_iso(),
                            "type": "process_terminated",
                            "pid": pid,
                            "name": cached_name,
                        })

                        self.pid_name_cache.pop(pid, None)
                        continue

                    # CREATED path
                    try:
                        proc_info, proc = self._safe_get_proc_info(pid)
                        self.pid_name_cache[pid] = proc_info.get("name", "<unknown>")

                        self.logger.write({
                            "ts": utc_iso(),
                            "type": "process_created",
                            "pid": pid,
                            "name": proc_info.get("name", "<unknown>"),
                            "parent_name": proc_info.get("parent_name", ""),
                            "cmdline": proc_info.get("cmdline", ""),
                            "username": proc_info.get("username", ""),
                        })

                        matched_rule = match_rule(
                            {
                                "name": proc_info["name"],
                                "cmdline": proc_info["cmdline"],
                                "parent_name": proc_info["parent_name"],
                            },
                            self.rules
                        )

                        if matched_rule:
                            rule_id = matched_rule.get("id", "<no-id>")
                            severity = matched_rule.get("severity", "medium")
                            self.alert(rule_id, severity, proc_info["name"], pid)

                            resp = matched_rule.get("response", {}) or {}
                            wants_terminate = resp.get("terminate") is True
                            blocked = self._should_block_termination(proc_info)

                            self.logger.write({
                                "ts": utc_iso(),
                                "type": "detection",
                                "rule_id": rule_id,
                                "rule_description": matched_rule.get("description", ""),
                                "severity": severity,
                                "pid": pid,
                                "name": proc_info.get("name", "<unknown>"),
                                "parent_name": proc_info.get("parent_name", ""),
                                "cmdline": proc_info.get("cmdline", ""),
                                "username": proc_info.get("username", ""),
                                "response": {
                                    "terminate_requested": wants_terminate,
                                    "dry_run": self.dry_run,
                                    "blocked_by_guard": blocked,
                                }
                            })

                            if wants_terminate:
                                if blocked:
                                    print(f"[GUARD] Termination blocked for PID={pid} ({proc_info['name']})")
                                elif self.dry_run:
                                    print(f"[DRY-RUN] Would terminate PID={pid} ({proc_info['name']})")
                                else:
                                    try:
                                        proc.terminate()
                                        print(f"[ACTION] Terminated PID={pid} ({proc_info['name']})")
                                    except Exception as e:
                                        print(f"[ERROR] Could not terminate PID={pid}: {e}")
                        else:
                            if not self.quiet:
                                print(f"CREATED    PID={pid:<6} Name={proc_info['name']}")

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        if not self.quiet:
                            print(f"CREATED    PID={pid:<6} Name=<unknown>")
                        self.logger.write({
                            "ts": utc_iso(),
                            "type": "process_created",
                            "pid": pid,
                            "name": "<unknown>",
                            "error": "NoSuchProcess or AccessDenied"
                        })

                self.last_pids = current

        except KeyboardInterrupt:
            print("\nStopping monitor...")
            self.logger.write({
                "ts": utc_iso(),
                "type": "service_stop"
            })

def main():
    parser = argparse.ArgumentParser(description="Process Sentinel: EDR-lite process monitor")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    parser.add_argument("--rules", type=str, default=None, help="Path to rules.yaml (optional)")
    parser.add_argument("--log", type=str, default="logs/events.jsonl", help="Path to JSONL event log")
    parser.add_argument("--terminate", action="store_true", help="Actually terminate processes when rules request it")
    parser.add_argument("--quiet", action="store_true", help="Only print detections/actions (hide CREATED/TERMINATED)")
    args = parser.parse_args()

    dry_run = not args.terminate

    monitor = ProcessMonitor(
        interval=args.interval,
        rules_path=args.rules,
        log_path=args.log,
        dry_run=dry_run,
        quiet=args.quiet
    )
    monitor.run()

if __name__ == "__main__":
    main()
