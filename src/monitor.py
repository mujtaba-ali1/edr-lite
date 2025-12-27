import time
import psutil
import argparse
from datetime import datetime, timezone

from rule_engine import load_rules, match_rule
from colorama import Fore, Style, init

init(autoreset=True)

class ProcessMonitor:
    def __init__(self, interval=1.0, rules_path=None):
        self.interval = float(interval)
        self.last_pids = set()
        self.rules = load_rules(rules_path)

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
        """
        Best-effort collection of metadata.
        Missing fields are allowed.
        """
        info = {
            "pid": pid,
            "name": "<unknown>",
            "cmdline": "",
            "parent_pid": None,
            "parent_name": "",
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
        self.last_pids = self.scan()

        try:
            while True:
                time.sleep(self.interval)
                current = self.scan()

                for event, pid in self.detect_changes(current):
                    if event == "TERMINATED":
                        print(f"TERMINATED PID={pid:<6} Name=<unknown>")
                        continue

                    # CREATED path
                    try:
                        proc_info, proc = self._safe_get_proc_info(pid)

                        matched_rule = match_rule(
                            {
                                "name": proc_info["name"],
                                "cmdline": proc_info["cmdline"],
                                "parent_name": proc_info["parent_name"],
                            },
                            self.rules
                        )

                        if matched_rule:
                            self.alert(
                                matched_rule.get("id", "<no-id>"),
                                matched_rule.get("severity", "medium"),
                                proc_info["name"],
                                pid
                            )

                            resp = matched_rule.get("response", {}) or {}
                            if resp.get("terminate") is True:
                                try:
                                    proc.terminate()
                                    print(f"[ACTION] Terminated PID={pid} ({proc_info['name']})")
                                except Exception as e:
                                    print(f"[ERROR] Could not terminate PID={pid}: {e}")
                        else:
                            print(f"CREATED    PID={pid:<6} Name={proc_info['name']}")

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        print(f"CREATED    PID={pid:<6} Name=<unknown>")

                self.last_pids = current

        except KeyboardInterrupt:
            print("\nStopping monitor...")

def main():
    parser = argparse.ArgumentParser(description="Process Sentinel: EDR-lite process monitor")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    parser.add_argument("--rules", type=str, default=None, help="Path to rules.yaml (optional)")
    args = parser.parse_args()

    monitor = ProcessMonitor(interval=args.interval, rules_path=args.rules)
    monitor.run()

if __name__ == "__main__":
    main()
