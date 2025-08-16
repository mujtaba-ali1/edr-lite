import time
import psutil
from rule_engine import load_rules, match_rule
from colorama import Fore, Style, init

init(autoreset=True)  # Enable color output

class ProcessMonitor:
    def __init__(self, interval=1.0):
        self.interval = interval
        self.last_pids = set()
        self.rules = load_rules()

    def scan(self):
        return {p.pid for p in psutil.process_iter(['pid'])}

    def detect_changes(self, current_pids):
        new = current_pids - self.last_pids
        gone = self.last_pids - current_pids
        for pid in new:
            yield ("CREATED", pid)
        for pid in gone:
            yield ("TERMINATED", pid)

    def alert(self, rule_id, severity, name, pid):
        sev = severity.upper()
        color = {
            "LOW": Fore.GREEN,
            "MEDIUM": Fore.YELLOW,
            "HIGH": Fore.RED
        }.get(sev, Fore.WHITE)

        print(f"{color}[{sev}] Rule '{rule_id}' matched: {name} (PID {pid}){Style.RESET_ALL}")

    def run(self):
        print(f"Starting monitor (interval={self.interval}s)...")
        self.last_pids = self.scan()

        while True:
            time.sleep(self.interval)
            current = self.scan()
            for event, pid in self.detect_changes(current):
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    if event == "CREATED":
                        matched_rule = match_rule(name, self.rules)
                        if matched_rule:
                            self.alert(matched_rule['id'], matched_rule['severity'], name, pid)
                            resp = matched_rule.get("response", {})
                            if resp.get("terminate"):
                                try:
                                    proc.terminate()
                                    print(f"[ACTION] Terminated PID={pid} ({name})")
                                except Exception as e:
                                    print(f"[ERROR] Could not terminate PID={pid}: {e}")
                        else:
                            print(f"CREATED    PID={pid:<6} Name={name}")
                    else:
                        print(f"TERMINATED PID={pid:<6} Name={name}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print(f"{event:<10} PID={pid:<6} Name=<unknown>")
            self.last_pids = current

if __name__ == "__main__":
    monitor = ProcessMonitor(interval=1.0)
    monitor.run()
