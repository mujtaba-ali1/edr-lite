import time
import psutil

class ProcessMonitor:
    def __init__(self, interval=2.0):
        self.interval = interval
        # Start with an empty set so we only report creations on first run
        self.last_pids = set()

    def scan(self):
        """Return the current set of PIDs."""
        return {p.pid for p in psutil.process_iter(['pid'])}

    def detect_changes(self, current_pids):
        """Compare to last snapshot and yield (event, pid)."""
        new = current_pids - self.last_pids
        gone = self.last_pids - current_pids

        for pid in new:
            yield ("CREATED", pid)
        for pid in gone:
            yield ("TERMINATED", pid)

    def run(self):
        print(f"Starting monitor (interval={self.interval}s)...")
        # First snapshot
        self.last_pids = self.scan()

        while True:
            time.sleep(self.interval)
            current = self.scan()
            for event, pid in self.detect_changes(current):
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = "<unknown>"
                print(f"{event:<10} PID={pid:<6} Name={name}")
            self.last_pids = current

if __name__ == "__main__":
    monitor = ProcessMonitor(interval=1.0)
    monitor.run()
