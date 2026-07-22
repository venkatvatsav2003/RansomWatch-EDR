#!/usr/bin/env python3
import os
import sys
import json
import time
import math
import yaml
import logging
import argparse
import signal
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ransomwatch")


class EntropyEngine:
    @staticmethod
    def shannon(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
        return round(entropy, 4)

    @staticmethod
    def file_entropy(filepath: str, sample_size: int = 1048576) -> float:
        try:
            with open(filepath, 'rb') as f:
                data = f.read(sample_size)
            return EntropyEngine.shannon(data)
        except Exception as e:
            log.debug(f"Entropy read error: {filepath} - {e}")
            return -1.0

    @staticmethod
    def file_signature(filepath: str, sample_bytes: int = 16) -> str:
        try:
            with open(filepath, 'rb') as f:
                return f.read(sample_bytes).hex()
        except: return ""


class FileMonitor:
    def __init__(self, config: dict):
        self.honeypot = Path(config.get("honeypot_dir", "./honeypot"))
        self.threshold = config.get("alert_threshold", 7.5)
        self.warning_threshold = config.get("warning_threshold", 6.5)
        self.poll_interval = config.get("poll_interval", 1.0)
        self.excluded_exts = set(config.get("excluded_extensions", [".tmp", ".log"]))
        self.excluded_patterns = config.get("excluded_patterns", [])
        self.max_file_size = config.get("max_file_size", 100 * 1024 * 1024)
        self.alert_log = Path(config.get("alert_log", "logs/alerts.json"))
        self.running = True

        self.honeypot.mkdir(parents=True, exist_ok=True)
        self.alert_log.parent.mkdir(parents=True, exist_ok=True)
        self._state = {}

    def _load_state(self):
        state_file = self.honeypot / ".edr_state.json"
        if state_file.exists():
            try:
                self._state = json.loads(state_file.read_text())
            except: self._state = {}
        else:
            self._state = {}

    def _save_state(self):
        state_file = self.honeypot / ".edr_state.json"
        try:
            state_file.write_text(json.dumps(self._state))
        except: pass

    def _log_alert(self, severity: str, filepath: str, entropy: float, signature: str, size: int):
        alert = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": severity,
            "file": str(filepath),
            "entropy": entropy,
            "signature": signature,
            "size_bytes": size,
            "alert_id": hashlib.md5(f"{filepath}{time.time()}".encode()).hexdigest()[:12],
        }
        with open(self.alert_log, 'a') as f:
            f.write(json.dumps(alert) + "\n")
        if severity == "ALERT":
            log.warning(f"[ALERT] High entropy in {filepath}: {entropy}")
        elif severity == "WARNING":
            log.info(f"[WARN] Suspicious entropy in {filepath}: {entropy}")

    def scan_once(self):
        findings = []
        for fp in self.honeypot.rglob("*"):
            if not fp.is_file() or fp.name.startswith('.') or fp.suffix in self.excluded_exts:
                continue
            if fp.stat().st_size > self.max_file_size:
                continue
            mtime = fp.stat().st_mtime
            last = self._state.get(str(fp), 0)
            if mtime <= last:
                continue
            self._state[str(fp)] = mtime
            entropy = EntropyEngine.file_entropy(str(fp))
            if entropy < 0:
                continue
            sig = EntropyEngine.file_signature(str(fp))
            size = fp.stat().st_size
            if entropy >= self.threshold:
                self._log_alert("ALERT", str(fp), entropy, sig, size)
                findings.append(("ALERT", fp, entropy))
            elif entropy >= self.warning_threshold:
                self._log_alert("WARNING", str(fp), entropy, sig, size)
                findings.append(("WARNING", fp, entropy))
            else:
                log.info(f"[OK] {fp.name} entropy={entropy}")
        return findings

    def run(self):
        log.info(f"RansomWatch EDR v2.0")
        log.info(f"Monitoring: {self.honeypot.resolve()}")
        log.info(f"Alert threshold: {self.threshold}")
        log.info(f"Poll interval: {self.poll_interval}s")
        log.info(f"Alert log: {self.alert_log}")
        print()
        self._load_state()
        signal.signal(signal.SIGINT, lambda s, f: setattr(self, 'running', False))
        while self.running:
            try:
                self.scan_once()
                self._save_state()
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log.error(f"Scan error: {e}")
                time.sleep(5)
        self._save_state()
        log.info("RansomWatch stopped.")


class AttackSimulator:
    @staticmethod
    def benign(path: str):
        fp = Path(path) / "readme.txt"
        content = "This is a normal document with predictable content." * 50
        fp.write_text(content)
        log.info(f"Created benign file: {fp} ({len(content)} bytes)")

    @staticmethod
    def ransomware(path: str, size_kb: int = 2048):
        fp = Path(path) / f"encrypted_{datetime.now().strftime('%H%M%S')}.enc"
        data = os.urandom(size_kb * 1024)
        fp.write_bytes(data)
        log.warning(f"Simulated ransomware: {fp} ({len(data)} bytes)")

    @staticmethod
    def ransom_note(path: str):
        fp = Path(path) / "README_TO_DECRYPT.txt"
        fp.write_text("All your files have been encrypted. Pay 1 BTC to recover them.")
        log.info(f"Dropped ransom note: {fp}")


def main():
    parser = argparse.ArgumentParser(description="RansomWatch EDR — Behavioral Ransomware Detection")
    parser.add_argument("action", nargs="?", choices=["monitor", "sim-benign", "sim-attack", "sim-all", "analyze", "dashboard"], default="monitor")
    parser.add_argument("-c", "--config", default="config/edr.yml")
    parser.add_argument("-p", "--path", default="./honeypot")
    parser.add_argument("--threshold", type=float, default=7.5)
    parser.add_argument("--size", type=int, default=2048, help="Simulated encrypted file size in KB")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    config = {
        "honeypot_dir": args.path,
        "alert_threshold": args.threshold,
        "poll_interval": 1.0,
    }
    if Path(args.config).exists():
        cfg = yaml.safe_load(Path(args.config).read_text())
        if cfg:
            config.update(cfg.get("edr", {}))

    if args.action == "monitor":
        monitor = FileMonitor(config)
        monitor.run()

    elif args.action == "sim-benign":
        log.info("Simulating normal file activity...")
        for i in range(3):
            AttackSimulator.benign(args.path)
            time.sleep(1)

    elif args.action == "sim-attack":
        log.warning("Simulating ransomware encryption...")
        for i in range(2):
            AttackSimulator.ransomware(args.path, args.size)
            time.sleep(0.5)
        AttackSimulator.ransom_note(args.path)

    elif args.action == "sim-all":
        log.info("Simulating mixed activity...")
        AttackSimulator.benign(args.path)
        time.sleep(2)
        AttackSimulator.ransomware(args.path, args.size)
        AttackSimulator.ransom_note(args.path)

    elif args.action == "dashboard":
        log.info("Alert dashboard:")
        log_file = Path("logs/alerts.json")
        if log_file.exists():
            alerts = [json.loads(l) for l in log_file.read_text().splitlines() if l.strip()]
            for a in alerts[-20:]:
                print(f"  [{a['severity']:7s}] {a['timestamp'][:19]}  {a['file'][:60]:60s}  entropy={a['entropy']}")
        else:
            log.info("No alerts yet.")


if __name__ == "__main__":
    main()
