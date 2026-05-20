#!/usr/bin/env python3
"""
bpfscript - eBPF-based system performance monitoring tool
Target: RK3588 ARM64, Ubuntu 24.04, Linux 6.1

Architecture:
  - /proc polling for baseline metrics (no root needed)
  - bpftrace subprocess for deep kernel tracing (needs sudo)
  - HTTP server with SSE for real-time data streaming
  - HTML dashboard with Chart.js

Usage:
  python3 monitor_server.py                    # /proc only, no root needed
  sudo python3 monitor_server.py --bpf         # /proc + bpftrace deep tracing
  python3 monitor_server.py --port 9090        # custom port
  python3 monitor_server.py --interval 2       # custom collection interval (seconds)
"""

import http.server
import json
import os
import signal
import socketserver
import subprocess
import sys
import threading
import time
import re
from urllib.parse import urlparse

# ────────────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────────────
DEFAULT_PORT = 8080
DEFAULT_INTERVAL = 1
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

# ────────────────────────────────────────────────────────────────────────
# /proc-based data collector
# ────────────────────────────────────────────────────────────────────────

class ProcCollector:

    def __init__(self):
        self._prev_cpu = None
        self._prev_disk = None
        self._prev_net = None
        self._cpu_count = os.cpu_count() or 4
        self._lock = threading.Lock()
        self._latest = {}

    def _read_file(self, path):
        try:
            with open(path, "r") as f:
                return f.read()
        except Exception:
            return ""

    def _cpu_stats(self):
        data = self._read_file("/proc/stat")
        cores = {}
        for line in data.strip().split("\n"):
            if not line.startswith("cpu"):
                continue
            parts = line.split()
            name = parts[0]
            vals = [int(v) for v in parts[1:9]]
            cores[name] = {"total": sum(vals), "idle": vals[3]}

        if not cores:
            return {}

        result = {}
        if self._prev_cpu:
            for name, cur in cores.items():
                prev = self._prev_cpu.get(name, cur)
                total_delta = cur["total"] - prev["total"]
                idle_delta = cur["idle"] - prev["idle"]
                if total_delta > 0:
                    usage = 100.0 * (total_delta - idle_delta) / total_delta
                else:
                    usage = 0.0
                result[name] = round(usage, 1)

        self._prev_cpu = cores
        return result

    def _memory_stats(self):
        data = self._read_file("/proc/meminfo")
        mem = {}
        for line in data.strip().split("\n"):
            m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
            if m:
                mem[m.group(1)] = int(m.group(2))

        total = mem.get("MemTotal", 0)
        free = mem.get("MemFree", 0)
        buffers = mem.get("Buffers", 0)
        cached = mem.get("Cached", 0)
        sreclaimable = mem.get("SReclaimable", 0)
        available = mem.get("MemAvailable", total)
        used = total - free - buffers - cached - sreclaimable

        return {
            "total_mb": round(total / 1024, 1),
            "used_mb": round(max(used, 0) / 1024, 1),
            "available_mb": round(available / 1024, 1),
            "percent": round(100.0 * max(used, 0) / total, 1) if total > 0 else 0,
            "swap_total_mb": round(mem.get("SwapTotal", 0) / 1024, 1),
            "swap_free_mb": round(mem.get("SwapFree", 0) / 1024, 1),
            "buffers_mb": round(buffers / 1024, 1),
            "cached_mb": round((cached + sreclaimable) / 1024, 1),
        }

    def _disk_stats(self):
        data = self._read_file("/proc/diskstats")
        current = {}
        for line in data.strip().split("\n"):
            parts = line.split()
            if len(parts) < 14:
                continue
            name = parts[2]
            current[name] = {
                "reads": int(parts[3]), "writes": int(parts[7]),
                "read_kb": int(parts[5]) * 512 // 1024,
                "write_kb": int(parts[9]) * 512 // 1024,
                "read_ms": int(parts[6]), "write_ms": int(parts[10]),
                "io_active": int(parts[11]),
            }

        result = {"devices": [], "total_read_kbps": 0, "total_write_kbps": 0,
                   "total_iops": 0, "max_util_pct": 0.0}

        if not self._prev_disk:
            self._prev_disk = current
            return result

        for name, cur in current.items():
            prev = self._prev_disk.get(name, cur)
            rps = cur["reads"] - prev["reads"]
            wps = cur["writes"] - prev["writes"]
            rkbps = cur["read_kb"] - prev["read_kb"]
            wkbps = cur["write_kb"] - prev["write_kb"]
            rio_ms = cur["read_ms"] - prev["read_ms"]
            wio_ms = cur["write_ms"] - prev["write_ms"]
            io_ms = cur["io_active"] - prev["io_active"]
            util = min(100.0, io_ms * 100.0 / 1000.0)

            if rps > 0 or wps > 0:
                result["devices"].append({
                    "name": name,
                    "read_iops": rps,
                    "write_iops": wps,
                    "read_kbps": rkbps,
                    "write_kbps": wkbps,
                    "r_await_ms": round(rio_ms / rps, 1) if rps > 0 else 0,
                    "w_await_ms": round(wio_ms / wps, 1) if wps > 0 else 0,
                    "util_pct": round(util, 1),
                })
                result["total_read_kbps"] += rkbps
                result["total_write_kbps"] += wkbps
                result["total_iops"] += rps + wps
                result["max_util_pct"] = max(result["max_util_pct"], util)

        self._prev_disk = current
        result["total_read_kbps"] = round(result["total_read_kbps"], 1)
        result["total_write_kbps"] = round(result["total_write_kbps"], 1)
        result["max_util_pct"] = round(result["max_util_pct"], 1)
        return result

    def _network_stats(self):
        data = self._read_file("/proc/net/dev")
        current = {}
        for line in data.strip().split("\n")[2:]:
            if ":" not in line:
                continue
            name, stats = line.split(":", 1)
            name = name.strip()
            vals = [int(v) for v in stats.split()]
            if len(vals) >= 10:
                current[name] = {
                    "rx_bytes": vals[0], "rx_packets": vals[1],
                    "rx_errs": vals[2], "rx_drop": vals[3],
                    "tx_bytes": vals[8], "tx_packets": vals[9],
                    "tx_errs": vals[10], "tx_drop": vals[11],
                }

        result = {"interfaces": [], "total_rx_kbps": 0, "total_tx_kbps": 0,
                   "total_rx_pps": 0, "total_tx_pps": 0}

        if not self._prev_net:
            self._prev_net = current
            return result

        for name, cur in current.items():
            if name == "lo":
                continue
            prev = self._prev_net.get(name, cur)
            rx_kbps = (cur["rx_bytes"] - prev["rx_bytes"]) * 8 / 1024
            tx_kbps = (cur["tx_bytes"] - prev["tx_bytes"]) * 8 / 1024
            rx_pps = cur["rx_packets"] - prev["rx_packets"]
            tx_pps = cur["tx_packets"] - prev["tx_packets"]
            rx_err = cur["rx_errs"] - prev["rx_errs"]
            tx_err = cur["tx_errs"] - prev["tx_errs"]

            result["interfaces"].append({
                "name": name,
                "rx_kbps": max(0, round(rx_kbps, 1)),
                "tx_kbps": max(0, round(tx_kbps, 1)),
                "rx_pps": max(0, rx_pps),
                "tx_pps": max(0, tx_pps),
                "rx_errs": max(0, rx_err),
                "tx_errs": max(0, tx_err),
            })
            result["total_rx_kbps"] += result["interfaces"][-1]["rx_kbps"]
            result["total_tx_kbps"] += result["interfaces"][-1]["tx_kbps"]
            result["total_rx_pps"] += result["interfaces"][-1]["rx_pps"]
            result["total_tx_pps"] += result["interfaces"][-1]["tx_pps"]

        self._prev_net = current
        result["total_rx_kbps"] = round(result["total_rx_kbps"], 1)
        result["total_tx_kbps"] = round(result["total_tx_kbps"], 1)
        return result

    def _loadavg(self):
        data = self._read_file("/proc/loadavg")
        parts = data.split()
        if len(parts) >= 3:
            return {
                "load1": float(parts[0]),
                "load5": float(parts[1]),
                "load15": float(parts[2]),
                "running": int(parts[3].split("/")[0]) if "/" in parts[3] else 0,
                "total_procs": int(parts[3].split("/")[1]) if "/" in parts[3] else 0,
            }
        return {}

    def _thermal(self):
        zones = []
        for i in range(8):
            try:
                with open(f"/sys/class/thermal/thermal_zone{i}/temp", "r") as f:
                    temp = int(f.read().strip()) / 1000.0
                with open(f"/sys/class/thermal/thermal_zone{i}/type", "r") as f:
                    ttype = f.read().strip()
                zones.append({"type": ttype, "temp": round(temp, 1)})
            except Exception:
                pass
        return zones

    def collect(self):
        stats = {
            "timestamp": time.time(),
            "cpu": self._cpu_stats(),
            "memory": self._memory_stats(),
            "disk": self._disk_stats(),
            "network": self._network_stats(),
            "load": self._loadavg(),
            "thermal": self._thermal(),
            "cpu_count": self._cpu_count,
        }
        with self._lock:
            self._latest = stats
        return stats

    def get_latest(self):
        with self._lock:
            return dict(self._latest)


# ────────────────────────────────────────────────────────────────────────
# bpftrace deep kernel tracer
# ────────────────────────────────────────────────────────────────────────

BPFTRACE_CPU_SCRIPT = r'''
BEGIN { printf("BPF_CPU_READY\n"); }

/* Use kprobes - they work on this kernel, tracepoints don't (BTF: pid_t missing) */
kprobe:ttwu_do_wakeup { @wakeup[arg1] = nsecs; }

kprobe:finish_task_switch
{
    $next = (uint64)arg1;
    if (@wakeup[$next]) {
        $lat = (nsecs - @wakeup[$next]) / 1000;
        @lat_us = hist($lat);
        delete(@wakeup[$next]);
    }
}

kprobe:schedule { @cs = count(); }

interval:s:1
{
    printf("BPF_HIST|latsched\n");
    print(@lat_us);
    printf("BPF_HIST_END\n");
    printf("BPF_CPU_DATA\n");
    print(@cs);
    printf("BPF_CPU_END\n");
    zero(@cs);
}

END { clear(@wakeup); }
'''

BPFTRACE_DISK_SCRIPT = r'''
BEGIN { printf("BPF_DISK_READY\n"); }

/* submit_bio / bio_endio are core functions, rarely inlined */
kprobe:submit_bio { @start[arg0] = nsecs; @issued = count(); }

kprobe:bio_endio
{
    $bio = (uint64)arg0;
    if (@start[$bio]) {
        $lat = (nsecs - @start[$bio]) / 1000;
        @disk_lat_us = hist($lat);
        @completed = count();
        delete(@start[$bio]);
    }
}

interval:s:1
{
    printf("BPF_HIST|disk_lat\n");
    print(@disk_lat_us);
    printf("BPF_HIST_END\n");
    printf("BPF_DISK_DATA\n");
    print(@issued);
    print(@completed);
    printf("BPF_DISK_END\n");
    clear(@disk_lat_us);
    zero(@issued);
    zero(@completed);
}

END { clear(@start); }
'''

BPFTRACE_MEM_SCRIPT = r'''
BEGIN { printf("BPF_MEM_READY\n"); }

tracepoint:kmem:mm_page_alloc { @page_allocs = count(); }
tracepoint:kmem:mm_page_free { @page_frees = count(); }

interval:s:1
{
    printf("BPF_MEM_DATA\n");
    print(@page_allocs);
    print(@page_frees);
    printf("BPF_MEM_END\n");
    zero(@page_allocs);
    zero(@page_frees);
}
'''

BPFTRACE_NET_SCRIPT = r'''
BEGIN { printf("BPF_NET_READY\n"); }

tracepoint:net:net_dev_queue    { @tx_pkts = count(); @tx_bytes = sum(args->len); }
tracepoint:net:netif_receive_skb { @rx_pkts = count(); @rx_bytes = sum(args->len); }

interval:s:1
{
    printf("BPF_NET_DATA\n");
    print(@tx_pkts);
    print(@tx_bytes);
    print(@rx_pkts);
    print(@rx_bytes);
    printf("BPF_NET_END\n");
    zero(@tx_pkts); zero(@tx_bytes); zero(@rx_pkts); zero(@rx_bytes);
}
'''


class BpfCollector:

    def __init__(self):
        self._lock = threading.Lock()
        self._bpf_data = {}
        self._bpf_histograms = {}
        self._running = False
        self._procs = []
        self._status = {}     # name -> {"running": True/False, "error": str}
        self._stderr_lines = {}  # name -> list of last 5 stderr lines

    def start(self):
        scripts = {
            "cpu": BPFTRACE_CPU_SCRIPT,
            "disk": BPFTRACE_DISK_SCRIPT,
            "mem": BPFTRACE_MEM_SCRIPT,
            "net": BPFTRACE_NET_SCRIPT,
        }
        self._running = True
        threads = []
        for name, script in scripts.items():
            with self._lock:
                self._status[name] = {"running": False, "error": "", "pid": 0}
                self._stderr_lines[name] = []
            t = threading.Thread(target=self._run_bpftrace, args=(name, script), daemon=True)
            t.start()
            threads.append(t)
        return threads

    def _run_bpftrace(self, name, script):
        cmd = ["bpftrace", "--unsafe", "-e", script]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1
            )
        except FileNotFoundError:
            with self._lock:
                self._status[name] = {"running": False, "error": "bpftrace not found", "pid": 0}
            print(f"[bpf/{name}] bpftrace not found", flush=True)
            return
        except Exception as e:
            with self._lock:
                self._status[name] = {"running": False, "error": str(e), "pid": 0}
            print(f"[bpf/{name}] start failed: {e}", flush=True)
            return

        self._procs.append(proc)
        with self._lock:
            self._status[name] = {"running": True, "error": "", "pid": proc.pid}
        print(f"[bpf/{name}] bpftrace started (PID {proc.pid})", flush=True)

        # Read stderr in a separate thread
        def read_stderr():
            try:
                for line in proc.stderr:
                    if not self._running:
                        break
                    line = line.strip()
                    if line:
                        with self._lock:
                            buf = self._stderr_lines.get(name, [])
                            buf.append(line)
                            if len(buf) > 5:
                                buf.pop(0)
                            self._stderr_lines[name] = buf
            except Exception:
                pass

        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        current_hist = None
        hist_buckets = []
        data_received = False
        in_data_block = False
        data_name = None
        data_kv = {}

        try:
            for line in proc.stdout:
                if not self._running:
                    break
                line = line.strip()
                if not line:
                    continue

                if "BPF_" in line and "_READY" in line:
                    data_received = True
                    with self._lock:
                        s = dict(self._status.get(name, {}))
                        s["error"] = ""
                        self._status[name] = s
                    print(f"[bpf/{name}] ready", flush=True)
                    continue

                # --- Histogram block ---
                if line.startswith("BPF_HIST|"):
                    current_hist = line.split("|", 1)[1] if "|" in line else ""
                    hist_buckets = []
                    continue

                if line == "BPF_HIST_END":
                    if current_hist:
                        with self._lock:
                            self._bpf_histograms[current_hist] = hist_buckets
                    current_hist = None
                    continue

                # --- Data block (print-based) ---
                # Matches: BPF_CPU_DATA, BPF_DISK_DATA, etc.
                m_data_begin = re.match(r'BPF_(\w+)_DATA$', line)
                if m_data_begin:
                    in_data_block = True
                    data_name = m_data_begin.group(1).lower()
                    data_kv = {}
                    data_received = True
                    continue

                if in_data_block and line.startswith("BPF_") and line.endswith("_END"):
                    # End of data block
                    if data_name:
                        with self._lock:
                            target = dict(self._bpf_data.get(name, {}))
                            target.update(data_kv)
                            self._bpf_data[name] = target
                    in_data_block = False
                    data_name = None
                    data_kv = {}
                    continue

                # Parse print() output inside data block: @map_name: value
                if in_data_block and line.startswith("@"):
                    m = re.match(r'@(\w+):\s*([\d]+)', line)
                    if m:
                        key = m.group(1)
                        val = int(m.group(2))
                        data_kv[key] = val
                    continue

                # --- Histogram data (inside BPF_HIST block) ---
                if current_hist and line.startswith("["):
                    m = re.match(r'\[\s*([\dKMGT]+)\s*[,\)]\s*([\dKMGT]+)?\s*\)?\s+(\d+)', line)
                    if m:
                        low = self._parse_bucket(m.group(1))
                        high = self._parse_bucket(m.group(2)) if m.group(2) else low + 1
                        hist_buckets.append([low, high, int(m.group(3))])
        except Exception as e:
            print(f"[bpf/{name}] output error: {e}", flush=True)
            with self._lock:
                s = dict(self._status.get(name, {}))
                s["error"] = str(e)
                self._status[name] = s
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

            with self._lock:
                s = dict(self._status.get(name, {}))
                s["running"] = False
                if not data_received:
                    errs = "\n".join(self._stderr_lines.get(name, []))
                    if errs:
                        s["error"] = errs
                    else:
                        s["error"] = "no data received (check probes)"
                    print(f"[bpf/{name}] FAILED: {s['error']}", flush=True)
                self._status[name] = s

    @staticmethod
    def _parse_bucket(s):
        if not s:
            return 0
        mult = {"K": 1000, "M": 1000000, "G": 1000000000, "T": 1000000000000}
        if s[-1] in mult:
            return int(float(s[:-1]) * mult[s[-1]])
        return int(s)

    def get_data(self):
        with self._lock:
            return {
                "data": dict(self._bpf_data),
                "histograms": dict(self._bpf_histograms),
                "status": dict(self._status),
            }

    def stop(self):
        self._running = False
        for proc in self._procs:
            try:
                proc.terminate()
            except Exception:
                pass


# ────────────────────────────────────────────────────────────────────────
# Shared state for SSE broadcasting
# ────────────────────────────────────────────────────────────────────────

class SharedState:

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers = []
        self._latest = None

    def subscribe(self):
        q = []
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, data):
        self._latest = data
        with self._lock:
            for q in self._subscribers:
                q.append(data)

    def get_latest(self):
        return self._latest


# ────────────────────────────────────────────────────────────────────────
# HTTP handler
# ────────────────────────────────────────────────────────────────────────

class MonitorHandler(http.server.BaseHTTPRequestHandler):

    shared_state = None

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == "/":
                self._serve_index()
            elif path == "/api/metrics":
                self._serve_sse()
            elif path == "/api/stats":
                self._serve_json()
            else:
                self.send_error(404)
        except Exception as e:
            self.send_error(500, str(e))

    def _serve_index(self):
        index_path = os.path.join(TEMPLATE_DIR, "index.html")
        if not os.path.exists(index_path):
            self.send_error(404, "index.html not found")
            return
        try:
            with open(index_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, str(e))

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = MonitorHandler.shared_state.subscribe()
        try:
            latest = MonitorHandler.shared_state.get_latest()
            if latest:
                self._send_event(latest)
            while True:
                if q:
                    data = q.pop(0)
                    self._send_event(data)
                else:
                    time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            MonitorHandler.shared_state.unsubscribe(q)

    def _send_event(self, data):
        msg = f"event: metrics\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"
        self.wfile.write(msg.encode("utf-8"))
        self.wfile.flush()

    def _serve_json(self):
        latest = MonitorHandler.shared_state.get_latest()
        if not latest:
            self.send_error(503, "No data yet")
            return
        body = json.dumps(latest, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ────────────────────────────────────────────────────────────────────────
# Collector thread
# ────────────────────────────────────────────────────────────────────────

def run_collector(state, interval, use_bpf):
    proc_collector = ProcCollector()
    bpf_collector = None

    if use_bpf:
        bpf_collector = BpfCollector()
        bpf_collector.start()
        time.sleep(2)

    while True:
        try:
            stats = proc_collector.collect()
            stats["bpf_enabled"] = use_bpf
            if bpf_collector:
                stats["bpf"] = bpf_collector.get_data()
            state.publish(stats)
        except Exception as e:
            print(f"[collector] error: {e}", flush=True)
        time.sleep(interval)


# ────────────────────────────────────────────────────────────────────────
# Main entry
# ────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(description="bpfscript - eBPF system performance monitor")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    p.add_argument("--bpf", action="store_true", help="Enable bpftrace deep kernel tracing (needs sudo)")
    p.add_argument("--host", type=str, default="0.0.0.0")
    args = p.parse_args()

    if args.bpf and os.geteuid() != 0:
        print("WARNING: --bpf requires root. Continuing with /proc-only mode.", flush=True)
        args.bpf = False

    print("=" * 60, flush=True)
    print("  bpfscript - System Performance Monitor", flush=True)
    print(f"  Target: RK3588 ARM64 / Linux 6.1", flush=True)
    print(f"  HTTP:   http://{args.host}:{args.port}", flush=True)
    print(f"  BPF:    {'enabled' if args.bpf else 'disabled (use --bpf with sudo)'}", flush=True)
    print(f"  Interval: {args.interval}s", flush=True)
    print("=" * 60, flush=True)

    state = SharedState()
    MonitorHandler.shared_state = state

    collector_thread = threading.Thread(
        target=run_collector, args=(state, args.interval, args.bpf), daemon=True
    )
    collector_thread.start()

    server = ThreadedHTTPServer((args.host, args.port), MonitorHandler)
    sys.stdout.flush()
    print(f"\n[server] Dashboard: http://localhost:{args.port}", flush=True)
    print(f"[server] SSE stream: http://localhost:{args.port}/api/metrics", flush=True)
    print(f"[server] JSON stats: http://localhost:{args.port}/api/stats", flush=True)
    print("[server] Press Ctrl+C to stop\n", flush=True)

    # Run serve_forever in a background thread so the signal handler
    # can call server.shutdown() without deadlocking on __is_shut_down.
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    stop_event = threading.Event()

    def _handle_signal(sig, frame):
        if sig == signal.SIGINT:
            print("\n[server] Ctrl+C received, stopping...", flush=True)
        else:
            print("\n[server] SIGTERM received, stopping...", flush=True)
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        while not stop_event.is_set():
            stop_event.wait(1)
    except KeyboardInterrupt:
        pass

    server.shutdown()
    server.server_close()
    print("[server] stopped.", flush=True)


if __name__ == "__main__":
    main()
