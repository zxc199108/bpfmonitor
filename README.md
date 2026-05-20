# bpfscript

基于 eBPF 的嵌入式系统性能实时监控工具，专为 ARM64 平台（RK3588）设计。

## 特性

- **零依赖运行** — 仅需 Python 3 标准库，无需 pip 安装任何包
- **双层数据源** — `/proc` 基础指标（无需 root）+ bpftrace 内核深度追踪（需 sudo）
- **实时仪表盘** — HTML5 + Chart.js + SSE 推送，浏览器打开即可查看
- **多子系统覆盖** — CPU、内存、磁盘 I/O、网络吞吐、调度延迟、温度监控
- **ARM64 适配** — 硬编码 PID offset（Linux 6.1 arm64），绕过 BTF 缺失问题

## 监控面板

| 面板 | 数据源 | 需要 root |
|---|---|---|
| CPU 使用率（per-core） | `/proc/stat` | 否 |
| 内存使用率 / Cache | `/proc/meminfo` | 否 |
| 磁盘 I/O 速率 / IOPS | `/proc/diskstats` | 否 |
| 网络吞吐量（kbps/pps） | `/proc/net/dev` | 否 |
| 系统负载 / 进程数 | `/proc/loadavg` | 否 |
| 温度（SOC/GPU/NPU/CPU） | `/sys/class/thermal/` | 否 |
| 调度延迟直方图 | bpftrace（kprobe） | 是 |
| 磁盘 I/O 延迟直方图 | bpftrace（kprobe） | 是 |
| 内存页分配速率 | bpftrace（tracepoint） | 是 |
| 网络包速率 | bpftrace（tracepoint） | 是 |

## 快速开始

```bash
# 基础模式（/proc，无需 root）
python3 monitor_server.py

# 浏览器打开
# http://localhost:8080
```

```bash
# 完整模式（含 BPF 内核追踪，需 sudo）
sudo python3 monitor_server.py --bpf
```

```bash
# 自定义端口和采集间隔
python3 monitor_server.py --port 9090 --interval 2
```

## 命令行参数

```
--port PORT        HTTP 服务端口 (默认: 8080)
--interval SECONDS 数据采集间隔秒数 (默认: 1)
--bpf              启用 bpftrace 内核深度追踪 (需要 sudo)
--host HOST        绑定地址 (默认: 0.0.0.0)
```

## API 端点

| 端点 | 说明 |
|---|---|
| `GET /` | 实时监控仪表盘 HTML |
| `GET /api/metrics` | SSE 事件流（实时数据推送） |
| `GET /api/stats` | JSON 格式当前快照 |

## 项目结构

```
bpfscript/
├── monitor_server.py      # 主程序：HTTP/SSE 服务 + 数据采集
├── start.sh               # 启动脚本
├── templates/
│   └── index.html         # 仪表盘前端
├── bpf/
│   ├── cpu.bt             # 调度延迟监控（bpftrace）
│   ├── disk.bt            # 磁盘 I/O 延迟监控（bpftrace）
│   ├── memory.bt          # 内存页分配监控（bpftrace）
│   ├── network.bt         # 网络包监控（bpftrace）
│   ├── monitor.bpf.c      # 综合 BPF 程序（libbpf，可选）
│   ├── loader.c           # 用户态加载器（libbpf，可选）
│   └── Makefile           # 编译 BPF C 程序
└── LICENSE
```

## 系统要求

- **架构**: ARM64（aarch64），也支持 x86_64
- **内核**: Linux 6.1+（BPF 模式）
- **OS**: Ubuntu 24.04 LTS / Debian 12+
- **依赖**: Python 3.8+, bpftrace 0.20+（可选，BPF 模式需要）

### 安装 bpftrace

```bash
sudo apt install bpftrace
```

## 截图

启动后打开浏览器访问 `http://localhost:8080`：

- 左侧：CPU per-core 使用率折线图、调度延迟直方图
- 右侧：内存/磁盘/网络实时数据 + 折线图
- 底部：负载均值 + 7 路温度传感器

> BPF 面板在非 root 模式或 bpftrace 不可用时显示 "BPF disabled" 遮罩。

## License

MIT License - 详见 [LICENSE](LICENSE)

BPF 程序（`.bpf.c`）使用 GPL-2.0 许可，符合内核要求。
