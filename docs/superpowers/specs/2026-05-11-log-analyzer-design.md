# Log Analyzer CLI — Design Spec

Rust 实现的日志分析 CLI 工具，帮助运维快速分析混合格式日志并定位问题。

## 概述

| 维度 | 决策 |
|------|------|
| 日志格式 | 混合格式，自动识别 |
| 分析模式 | 离线文件分析 |
| 特征识别 | 规则引擎 + 可选 LLM 深度分析 |
| 输出方式 | 终端富文本 / JSON / HTML 报告 / 管道友好 |
| 文件规模 | > 1GB，流式逐行处理 |
| 分发方式 | 单一二进制文件，零运行时依赖 |
| 架构模式 | 流式管道 |

## 1. 架构

### 1.1 模块结构

```
log-analyze (CLI entry)
├── core/           — 核心抽象 (traits, types)
│   ├── pipeline    — Pipeline trait 定义与组合
│   ├── parser      — LogParser trait + 格式检测
│   └── pattern     — Pattern trait + 规则引擎
├── parsers/        — 内置格式解析器
│   ├── json        — JSON 日志解析
│   ├── syslog      — Syslog 解析
│   ├── nginx       — Nginx access/error 日志
│   ├── apache      — Apache 日志
│   └── generic     — 通用正则 + 自动检测回退
├── patterns/       — 内置特征模式
│   ├── anomaly     — 异常检测 (错误率突增、异常值)
│   ├── frequency   — 频率分析 (重复模式、高频条目)
│   └── custom      — 用户自定义规则加载
├── analyzer/       — 分析引擎
│   ├── engine      — 流式分析引擎主循环
│   ├── aggregator  — 实时聚合统计
│   └── llm         — 可选 LLM 深度分析
├── output/         — 输出模块
│   ├── terminal    — 终端富文本 (colored + comfy-table)
│   ├── json        — JSON 序列化输出
│   ├── report      — HTML 报告生成
│   └── pipe        — 管道友好格式
├── config/         — 配置管理
│   └── rules       — TOML 规则文件加载
└── cli/            — CLI 入口 (clap)
```

### 1.2 数据流

```
File → BufReader 逐行 → FormatDetector → Parser → PatternMatcher → Aggregator → Output
                              ↓                              ↓
                        格式识别概率排序               可选 LLM 分析
```

### 1.3 核心 Trait

- `LogParser`：输入 `&[u8]` 原始行，输出 `LogEntry`
- `Pattern`：输入 `LogEntry`，输出 `Option<Match>`
- `Sink`：消费分析结果，输出到终端/文件/JSON

新增格式只需实现 `LogParser`，新增分析规则只需实现 `Pattern`。

## 2. 核心数据类型

```rust
enum LogLevel { Error, Warn, Info, Debug, Trace }
enum Severity { Critical, Warning, Info }

enum Value {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
}

struct LogEntry {
    timestamp: Option<DateTime<Utc>>,
    level: Option<LogLevel>,
    source: Option<String>,
    message: String,
    fields: HashMap<String, Value>,
    line_number: u64,              // 按需回查原始行，不存 raw
}

struct MatchStats {
    count: u64,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    rate_per_minute: f64,
}

struct PatternMatch {
    pattern_name: String,
    severity: Severity,
    description: String,
    entries: Vec<LogEntry>,        // 采样保留，上限 50 条
    stats: MatchStats,
}

struct Anomaly {
    anomaly_type: AnomalyType,     // Spike / Gap / Frequency
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    score: f64,                    // 异常分数 (Z-score 等)
    detail: String,
}

struct AnalysisReport {
    file_info: FileInfo,
    format: DetectedFormat,
    time_range: Option<TimeRange>,
    level_distribution: HashMap<LogLevel, u64>,
    patterns: Vec<PatternMatch>,
    anomalies: Vec<Anomaly>,
}
```

## 3. 流式处理管线

```
┌─────────────┐  逐行    ┌──────────────┐   LogEntry   ┌─────────────┐
│  BufReader   │────────→│    Parser     │────────────→│ PatternEngine│
│  (逐行读取)   │         │ (格式检测1次)  │              │ (规则匹配)   │
└─────────────┘         └──────────────┘              └──────┬──────┘
                                                             │
                                       PatternMatch          │
                                             ↓               ↓
                                     ┌──────────────┐  ┌──────────┐
                                     │  Aggregator   │  │ LLMSink  │
                                     │ (增量统计汇总)  │  │ (可选)    │
                                     └──────┬───────┘  └──────────┘
                                            │
                                            ↓
                                   ┌───────────────┐
                                   │   OutputSink   │
                                   │ (终端/JSON/报告)│
                                   └───────────────┘
```

- **BufReader**：逐行读取文件，不加载全文件到内存
- **Parser**：格式检测只对前 100 行做一次，后续复用
- **PatternEngine**：顺序消费，依次过所有规则
- **Aggregator**：增量式统计——滑动窗口计数、fingerprint HashMap、last_timestamp
- **内存控制**：Aggregator 不持有 Vec<LogEntry>，管线 ~50-100MB，不随文件增长

## 4. 特征识别 (三层架构)

### Layer 1 — 规则模式匹配 (内置 + 自定义)

内置规则：

| 规则名 | 检测内容 |
|--------|---------|
| `connection_refused` | 连接被拒绝 |
| `oom_kill` | OOM killer |
| `disk_full` | 磁盘空间不足 |
| `timeout` | 各类超时 |
| `auth_failure` | 认证失败暴增 |
| `stack_trace` | 异常堆栈出现 |

注：`error_burst` 由 Aggregator 的滑动窗口 spike 检测负责，不作为 Pattern 规则。

自定义规则 (TOML)：

```toml
[[pattern]]
name = "k8s_pod_crashloop"
description = "K8s Pod CrashLoopBackOff"
severity = "critical"
match_type = "regex"          # regex | keyword | field
expression = "CrashLoopBackOff|Back-off restarting"
count_threshold = 3
time_window = "5m"

[[pattern]]
name = "slow_query"
description = "慢查询超过阈值"
severity = "warning"
match_type = "field"
field = "duration_ms"
condition = "gt"              # gt | lt | eq | gte | lte
value = 1000
```

### Layer 2 — 统计异常检测 (自动)

- **错误率突增**：滑动窗口 Z-score > 2 标记异常
- **高频重复**：消息 fingerprint 去参数化，Top-K + 均值偏差
- **时间间隔**：检测日志流 "沉默期"（服务挂起）

### Layer 3 — LLM 深度分析 (可选)

- `--llm` 标志启用
- 将异常上下文（前后 20 行）发送给 LLM
- 返回：根因分析、影响范围、修复建议
- 支持 Claude/OpenAI/自建 API endpoint
- API Key 从环境变量读取，不存明文

### 格式自动检测

前 100 行 → 所有 Parser 尝试解析 → 按 解析成功率 × 字段完整度 排序
→ 选最高分 Parser，置信度 < 0.7 回退到 Generic

## 5. CLI 接口

```
log-analyze <COMMAND>

Commands:
  analyze    分析日志文件 (默认命令)
  detect     仅检测日志格式
  patterns   列出所有可用规则
  report     生成完整分析报告
```

### Flags

| Flag | 说明 |
|------|------|
| `-f, --format` | 强制格式 (auto/json/syslog/nginx/apache/generic) |
| `-p, --patterns` | 指定规则，逗号分隔 |
| `-o, --output` | 输出目标 (`.json`/`.html` 按后缀识别) |
| `--llm` | 启用 LLM 深度分析 |
| `--llm-endpoint` | LLM API 地址 |
| `--lang` | 输出语言 (zh/en) |
| `--time-range` | 时间范围 (`2024-01-01..2024-01-02`, `last-1h`) |
| `--level` | 过滤级别 |
| `--rules` | 自定义规则文件 |
| `--threads` | 并行线程数 |
| `-q, --quiet` | 管道友好格式 |

### 终端输出

彩色终端表格，展示：

- 文件元信息（大小、行数、格式、时间范围）
- 级别分布柱状图
- 规则匹配结果（严重性 + 时间段 + 采样 + 影响行数）
- 统计异常列表
- 总结（critical/warning 计数）

## 6. 错误处理

```rust
enum AppError {
    Io(io::Error),
    Parse { file: String, line: u64, detail: String },
    Config { path: String, reason: String },
    Llm { status: u16, message: String },
}
```

- 单行解析失败不中断，记录到 `parse_errors` 计数器
- 格式置信度低时 warning 并降级到 generic
- LLM 失败回退到纯规则结果
- `anyhow` + 自定义 error kind 传播

## 7. 配置层级

```
/etc/log-analyze/config.toml          # 系统级
~/.config/log-analyze/config.toml     # 用户级
~/.config/log-analyze/rules.toml      # 自定义规则
./log-analyze.toml                    # 项目级
CLI flags                             # 最高优先级
```

```toml
[general]
threads = 0              # 0 = 自动
lang = "zh"
default_format = "auto"

[llm]
enabled = false
endpoint = "https://api.anthropic.com/v1"
model = "claude-sonnet-4-6"
api_key_env = "LOG_ANALYZE_API_KEY"

[detection]
sample_lines = 100
confidence_threshold = 0.7
```

## 8. 测试策略

| 层级 | 方式 | 重点 |
|------|------|------|
| Parser | 单元测试，50+ 行样本/格式 | 解析正确性、边界、畸形输入 |
| Pattern | 单元测试，构造匹配/不匹配条目 | 规则准确性、阈值边界 |
| 统计异常 | 构造已知异常分布 | Z-score、突增检测 |
| 格式检测 | 混合格式样本 | 识别准确率、置信度 |
| 集成 | 真实生产日志 (脱敏) | 端到端、大文件性能 |
| 性能 | `cargo bench` + 1GB 合成日志 | 吞吐量、内存峰值 |

## 9. 质量目标

- 解析吞吐量 > 100MB/s (单线程)，并行接近线性
- 1GB 文件分析 < 10 秒 (纯规则模式)
- 内存峰值 < 200MB (无论文件大小)
- 解析容错率 > 99.9%

## 10. 关键依赖

| Crate | 用途 |
|-------|------|
| `clap` | CLI 参数解析 |
| `regex` | 正则匹配 |
| `serde` + `serde_json` | 序列化 |
| `chrono` | 时间解析 |
| `colored` | 终端颜色 |
| `comfy-table` | 终端表格 |
| `toml` | 配置解析 |
| `anyhow` + `thiserror` | 错误处理 |
| `once_cell` | 静态正则缓存 |
| `dirs-next` | 查找配置文件路径 |
| `reqwest` | LLM API HTTP 调用 (可选) |
| `tokio` | 异步运行时 (仅 LLM 调用，核心管线同步, 可选) |

**v1 不使用**: ~~memmap2~~ (BufReader 足够)、~~crossbeam~~ (单线程先跑通)、~~bytes~~ (不存 raw)。
