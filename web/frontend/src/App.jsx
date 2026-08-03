import { useCallback, useEffect, useMemo, useState } from "react";
import ReactFlow, { Background, Controls, MiniMap } from "reactflow";
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Clock3,
  ClipboardCheck,
  Database,
  FileText,
  Filter,
  GitBranch,
  HardDrive,
  History,
  LayoutDashboard,
  Loader2,
  LockKeyhole,
  Network,
  Play,
  Radio,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  XCircle
} from "lucide-react";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip
} from "recharts";

const navItems = [
  { id: "overview", label: "总览", group: "指挥台", icon: LayoutDashboard },
  { id: "alerts", label: "AI 告警", group: "研判", icon: ShieldAlert },
  { id: "cases", label: "研判案件", group: "研判", icon: ClipboardCheck },
  { id: "evidence", label: "证据拓扑", group: "研判", icon: GitBranch },
  { id: "reports", label: "报告中心", group: "交付留痕", icon: FileText },
  { id: "history", label: "任务历史", group: "交付留痕", icon: History }
];

const navGroups = ["指挥台", "研判", "交付留痕"];

const sourceLabels = {
  ai_alerts: "MineShark AI",
  wazuh_alerts: "Wazuh",
  zeek: "Zeek",
  suricata: "Suricata",
  rag_index: "RAG"
};

const riskLabels = {
  high: "高危",
  medium: "中危",
  low: "低危",
  informational: "提示",
  unknown: "未知"
};

const riskColors = {
  high: "var(--risk)",
  medium: "var(--warning)",
  low: "var(--accent)",
  informational: "var(--evidence)",
  unknown: "var(--neutral-status)"
};

const taskLabels = {
  preflight: "Preflight",
  "evidence-only": "证据聚合",
  "agent-report": "Agent 报告",
  "case-sync": "同步告警"
};

const caseStatusLabels = {
  new: "待研判",
  in_review: "研判中",
  escalated: "已升级",
  closed: "已关闭"
};

const dispositionLabels = {
  malicious: "确认恶意",
  suspicious: "可疑待跟进",
  benign: "良性流量"
};

const statusLabels = {
  queued: "排队中",
  running: "执行中",
  succeeded: "已完成",
  failed: "失败",
  ok: "在线",
  error: "异常",
  ready: "已覆盖",
  missing: "缺失",
  new: "待研判",
  in_review: "研判中",
  escalated: "已升级",
  closed: "已关闭"
};

const evidenceSources = [
  { key: "ai_alerts", label: "MineShark AI", count: (bundle) => bundle.selected_alerts?.length || 0 },
  { key: "wazuh", label: "Wazuh", count: (bundle) => bundle.wazuh_evidence?.alerts?.length || 0 },
  { key: "zeek", label: "Zeek", count: (bundle) => bundle.zeek_context?.events?.length || 0 },
  { key: "suricata", label: "Suricata", count: (bundle) => bundle.suricata_alerts?.alerts?.length || 0 },
  { key: "rag", label: "RAG", count: (bundle) => bundle.rag_matches?.matches?.length || 0 }
];

async function apiGet(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function apiPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function apiPatch(path, body) {
  const response = await fetch(path, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

function scoreOf(alert) {
  const raw =
    alert?._mineshark_score ??
    alert?.malware_probability ??
    alert?.probability ??
    alert?.risk_score ??
    alert?.score;
  const value = Number(raw);
  return Number.isFinite(value) ? value : null;
}

function riskOf(alert) {
  const score = scoreOf(alert);
  if (score === null) return "unknown";
  if (score >= 0.9) return "high";
  if (score >= 0.7) return "medium";
  if (score >= 0.5) return "low";
  return "informational";
}

function alertKey(alert) {
  return alert?.alert_id || alert?._mineshark_alert_id || alert?.uid || alert?._mineshark_uid || "unknown";
}

function alertTime(alert) {
  return alert?.timestamp || alert?._mineshark_timestamp || alert?.["@timestamp"] || alert?.generated_at || "-";
}

function srcIp(alert) {
  return alert?.src_ip || alert?.srcip || alert?.["id.orig_h"] || "-";
}

function dstIp(alert) {
  return alert?.dst_ip || alert?.dstip || alert?.dest_ip || alert?.["id.resp_h"] || "-";
}

function displayTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("zh-CN", { hour12: false });
}

function evidenceRows(bundle = {}, healthSources = {}) {
  const missingSources = new Set(bundle.missing_sources || []);
  const errors = bundle.errors || [];
  const healthKeys = { ai_alerts: "ai_alerts", wazuh: "wazuh_alerts", zeek: "zeek", suricata: "suricata", rag: "rag_index" };
  return evidenceSources.map((source) => {
    const count = source.count(bundle);
    const error = errors.find((item) => item.startsWith(`${source.key}:`));
    const missing = missingSources.has(source.key);
    const health = healthSources[healthKeys[source.key]];
    const indexMissing = source.key === "rag" && health && (!health.knowledge_faiss || !health.metadata_json);
    const reason = indexMissing
      ? `索引缺失：${health.path || "RAG 索引目录"}`
      : error && source.key === "wazuh"
        ? "Indexer 未连接，已回退本地日志；当前无匹配记录。"
        : error
          ? error
          : health?.exists === false
            ? `路径不存在：${health.path}`
            : missing
              ? "当前查询未返回匹配事件或索引结果。"
              : count > 0
                ? "当前查询已返回可追溯记录。"
                : "等待证据聚合。";
    return {
      ...source,
      count,
      status: count > 0 ? "ready" : error && !indexMissing ? "error" : "missing",
      reason
    };
  });
}

function evidenceCoverage(bundle) {
  if (!bundle) return null;
  const rows = evidenceRows(bundle);
  return {
    ready: rows.filter((item) => item.count > 0).length,
    total: rows.length,
    rows
  };
}

function evidenceAppliesToAlert(bundle, alert) {
  if (!bundle || !alert) return false;
  const queryId = bundle.query_keys?.alert_id;
  if (queryId && queryId === alertKey(alert)) return true;
  return (bundle.selected_alerts || []).some((item) => alertKey(item) === alertKey(alert));
}

function queryWindow(bundle = {}) {
  const query = bundle.query_keys || {};
  const start = query.start_time ? displayTime(query.start_time) : "未指定开始时间";
  const end = query.end_time ? displayTime(query.end_time) : "未限定结束时间";
  return `${start} 至 ${end}`;
}

function caseTimeline(caseItem) {
  if (!caseItem) return [];
  const events = [
    {
      label: "建案",
      time: caseItem.created_at,
      detail: `从 AI 告警 ${caseItem.alert_key} 保存事实快照。`,
      tone: "evidence"
    }
  ];
  if (caseItem.owner) {
    events.push({
      label: "分析员接手",
      time: caseItem.updated_at,
      detail: `当前负责人：${caseItem.owner}。`,
      tone: "warning"
    });
  }
  if (caseItem.disposition || caseItem.decision_reason) {
    events.push({
      label: "结论更新",
      time: caseItem.updated_at,
      detail: caseItem.disposition ? dispositionLabels[caseItem.disposition] || caseItem.disposition : "已补充研判依据。",
      tone: caseItem.disposition === "benign" ? "success" : "warning"
    });
  }
  if (caseItem.closed_at) {
    events.push({
      label: "关闭",
      time: caseItem.closed_at,
      detail: "案件已关闭；修改为待研判可重新进入人工复核。",
      tone: "success"
    });
  }
  return events;
}

function StatusPill({ status, label }) {
  const normalized = status || "unknown";
  const Icon =
    normalized === "succeeded" || normalized === "ok" || normalized === "ready" || normalized === "closed"
      ? CheckCircle2
      : normalized === "failed" || normalized === "error" || normalized === "missing"
        ? XCircle
        : normalized === "running"
          ? Loader2
          : Clock3;
  return (
    <span className={`status-pill status-${normalized}`}>
      <Icon size={14} className={normalized === "running" ? "spin" : ""} />
      {label || statusLabels[normalized] || normalized}
    </span>
  );
}

function IconButton({ icon: Icon, label, onClick, disabled, variant = "primary", title, iconOnly = false }) {
  return (
    <button
      className={`button button-${variant} ${iconOnly ? "button-icon" : ""}`}
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title || label}
      aria-label={title || label}
    >
      <Icon size={16} />
      <span className={iconOnly ? "sr-only" : ""}>{label}</span>
    </button>
  );
}

function EmptyState({ title, detail }) {
  return (
    <div className="empty-state">
      <Database size={28} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function App() {
  const [activeView, setActiveView] = useState("overview");
  const [health, setHealth] = useState(null);
  const [overview, setOverview] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [alertsMeta, setAlertsMeta] = useState({});
  const [tasks, setTasks] = useState([]);
  const [reports, setReports] = useState([]);
  const [cases, setCases] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [selectedCase, setSelectedCase] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [filters, setFilters] = useState({ ip: "", uid: "", alert_id: "", threshold: "0.5" });
  const [loading, setLoading] = useState(false);
  const [busyTask, setBusyTask] = useState(null);
  const [error, setError] = useState("");
  const [lastRefreshedAt, setLastRefreshedAt] = useState(null);

  const refreshAll = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [healthData, overviewData, alertsData, tasksData, reportsData, casesData] = await Promise.all([
        apiGet("/api/health"),
        apiGet("/api/overview"),
        apiGet("/api/alerts?threshold=0.5&limit=50"),
        apiGet("/api/tasks?limit=40"),
        apiGet("/api/reports?limit=40"),
        apiGet("/api/cases?limit=40")
      ]);
      setHealth(healthData);
      setOverview(overviewData);
      setAlerts(alertsData.alerts || []);
      setAlertsMeta(alertsData);
      setTasks(tasksData.tasks || []);
      setReports(reportsData.reports || []);
      setCases(casesData.cases || []);
      setSelectedAlert((current) => current || (alertsData.alerts || [])[0] || null);
      setSelectedReport((current) => current || (reportsData.reports || [])[0] || null);
      setSelectedCase((current) => current || (casesData.cases || [])[0] || null);
      setLastRefreshedAt(new Date().toISOString());
    } catch (exc) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  const pollTask = useCallback(
    async (taskId) => {
      let lastTask = null;
      for (let index = 0; index < 80; index += 1) {
        const payload = await apiGet(`/api/tasks/${taskId}`);
        lastTask = payload.task;
        setTasks((current) => [lastTask, ...current.filter((task) => task.id !== lastTask.id)].slice(0, 40));
        if (["succeeded", "failed"].includes(lastTask.status)) break;
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
      await refreshAll();
      return lastTask;
    },
    [refreshAll]
  );

  const runTask = useCallback(
    async (taskType, extra = {}) => {
      setBusyTask(taskType);
      setError("");
      try {
        const selected = selectedAlert || {};
        const parameters = {
          threshold: Number(filters.threshold || 0.5),
          max_events: 5,
          top_k: 4,
          alert_id: selected.alert_id || selected._mineshark_alert_id || filters.alert_id || undefined,
          uid: selected.uid || selected._mineshark_uid || filters.uid || undefined,
          ip: filters.ip || selected.src_ip || selected.srcip || undefined,
          ...extra
        };
        const created = await apiPost("/api/tasks", { task_type: taskType, parameters });
        await pollTask(created.task.id);
      } catch (exc) {
        setError(exc.message);
      } finally {
        setBusyTask(null);
      }
    },
    [filters, pollTask, selectedAlert]
  );

  const applyAlertFilters = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.set(key === "alert_id" ? "alert_id" : key, value);
      });
      params.set("limit", "100");
      const payload = await apiGet(`/api/alerts?${params.toString()}`);
      setAlerts(payload.alerts || []);
      setAlertsMeta(payload);
      setSelectedAlert((payload.alerts || [])[0] || null);
    } catch (exc) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  const loadEvidence = useCallback(
    async (alert = selectedAlert) => {
      setLoading(true);
      setError("");
      try {
        const params = new URLSearchParams();
        const threshold = filters.threshold || "0.5";
        params.set("threshold", threshold);
        params.set("max_events", "5");
        params.set("top_k", "4");
        const id = alert?.alert_id || alert?._mineshark_alert_id || filters.alert_id;
        const uid = alert?.uid || alert?._mineshark_uid || filters.uid;
        const ip = filters.ip || alert?.src_ip || alert?.srcip;
        if (id) params.set("alert_id", id);
        if (uid) params.set("uid", uid);
        if (ip) params.set("ip", ip);
        const payload = await apiGet(`/api/evidence?${params.toString()}`);
        setEvidence(payload);
        if (alert) setSelectedAlert(alert);
      } catch (exc) {
        setError(exc.message);
      } finally {
        setLoading(false);
      }
    },
    [filters, selectedAlert]
  );

  const loadReport = useCallback(async (reportId) => {
    setLoading(true);
    setError("");
    try {
      const payload = await apiGet(`/api/reports/${reportId}`);
      setSelectedReport(payload.report);
    } catch (exc) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const syncCases = useCallback(async () => {
    setBusyTask("case-sync");
    setError("");
    try {
      const threshold = Number(filters.threshold || 0.5);
      await apiPost(`/api/cases/sync?threshold=${encodeURIComponent(threshold)}`, {});
      await refreshAll();
    } catch (exc) {
      setError(exc.message);
    } finally {
      setBusyTask(null);
    }
  }, [filters.threshold, refreshAll]);

  const createCase = useCallback(
    async (alert = selectedAlert) => {
      if (!alert) return;
      setLoading(true);
      setError("");
      try {
        const created = await apiPost("/api/cases", {
          alert_key: alertKey(alert),
          alert_snapshot: alert
        });
        setCases((current) => [created.case, ...current]);
        setSelectedCase(created.case);
        setActiveView("cases");
      } catch (exc) {
        setError(exc.message);
      } finally {
        setLoading(false);
      }
    },
    [selectedAlert]
  );

  const updateCaseDecision = useCallback(async (caseId, decision) => {
    setLoading(true);
    setError("");
    try {
      const updated = await apiPatch(`/api/cases/${caseId}`, decision);
      setCases((current) => current.map((item) => (item.id === caseId ? updated.case : item)));
      setSelectedCase(updated.case);
    } catch (exc) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const context = {
    activeView,
    setActiveView,
    health,
    overview,
    alerts,
    alertsMeta,
    tasks,
    reports,
    cases,
    selectedAlert,
    setSelectedAlert,
    selectedReport,
    selectedCase,
    setSelectedCase,
    evidence,
    filters,
    setFilters,
    loading,
    busyTask,
    error,
    runTask,
    refreshAll,
    applyAlertFilters,
    loadEvidence,
    loadReport,
    createCase,
    updateCaseDecision,
    syncCases
  };
  const activeNavItem = navItems.find((item) => item.id === activeView) || navItems[0];
  const pageTitle = activeView === "overview" ? "安全态势指挥台" : activeNavItem.label;
  const lastUpdated = lastRefreshedAt || "等待首次读取";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">MS</div>
          <div>
            <strong>MineShark</strong>
            <span>LOCAL TRIAGE NODE</span>
          </div>
        </div>
        <div className="side-context">
          <span>本地加密流量研判</span>
          <strong>安全运营验证平台</strong>
        </div>
        <nav className="nav-list" aria-label="MineShark 工作台导航">
          {navGroups.map((group) => (
            <div className="nav-group" key={group}>
              <span className="nav-group-label">{group}</span>
              {navItems.filter((item) => item.group === group).map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${activeView === item.id ? "active" : ""}`}
                    type="button"
                    onClick={() => setActiveView(item.id)}
                  >
                    <Icon size={18} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="node-state">
            <span className="status-dot" />
            <strong>本地节点在线</strong>
          </div>
          <span>旁路只读 · 分析员确认</span>
          <code>{health?.config?.deepseek?.model || "DeepSeek"}</code>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">MINESHARK / NODE-01 / {activeNavItem.group}</p>
            <h1>{pageTitle}</h1>
            <div className="topbar-meta">
              <span><LockKeyhole size={13} /> 本地部署</span>
              <span><Radio size={13} /> 旁路只读</span>
              <span><GitBranch size={13} /> 全程留痕</span>
              <span><Clock3 size={13} /> 更新：{displayTime(lastUpdated)}</span>
            </div>
          </div>
          <div className="topbar-actions">
            <IconButton icon={RefreshCw} label="同步告警" onClick={syncCases} disabled={!!busyTask} />
            <IconButton icon={RefreshCw} label="刷新数据" onClick={refreshAll} disabled={loading} variant="secondary" iconOnly />
          </div>
        </header>

        {error ? (
          <div className="error-banner">
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        ) : null}

        {busyTask ? (
          <div className="task-banner">
            <Loader2 size={18} className="spin" />
            <span>{taskLabels[busyTask]} 正在执行</span>
          </div>
        ) : null}

        {activeView === "overview" ? <OverviewPage {...context} /> : null}
        {activeView === "alerts" ? <AlertsPage {...context} /> : null}
        {activeView === "cases" ? <CasesPage {...context} /> : null}
        {activeView === "evidence" ? <EvidencePage {...context} /> : null}
        {activeView === "reports" ? <ReportsPage {...context} /> : null}
        {activeView === "history" ? <HistoryPage {...context} /> : null}
      </main>
    </div>
  );
}

function OverviewPage({ health, overview, cases, runTask, setActiveView, loadEvidence, selectedAlert }) {
  const sourceData = useMemo(() => {
    const sources = overview?.sources || {};
    return Object.entries(sourceLabels).map(([key, label]) => ({
      key,
      label,
      ok: key === "rag_index" ? !!(sources[key]?.knowledge_faiss && sources[key]?.metadata_json) : !!sources[key]?.ok
    }));
  }, [overview]);
  const totalAlerts = overview?.alerts?.matched || 0;
  const highAlerts = overview?.alerts?.risk_counts?.high || 0;
  const sourceReady = sourceData.filter((source) => source.ok).length;
  const sourceMissing = Math.max(sourceData.length - sourceReady, 0);
  const caseCounts = cases.reduce(
    (counts, item) => ({ ...counts, [item.status]: (counts[item.status] || 0) + 1 }),
    { new: 0, in_review: 0, escalated: 0, closed: 0 }
  );
  const latestAlert = overview?.alerts?.latest?.[0] || selectedAlert;
  const latestCase =
    (latestAlert && cases.find((item) => item.alert_key === alertKey(latestAlert))) || cases[0] || null;
  const deploymentOnline = health?.status === "ok";
  const decisionLabel = latestCase?.disposition
    ? dispositionLabels[latestCase.disposition] || latestCase.disposition
    : "待人工复核";
  const decisionTone = latestCase?.disposition === "benign"
    ? "success"
    : latestCase?.disposition === "malicious"
      ? "risk"
      : "warning";
  const evidenceDetail = sourceMissing > 0 ? `${sourceMissing} 个来源未连接` : "全部来源已连接";
  const railNodes = [
    {
      id: "signal",
      label: "模型信号",
      value: `${totalAlerts} 条命中`,
      detail: latestAlert ? `score ${scoreOf(latestAlert)?.toFixed(3) || "-"}` : "暂无告警",
      icon: ShieldAlert,
      tone: highAlerts > 0 ? "risk" : "neutral",
      action: () => setActiveView("alerts")
    },
    {
      id: "evidence",
      label: "证据接入",
      value: `${sourceReady}/${sourceData.length} 已连接`,
      detail: evidenceDetail,
      icon: Network,
      tone: sourceMissing > 0 ? "warning" : "success",
      action: () => {
        if (latestAlert) loadEvidence(latestAlert);
        setActiveView("evidence");
      }
    },
    {
      id: "case",
      label: "人工案件",
      value: latestCase ? caseStatusLabels[latestCase.status] || latestCase.status : "尚未建案",
      detail: latestCase?.owner ? `负责人 ${latestCase.owner}` : "等待分析员接手",
      icon: ClipboardCheck,
      tone: latestCase?.status === "closed" ? "success" : "warning",
      action: () => setActiveView("cases")
    },
    {
      id: "decision",
      label: "最终结论",
      value: decisionLabel,
      detail: latestCase?.decision_reason || "尚无人工研判依据",
      icon: ShieldCheck,
      tone: decisionTone,
      action: () => setActiveView("cases")
    }
  ];
  const latestAlerts = overview?.alerts?.latest || [];
  const hasTrend = latestAlerts.length > 1;

  return (
    <div className="view-grid overview-grid">
      <section className="command-overview wide" aria-label="当前研判与本地运行边界">
        <article className="decision-summary" aria-labelledby="decision-summary-title">
          <div className="section-headline">
            <span><AlertTriangle size={15} /> 当前研判</span>
            <span className="semantic-state state-risk">模型信号</span>
          </div>
          <div className="decision-measure">
            <strong>{highAlerts}</strong>
            <div>
              <h2 id="decision-summary-title">条高风险模型信号</h2>
              <p>证据覆盖 {sourceReady}/{sourceData.length}，模型输出必须经证据关联和分析员复核。</p>
            </div>
          </div>
          {latestAlert ? (
            <button className="signal-reference" type="button" onClick={() => setActiveView("alerts")}>
              <span className={`risk-badge risk-${riskOf(latestAlert)}`}>{riskLabels[riskOf(latestAlert)]}</span>
              <code>{alertKey(latestAlert)}</code>
              <span>{srcIp(latestAlert)} → {dstIp(latestAlert)}</span>
              <time>{displayTime(alertTime(latestAlert))}</time>
            </button>
          ) : null}
          <div className={`decision-outcome outcome-${decisionTone}`}>
            <div>
              <span>人工复核结论</span>
              <strong>{decisionLabel}</strong>
            </div>
            <p>{latestCase?.decision_reason || "尚未形成案件结论，需由分析员补充研判依据。"}</p>
          </div>
          <div className="sample-sufficiency">
            <History size={14} />
            <div>
              <span>时间趋势</span>
              <strong>{hasTrend ? `当前窗口有 ${latestAlerts.length} 条样本，可按时间继续核验。` : "样本不足以形成趋势"}</strong>
              <small>{hasTrend ? "趋势仅依据当前接口返回的告警时间。" : "当前仅有一个时间样本，未绘制虚构时间序列。"}</small>
            </div>
          </div>
        </article>

        <aside className="deployment-boundary" aria-label="本地部署边界">
          <div className="section-headline">
            <span><HardDrive size={15} /> 本地运行边界</span>
            <span className={`semantic-state state-${deploymentOnline ? "success" : "risk"}`}>
              {deploymentOnline ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
              {deploymentOnline ? "节点在线" : "节点异常"}
            </span>
          </div>
          <div className="boundary-grid">
            <div><span>运行节点</span><strong>NODE-01</strong><small>本地进程</small></div>
            <div><span>数据处理</span><strong>旁路只读</strong><small>本地读取</small></div>
            <div><span>自动处置</span><strong>未启用</strong><small>分析员确认</small></div>
            <div><span>当前接入</span><strong>{sourceReady}/{sourceData.length}</strong><small>以实际配置为准</small></div>
          </div>
          <div className="boundary-path">
            <LockKeyhole size={14} />
            <span>项目根目录</span>
            <code>{health?.project_root || "本地部署目录"}</code>
          </div>
          <p className="boundary-capability">支持接入 Wazuh / Zeek / Suricata；当前连接状态见下方数据源清单。</p>
          <div className="boundary-actions">
            <IconButton icon={Play} label="环境预检" onClick={() => runTask("preflight")} variant="ghost" />
            <IconButton icon={BrainCircuit} label="生成研判报告" onClick={() => runTask("agent-report")} variant="secondary" />
          </div>
        </aside>
      </section>

      <section
        className="evidence-rail wide"
        data-evidence-state={sourceMissing > 0 ? "gap" : "complete"}
        aria-labelledby="evidence-rail-title"
      >
        <div className="rail-head">
          <div>
            <span>研判链路总线</span>
            <h2 id="evidence-rail-title">从模型信号到人工结论</h2>
          </div>
          <span className={`semantic-state state-${sourceMissing > 0 ? "warning" : "success"}`}>
            {sourceMissing > 0 ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}
            证据覆盖 {sourceReady}/{sourceData.length}
          </span>
        </div>
        <div className="rail-track">
          {railNodes.map((node, index) => {
            const Icon = node.icon;
            return (
              <button className={`rail-node tone-${node.tone}`} type="button" key={node.id} onClick={node.action}>
                <span className="rail-index">0{index + 1}</span>
                <span className="rail-icon"><Icon size={17} /></span>
                <span className="rail-copy">
                  <span>{node.label}</span>
                  <strong>{node.value}</strong>
                  <small title={node.detail}>{node.detail}</small>
                </span>
              </button>
            );
          })}
        </div>
        <div className="rail-note"><LockKeyhole size={14} /> 状态来自当前告警文件、数据源配置与 SQLite 案件快照。</div>
      </section>

      <section className="status-strip wide" aria-label="指挥台关键状态">
        {[
          ["当前风险", `${highAlerts}/${totalAlerts}`, "高风险 / 全部命中", AlertTriangle, "risk"],
          ["证据覆盖", `${sourceReady}/${sourceData.length}`, evidenceDetail, Network, sourceMissing > 0 ? "warning" : "success"],
          ["处置闭环", `${caseCounts.closed}/${cases.length}`, "已关闭 / 全部案件", ClipboardCheck, "success"],
          ["本地部署", deploymentOnline ? "在线" : "异常", "旁路只读 · 可控运行", HardDrive, deploymentOnline ? "success" : "risk"]
        ].map(([label, value, detail, Icon, tone]) => (
          <div className={`status-cell tone-${tone}`} key={label}>
            <Icon size={17} />
            <div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
          </div>
        ))}
      </section>

      <section className="work-panel command-queue">
        <div className="work-panel-head">
          <div><span>研判工作区</span><h2>最新告警与案件</h2></div>
          <button type="button" className="text-action" onClick={() => setActiveView("alerts")}>查看全部告警</button>
        </div>
        <div className="table-wrap">
          <table className="command-table">
            <thead><tr><th>风险</th><th>Alert ID</th><th>通信对象</th><th>证据</th><th>案件</th><th>负责人</th><th>时间</th></tr></thead>
            <tbody>
              {latestAlerts.length ? latestAlerts.map((alert, index) => {
                const linkedCase = cases.find((item) => item.alert_key === alertKey(alert));
                return (
                  <tr key={`${alertKey(alert)}-${index}`}>
                    <td><span className={`risk-badge risk-${riskOf(alert)}`}>{riskLabels[riskOf(alert)]}</span></td>
                    <td><button className="row-link" type="button" onClick={() => setActiveView("alerts")}>{alertKey(alert)}</button></td>
                    <td><code>{srcIp(alert)} → {dstIp(alert)}</code></td>
                    <td><span className={`queue-evidence ${sourceMissing > 0 ? "is-warning" : "is-ready"}`}>{sourceReady}/{sourceData.length}</span></td>
                    <td><span className={`semantic-state state-${linkedCase?.status === "closed" ? "success" : "warning"}`}>{linkedCase ? caseStatusLabels[linkedCase.status] || linkedCase.status : "未建案"}</span></td>
                    <td>{linkedCase?.owner || "待分配"}</td>
                    <td><time>{displayTime(alertTime(alert))}</time></td>
                  </tr>
                );
              }) : (
                <tr><td colSpan="7"><EmptyState title="当前没有告警" detail="检查告警文件路径或刷新数据。" /></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="work-panel source-readiness">
        <div className="work-panel-head">
          <div><span>实际连接状态</span><h2>数据源运行状态</h2></div>
          <Server size={18} />
        </div>
        <div className="source-list command-source-list">
          {sourceData.map((source) => (
            <div className="source-row" key={source.key}>
              <span>{source.label}</span>
              <span className={`source-state ${source.ok ? "is-ready" : "is-missing"}`}>
                {source.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                {source.ok ? "已连接" : "未连接"}
              </span>
            </div>
          ))}
        </div>
        <div className="quick-actions">
          <IconButton icon={TerminalSquare} label="证据聚合" onClick={() => runTask("evidence-only")} variant="secondary" />
          <IconButton
            icon={Network}
            label="查看拓扑"
            onClick={() => {
              if (latestAlert) loadEvidence(latestAlert);
              setActiveView("evidence");
            }}
            variant="ghost"
          />
        </div>
      </section>
    </div>
  );
}

function AlertsPage({
  alerts,
  alertsMeta,
  cases,
  evidence,
  filters,
  setFilters,
  selectedAlert,
  setSelectedAlert,
  applyAlertFilters,
  loadEvidence,
  createCase,
  selectedCase,
  setSelectedCase,
  setActiveView,
  error
}) {
  const linkedCase = selectedAlert ? cases.find((item) => item.alert_key === alertKey(selectedAlert)) : null;
  const bundle = evidenceAppliesToAlert(evidence?.evidence_bundle, selectedAlert) ? evidence.evidence_bundle : null;
  const coverage = evidenceCoverage(bundle);

  return (
    <div className="view-grid alerts-grid">
      <PageHeader
        eyebrow="研判 / 告警队列"
        title="AI 告警工作台"
        detail="模型信号按当前筛选范围进入队列；告警详情保存原始快照，并可进入证据与案件流程。"
        meta={<><span>当前筛选范围：{Object.values(filters).filter(Boolean).length ? "已应用条件" : "默认阈值"}</span><span>数据来源：MineShark AI 告警文件</span><span>命中：{alertsMeta.matched || 0} / {alertsMeta.total_records || 0}</span></>}
      />
      <WorkspaceError error={error} />
      <section className="panel filter-panel wide">
        <div className="panel-head">
          <div><span className="panel-kicker">队列条件</span><h2>当前筛选范围</h2></div>
          <Filter size={18} />
        </div>
        <div className="filter-row">
          <label>
            IP
            <input value={filters.ip} onChange={(event) => setFilters({ ...filters, ip: event.target.value })} placeholder="10.0.0.5" />
          </label>
          <label>
            UID
            <input value={filters.uid} onChange={(event) => setFilters({ ...filters, uid: event.target.value })} placeholder="Cdemo1" />
          </label>
          <label>
            Alert ID
            <input value={filters.alert_id} onChange={(event) => setFilters({ ...filters, alert_id: event.target.value })} placeholder="demo-alert-001" />
          </label>
          <label>
            阈值
            <input value={filters.threshold} onChange={(event) => setFilters({ ...filters, threshold: event.target.value })} placeholder="0.5" />
          </label>
          <IconButton icon={Search} label="查询" onClick={applyAlertFilters} />
        </div>
      </section>

      <section className="panel table-panel alerts-table-panel">
        <div className="panel-head">
          <div><span className="panel-kicker">优先队列</span><h2>AI 告警流</h2></div>
          <span className="muted">按模型分数与人工案件状态查看</span>
        </div>
        <AlertsTable alerts={alerts} cases={cases} evidence={bundle} selectedAlert={selectedAlert} onSelect={setSelectedAlert} />
      </section>

      <section className="panel detail-panel investigation-panel">
        <div className="panel-head">
          <div><span className="panel-kicker">调查上下文</span><h2>告警详情</h2></div>
          <ShieldCheck size={18} />
        </div>
        {selectedAlert ? (
          <>
            <div className="detail-title">
              <strong>{alertKey(selectedAlert)}</strong>
              <span className={`risk-badge risk-${riskOf(selectedAlert)}`}>{riskLabels[riskOf(selectedAlert)]}</span>
            </div>
            <div className="kv-grid">
              <span>时间</span><strong>{alertTime(selectedAlert)}</strong>
              <span>源地址</span><strong>{srcIp(selectedAlert)}</strong>
              <span>目的地址</span><strong>{dstIp(selectedAlert)}</strong>
              <span>概率</span><strong>{scoreOf(selectedAlert)?.toFixed(3) || "-"}</strong>
            </div>
            <div className="investigation-summary">
              <div><span>模型信号</span><strong>{riskLabels[riskOf(selectedAlert)]} · {scoreOf(selectedAlert)?.toFixed(3) || "未提供分数"}</strong></div>
              <div><span>证据覆盖</span><strong>{coverage ? `${coverage.ready}/${coverage.total} 已返回` : "尚未聚合"}</strong></div>
              <div><span>关联案件</span><strong>{linkedCase ? caseStatusLabels[linkedCase.status] || linkedCase.status : "未建案"}</strong></div>
            </div>
            <details className="raw-snapshot" open>
              <summary>原始告警快照</summary>
              <pre className="json-preview">{JSON.stringify(selectedAlert, null, 2)}</pre>
            </details>
            <div className="detail-actions">
              <IconButton
                icon={Network}
                label="生成证据拓扑"
                onClick={() => {
                  loadEvidence(selectedAlert);
                  setActiveView("evidence");
                }}
              />
              <IconButton
                icon={ClipboardCheck}
                label={linkedCase ? "查看案件" : "创建案件"}
                onClick={() => {
                  if (linkedCase) {
                    setSelectedCase(linkedCase);
                    setActiveView("cases");
                    return;
                  }
                  createCase(selectedAlert);
                }}
                variant="secondary"
              />
            </div>
          </>
        ) : (
          <EmptyState title="暂无选中告警" detail="当前筛选条件没有返回 MineShark AI 告警。" />
        )}
      </section>
    </div>
  );
}

function WorkspaceError({ error }) {
  if (!error) return null;
  return (
    <div className="workspace-error" role="alert">
      <AlertTriangle size={17} />
      <div><strong>当前工作区数据读取异常</strong><span>错误信息：{error}</span></div>
    </div>
  );
}

function PageHeader({ eyebrow, title, detail, meta, actions }) {
  return (
    <header className="workspace-header wide">
      <div>
        <span className="workspace-kicker">{eyebrow}</span>
        <h2>{title}</h2>
        <p>{detail}</p>
        {meta ? <div className="workspace-meta">{meta}</div> : null}
      </div>
      {actions ? <div className="workspace-actions">{actions}</div> : null}
    </header>
  );
}

function CasesPage({ cases, selectedCase, setSelectedCase, updateCaseDecision, loading, error }) {
  const [draft, setDraft] = useState({ status: "new", disposition: "", owner: "", decision_reason: "" });

  useEffect(() => {
    setDraft({
      status: selectedCase?.status || "new",
      disposition: selectedCase?.disposition || "",
      owner: selectedCase?.owner || "",
      decision_reason: selectedCase?.decision_reason || ""
    });
  }, [selectedCase]);

  const snapshot = selectedCase?.alert_snapshot || {};
  const timeline = caseTimeline(selectedCase);
  return (
    <div className="view-grid cases-grid">
      <PageHeader
        eyebrow="研判 / 人工案件"
        title="研判案件工作台"
        detail="案件保留告警事实快照、当前负责人、研判依据与最终结论；模型信号不能绕过人工确认。"
        meta={<><span>案件总数：{cases.length}</span><span>当前状态：{selectedCase ? caseStatusLabels[selectedCase.status] || selectedCase.status : "未选择案件"}</span><span>存储：SQLite 案件快照</span></>}
      />
      <WorkspaceError error={error} />
      {!cases.length ? <EmptyState title="暂无研判案件" detail="在 AI 告警详情中创建案件后，可在此完成处置与复盘。" /> : null}
      {cases.length ? <>
      <section className="panel case-list">
        <div className="panel-head">
          <div><span className="panel-kicker">优先队列</span><h2>研判队列</h2></div>
          <span className="muted">{cases.length} 个案件</span>
        </div>
        <div className="case-items">
          {cases.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`case-item ${selectedCase?.id === item.id ? "active" : ""}`}
              onClick={() => setSelectedCase(item)}
              >
                <div>
                  <strong>{item.alert_key}</strong>
                  <span>{item.owner || "未分配"} · 更新 {displayTime(item.updated_at)}</span>
                </div>
                <StatusPill status={item.status} />
              </button>
            ))}
        </div>
      </section>

      <section className="panel case-detail">
        <div className="panel-head">
          <div>
            <span className="panel-kicker">调查上下文</span><h2>案件研判</h2>
            <span className="muted">{selectedCase?.id || "-"}</span>
          </div>
          <StatusPill status={selectedCase?.status} />
        </div>
        {selectedCase ? (
          <>
            <section className="fact-snapshot">
              <div className="subsection-head"><h3>事实快照</h3><span>建案时保存，后续不覆盖原始告警</span></div>
              <div className="case-evidence-grid">
              <span>Alert ID</span><strong>{selectedCase.alert_key}</strong>
              <span>UID</span><strong>{snapshot.uid || snapshot._mineshark_uid || "-"}</strong>
              <span>源地址</span><strong>{srcIp(snapshot)}</strong>
              <span>目的地址</span><strong>{dstIp(snapshot)}</strong>
              <span>模型概率</span><strong>{scoreOf(snapshot)?.toFixed(3) || "-"}</strong>
              <span>创建时间</span><strong className="timestamp-value">{displayTime(selectedCase.created_at)}</strong>
              </div>
            </section>

            <section className="case-timeline-block">
              <div className="subsection-head"><h3>案件时间线</h3><span>当前 schema 保存关键时间戳，不虚构逐项操作日志</span></div>
              <ol className="case-timeline">
                {timeline.map((event, index) => (
                  <li className={`timeline-${event.tone}`} key={`${event.label}-${index}`}>
                    <span className="timeline-marker" aria-hidden="true" />
                    <div><strong>{event.label}</strong><time>{displayTime(event.time)}</time><p>{event.detail}</p></div>
                  </li>
                ))}
              </ol>
            </section>

            <div className="case-form">
              <div className="form-heading"><h3>处置与结论</h3><span>选择“待研判”可将已关闭案件重新打开。</span></div>
              <label>
                状态
                <select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
                  {Object.entries(caseStatusLabels).map(([value, label]) => <option key={value} value={value}>{value === "new" ? "待研判（重新打开）" : label}</option>)}
                </select>
              </label>
              <label>
                研判结论
                <select value={draft.disposition} onChange={(event) => setDraft({ ...draft, disposition: event.target.value })}>
                  <option value="">未下结论</option>
                  {Object.entries(dispositionLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
              </label>
              <label>
                负责人
                <input value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} placeholder="analyst-a" />
              </label>
              <label className="case-reason-field">
                研判依据
                <textarea
                  value={draft.decision_reason}
                  onChange={(event) => setDraft({ ...draft, decision_reason: event.target.value })}
                  placeholder="记录哪些证据支持或否定模型信号，以及后续处置建议。"
                  rows="5"
                />
              </label>
              <IconButton
                icon={CheckCircle2}
                label="保存研判"
                onClick={() => updateCaseDecision(selectedCase.id, draft)}
                disabled={loading}
              />
            </div>
          </>
        ) : null}
      </section>
      </> : null}
    </div>
  );
}

function EvidencePage({ selectedAlert, evidence, loadEvidence, alerts, setSelectedAlert, health, error }) {
  const selected = selectedAlert || alerts?.[0];
  const graph = useMemo(() => buildEvidenceGraph(selected, evidence, health?.sources), [selected, evidence, health]);
  const bundle = evidence?.evidence_bundle || {};
  const ledger = evidenceRows(bundle, health?.sources);
  const coverage = evidenceCoverage(evidence?.evidence_bundle);
  const chartData = ledger.map((item) => ({ name: item.label, value: item.count }));
  const hasEvidence = chartData.some((item) => item.value > 0);

  return (
    <div className="view-grid evidence-grid">
      <PageHeader
        eyebrow="研判 / 证据关系"
        title="证据拓扑与台账"
        detail="拓扑与台账只描述当前 evidence_bundle 返回的事件、缺失源和错误信息，不把未接入来源显示为在线。"
        meta={<><span>查询窗口：{evidence?.evidence_bundle ? queryWindow(bundle) : "尚未请求"}</span><span>覆盖：{coverage ? `${coverage.ready}/${coverage.total}` : "尚未聚合"}</span><span>关联告警：{selected ? alertKey(selected) : "未选择"}</span></>}
        actions={<IconButton icon={RefreshCw} label="刷新拓扑" onClick={() => loadEvidence(selected)} variant="secondary" disabled={!selected} />}
      />
      <WorkspaceError error={error} />
      <section className="panel graph-panel">
        <div className="panel-head">
          <div><span className="panel-kicker">关系视图</span><h2>证据关系拓扑</h2></div>
          <span className="muted">虚线表示当前没有返回旁证</span>
        </div>
        {selected ? (
          <div className="flow-wrap">
            <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView minZoom={0.5} maxZoom={1.4}>
              <MiniMap pannable zoomable nodeColor={(node) => node.data?.color || "var(--evidence)"} />
              <Controls />
              <Background color="var(--border)" gap={18} />
            </ReactFlow>
          </div>
        ) : (
          <EmptyState title="暂无拓扑数据" detail="先在 AI 告警页选择一条告警。" />
        )}
      </section>

      <section className="panel evidence-side">
        <div className="panel-head">
          <div><span className="panel-kicker">来源核验</span><h2>证据台账</h2></div>
          <Network size={18} />
        </div>
        {hasEvidence ? (
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie dataKey="value" data={chartData} innerRadius={42} outerRadius={64} paddingAngle={2}>
                {ledger.map((item) => <Cell key={item.key} fill={item.status === "ready" ? "var(--evidence)" : item.status === "error" ? "var(--risk)" : "var(--neutral-status)"} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border-strong)" }} />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="evidence-empty"><span>尚未获得可展示的事件计数</span><strong>刷新拓扑后按当前查询条件聚合。</strong></div>
        )}
        <div className="ledger-window"><span>查询窗口</span><strong>{evidence?.evidence_bundle ? queryWindow(bundle) : "未请求 evidence_bundle"}</strong></div>
        <div className="table-wrap evidence-ledger">
          <table>
            <thead><tr><th>来源</th><th>状态</th><th>事件</th><th>缺失原因</th></tr></thead>
            <tbody>
              {ledger.map((item) => (
                <tr key={item.key}>
                  <td>{item.label}</td>
                  <td><StatusPill status={item.status} /></td>
                  <td>{item.count}</td>
                  <td title={item.reason}>{item.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel table-panel wide">
        <div className="panel-head">
          <div><span className="panel-kicker">切换对象</span><h2>可选告警</h2></div>
          <span className="muted">点击后可刷新拓扑</span>
        </div>
        <AlertsTable
          alerts={alerts}
          selectedAlert={selectedAlert}
          onSelect={(alert) => {
            setSelectedAlert(alert);
            loadEvidence(alert);
          }}
          compact
        />
      </section>
    </div>
  );
}

function ReportsPage({ reports, selectedReport, loadReport, runTask, cases, error }) {
  const selectedAlertId = selectedReport?.parameters?.alert_id || selectedReport?.parameters?.uid || "-";
  const linkedCase = cases.find((item) => item.alert_key === selectedReport?.parameters?.alert_id);
  return (
    <div className="view-grid reports-grid">
      <PageHeader
        eyebrow="交付留痕 / 报告快照"
        title="报告中心"
        detail="报告队列保留生成任务、参数、状态和 Markdown 内容，方便从交付结果回溯到关联告警或案件。"
        meta={<><span>报告数量：{reports.length}</span><span>生成方式：Agent 报告 / 证据聚合 / 预检</span><span>存储：任务输出快照</span></>}
        actions={<IconButton icon={BrainCircuit} label="生成报告" onClick={() => runTask("agent-report")} />}
      />
      <WorkspaceError error={error} />
      <section className="panel report-list">
        <div className="panel-head">
          <div><span className="panel-kicker">可追溯队列</span><h2>报告队列</h2></div>
          <span className="muted">按完成时间排序</span>
        </div>
        <div className="report-items">
          {reports.length ? (
            reports.map((report) => (
              <button
                key={report.id}
                type="button"
                className={`report-item ${selectedReport?.id === report.id ? "active" : ""}`}
                onClick={() => loadReport(report.id)}
              >
                <strong>{taskLabels[report.task_type] || report.task_type}</strong>
                <span>任务来源：{report.id}</span>
                <span>关联告警：{report.parameters?.alert_id || report.parameters?.uid || "未指定"}</span>
                <div><StatusPill status={report.status} /><time>{displayTime(report.finished_at || report.created_at)}</time></div>
              </button>
            ))
          ) : (
            <EmptyState title="暂无报告" detail="运行 Agent 报告后会出现在这里。" />
          )}
        </div>
      </section>
      <section className="panel report-reader">
        <div className="panel-head">
          <div><span className="panel-kicker">审计阅读器</span><h2>可追溯阅读器</h2></div>
          <FileText size={18} />
        </div>
        {selectedReport ? (
          <>
            <div className="report-trace">
              <div><span>报告状态</span><StatusPill status={selectedReport.status} /></div>
              <div><span>任务来源</span><strong>{taskLabels[selectedReport.task_type] || selectedReport.task_type}</strong></div>
              <div><span>关联告警 / 案件</span><strong>{selectedAlertId}{linkedCase ? ` / ${linkedCase.id}` : " / 未建案"}</strong></div>
              <div><span>生成时间</span><strong>{displayTime(selectedReport.finished_at || selectedReport.created_at)}</strong></div>
            </div>
            {selectedReport.error ? <div className="report-error"><AlertTriangle size={15} /> 错误信息：{selectedReport.error}</div> : null}
            <article className="markdown-body">
              <pre>{selectedReport.markdown || selectedReport.report?.markdown_report || "暂无 Markdown 内容"}</pre>
            </article>
          </>
        ) : (
          <EmptyState title="未选择报告" detail="左侧列表为空或尚未加载报告快照。" />
        )}
      </section>
    </div>
  );
}

function HistoryPage({ health, tasks, runTask, refreshAll, error }) {
  const sourceRows = Object.entries(health?.sources || {});
  return (
    <div className="view-grid history-grid">
      <PageHeader
        eyebrow="交付留痕 / 运行记录"
        title="任务历史"
        detail="预检、证据聚合、研判报告和告警同步都以任务状态、时间与错误信息保留在本地工作台。"
        meta={<><span>任务数量：{tasks.length}</span><span>节点：NODE-01</span><span>运行边界：旁路只读</span></>}
        actions={<><IconButton icon={TerminalSquare} label="Preflight" onClick={() => runTask("preflight")} variant="secondary" /><IconButton icon={RefreshCw} label="刷新" onClick={refreshAll} variant="secondary" iconOnly /></>}
      />
      <WorkspaceError error={error} />
      <section className="panel task-history">
        <div className="panel-head">
          <div><span className="panel-kicker">执行留痕</span><h2>任务时间线</h2></div>
          <span className="muted">任务类型：preflight / evidence-only / agent-report / case-sync</span>
        </div>
        {tasks.length ? <ol className="task-timeline">
          {tasks.map((task) => (
            <li key={task.id}>
              <span className={`task-marker marker-${task.status}`} aria-hidden="true" />
              <div className="task-timeline-main"><strong>{taskLabels[task.task_type] || task.task_type}</strong><code>{task.id}</code><span>创建：{displayTime(task.created_at)}</span></div>
              <StatusPill status={task.status} />
              <div className="task-timeline-detail"><span>完成：{displayTime(task.finished_at)}</span><p>{task.error ? `错误信息：${task.error}` : task.summary?.report_status || task.summary?.preflight_ok?.toString() || "尚无任务摘要。"}</p></div>
            </li>
          ))}
        </ol> : <EmptyState title="暂无任务记录" detail="运行 Preflight、证据聚合或 Agent 报告后，时间线会保留本地任务状态。" />}
      </section>

      <section className="panel source-status">
        <div className="panel-head">
          <div><span className="panel-kicker">本地边界</span><h2>系统状态</h2></div>
          <Server size={18} />
        </div>
        {sourceRows.length ? <div className="source-list">
          {sourceRows.map(([key, value]) => {
            const ok = key === "rag_index" ? value.knowledge_faiss && value.metadata_json : value.ok;
            return (
              <div className="source-row" key={key}>
                <span>{sourceLabels[key] || key}</span>
                <StatusPill status={ok ? "ok" : "error"} />
              </div>
            );
          })}
        </div> : <EmptyState title="系统状态尚未读取" detail="刷新数据后显示当前配置与数据源健康状态。" />}
        <div className="config-block">
          <span>数据库</span>
          <strong>{health?.database?.tasks || 0} tasks / {health?.database?.reports || 0} reports</strong>
          <span>项目路径</span>
          <strong>{health?.project_root}</strong>
        </div>
      </section>
    </div>
  );
}

function AlertsTable({ alerts = [], selectedAlert, onSelect, compact = false, cases = [], evidence }) {
  const coverage = evidenceCoverage(evidence);
  if (!alerts.length) {
    return <EmptyState title="暂无告警" detail="检查 AI 告警路径、筛选条件或运行环境权限。" />;
  }
  return (
    <div className="table-wrap">
      <table className={compact ? "compact-table" : ""}>
        <thead>
          <tr>
            <th>风险</th>
            <th>Alert ID</th>
            <th>时间</th>
            <th>源地址</th>
            <th>目的地址</th>
            <th>概率</th>
            <th>证据覆盖</th>
            <th>案件状态</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => {
            const risk = riskOf(alert);
            const selected = selectedAlert && alertKey(selectedAlert) === alertKey(alert);
            const linkedCase = cases.find((item) => item.alert_key === alertKey(alert));
            const hasSelectedEvidence = evidenceAppliesToAlert(evidence, alert);
            return (
              <tr key={`${alertKey(alert)}-${index}`} className={selected ? "selected-row" : ""}>
                <td><span className={`risk-badge risk-${risk}`}>{riskLabels[risk]}</span></td>
                <td><button className="row-link" type="button" onClick={() => onSelect?.(alert)}>{alertKey(alert)}</button></td>
                <td>{alertTime(alert)}</td>
                <td>{srcIp(alert)}</td>
                <td>{dstIp(alert)}</td>
                <td>{scoreOf(alert)?.toFixed(3) || "-"}</td>
                <td>{hasSelectedEvidence && coverage ? `${coverage.ready}/${coverage.total}` : "未聚合"}</td>
                <td>{linkedCase ? <StatusPill status={linkedCase.status} /> : <span className="table-muted">未建案</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function buildEvidenceGraph(alert, evidence, healthSources = {}) {
  const bundle = evidence?.evidence_bundle || {};
  const query = bundle.query_keys || {};
  const source = query.ip || srcIp(alert || {});
  const dest = dstIp(alert || {});
  const ledger = evidenceRows(bundle, healthSources);
  const sourceState = Object.fromEntries(ledger.map((item) => [item.key, item]));
  const nodeTone = (key, fallback) => sourceState[key]?.status === "ready" ? fallback : sourceState[key]?.status === "error" ? "var(--risk)" : "var(--warning)";
  const nodeLabel = (key, title) => {
    const row = sourceState[key];
    const status = row?.status === "ready" ? "已返回" : row?.status === "error" ? "查询异常" : "未返回";
    return `${title}\n${row?.count || 0} 条 · ${status}`;
  };
  const nodeBase = {
    source: { label: `查询对象\n${source}`, color: "var(--evidence)", x: 0, y: 120, status: "ready" },
    ai: { label: nodeLabel("ai_alerts", "MineShark AI"), color: nodeTone("ai_alerts", "var(--evidence)"), x: 230, y: 20, status: sourceState.ai_alerts?.status },
    wazuh: { label: nodeLabel("wazuh", "Wazuh"), color: nodeTone("wazuh", "var(--success)"), x: 460, y: 20, status: sourceState.wazuh?.status },
    zeek: { label: nodeLabel("zeek", "Zeek"), color: nodeTone("zeek", "var(--success)"), x: 230, y: 220, status: sourceState.zeek?.status },
    suricata: { label: nodeLabel("suricata", "Suricata"), color: nodeTone("suricata", "var(--warning)"), x: 460, y: 220, status: sourceState.suricata?.status },
    rag: { label: nodeLabel("rag", "RAG"), color: nodeTone("rag", "var(--evidence)"), x: 690, y: 120, status: sourceState.rag?.status }
  };
  const nodes = Object.entries(nodeBase).map(([id, item]) => ({
    id,
    position: { x: item.x, y: item.y },
    data: { label: item.label, color: item.color },
    style: {
      background: "var(--surface)",
      color: "var(--text-primary)",
      border: `${item.status === "ready" ? "1px solid" : "1px dashed"} ${item.color}`,
      borderRadius: 4,
      width: 168,
      minHeight: 64,
      whiteSpace: "pre-line"
    }
  }));
  if (dest && dest !== "-") {
    nodes.push({
      id: "dest",
      position: { x: 0, y: 260 },
      data: { label: `目的地址\n${dest}`, color: "var(--risk)" },
      style: {
        background: "var(--surface)",
        color: "var(--text-primary)",
        border: "1px solid var(--warning)",
        borderRadius: 4,
        width: 168,
        minHeight: 64,
        whiteSpace: "pre-line"
      }
    });
  }
  const edgeBase = [
    ["source", "ai"],
    ["source", "zeek"],
    ["source", "suricata"],
    ["ai", "wazuh"],
    ["ai", "rag"]
  ];
  if (dest && dest !== "-") edgeBase.push(["source", "dest"]);
  const edges = edgeBase.map(([from, to], index) => ({
    id: `e-${from}-${to}-${index}`,
    source: from,
    target: to,
    animated: nodeBase[to]?.status === "ready",
    style: {
      stroke: nodeBase[to]?.status === "ready" ? "var(--evidence)" : "var(--warning)",
      strokeWidth: 2,
      strokeDasharray: nodeBase[to]?.status === "ready" ? undefined : "5 5"
    }
  }));
  return { nodes, edges };
}

export default App;
