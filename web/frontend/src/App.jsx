import { useCallback, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import ReactFlow, { Background, Controls, MiniMap } from "reactflow";
import remarkGfm from "remark-gfm";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  BrainCircuit,
  CheckCircle2,
  Clock3,
  Database,
  FileText,
  Filter,
  GitBranch,
  History,
  LayoutDashboard,
  Loader2,
  Network,
  Play,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  XCircle
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

const navItems = [
  { id: "overview", label: "总览", icon: LayoutDashboard },
  { id: "alerts", label: "AI 告警", icon: ShieldAlert },
  { id: "evidence", label: "证据拓扑", icon: GitBranch },
  { id: "reports", label: "报告中心", icon: FileText },
  { id: "history", label: "任务历史", icon: History }
];

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
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#38bdf8",
  informational: "#2dd4bf",
  unknown: "#94a3b8"
};

const taskLabels = {
  preflight: "Preflight",
  "evidence-only": "证据聚合",
  "agent-report": "Agent 报告"
};

const REPORTS_PER_PAGE = 5;
const REPORTS_HISTORY_LIMIT = 50;
const ALERTS_LIMIT = 50;
const ALERTS_PER_PAGE = 10;
const EVIDENCE_ALERTS_PER_PAGE = 5;
const TASKS_HISTORY_LIMIT = 50;
const TASKS_PER_PAGE = 10;
const MIN_TASK_BUSY_MS = 2000;
const TASK_POLL_INTERVAL_MS = 1500;
const MAX_TASK_POLL_MS = 30 * 60 * 1000;
const RUNNING_TASK_REFRESH_MS = 5000;

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

function evidenceKeyFromAlert(alert) {
  if (!alert) return "";
  return [alert.alert_id || alert._mineshark_alert_id || "", alert.uid || alert._mineshark_uid || "", srcIp(alert)].join("|");
}

function evidenceKeyFromBundle(evidence) {
  const query = evidence?.evidence_bundle?.query_keys || {};
  if (!query.alert_id && !query.uid && !query.ip) return "";
  return [query.alert_id || "", query.uid || "", query.ip || ""].join("|");
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (item) => String(item).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(
    date.getMinutes()
  )}:${pad(date.getSeconds())}`;
}

function formatDurationMs(value) {
  const totalSeconds = Math.max(0, Math.floor(value / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours) return `${hours}时${minutes}分${seconds}秒`;
  if (minutes) return `${minutes}分${seconds}秒`;
  return `${seconds}秒`;
}

function taskDuration(task) {
  const started = new Date(task?.started_at || task?.created_at || "");
  if (Number.isNaN(started.getTime())) return "-";
  const finished = task?.finished_at ? new Date(task.finished_at) : null;
  const ended = finished && !Number.isNaN(finished.getTime()) ? finished : task?.status === "running" ? new Date() : null;
  if (!ended) return "-";
  const duration = formatDurationMs(ended.getTime() - started.getTime());
  return task?.status === "running" ? `已运行 ${duration}` : duration;
}

function alertTime(alert) {
  return formatDateTime(alert?.timestamp || alert?._mineshark_timestamp || alert?.["@timestamp"] || alert?.generated_at);
}

function srcIp(alert) {
  return alert?.src_ip || alert?.srcip || alert?.["id.orig_h"] || "-";
}

function dstIp(alert) {
  return alert?.dst_ip || alert?.dstip || alert?.dest_ip || alert?.["id.resp_h"] || "-";
}

function StatusPill({ status }) {
  const normalized = status || "unknown";
  const Icon =
    normalized === "succeeded" || normalized === "ok"
      ? CheckCircle2
      : normalized === "failed" || normalized === "error"
        ? XCircle
        : normalized === "running"
          ? Loader2
          : Clock3;
  return (
    <span className={`status-pill status-${normalized}`}>
      <Icon size={14} className={normalized === "running" ? "spin" : ""} />
      {normalized}
    </span>
  );
}

function IconButton({ icon: Icon, label, onClick, disabled, variant = "primary", title, iconClassName = "" }) {
  return (
    <button className={`button button-${variant}`} type="button" onClick={onClick} disabled={disabled} title={title || label}>
      <Icon size={16} className={iconClassName} />
      <span>{label}</span>
    </button>
  );
}

function MetricCard({ label, value, detail, tone = "neutral", icon: Icon }) {
  return (
    <section className={`metric-card metric-${tone}`}>
      <div className="metric-head">
        <span>{label}</span>
        {Icon ? <Icon size={20} /> : null}
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </section>
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
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [filters, setFilters] = useState({ ip: "", uid: "", alert_id: "", threshold: "0.5" });
  const [loading, setLoading] = useState(false);
  const [busyTask, setBusyTask] = useState(null);
  const [error, setError] = useState("");

  const refreshAll = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [healthData, overviewData, alertsData, tasksData, reportsData] = await Promise.all([
        apiGet("/api/health"),
        apiGet("/api/overview"),
        apiGet(`/api/alerts?threshold=0.5&limit=${ALERTS_LIMIT}`),
        apiGet(`/api/tasks?limit=${TASKS_HISTORY_LIMIT}`),
        apiGet(`/api/reports?limit=${REPORTS_HISTORY_LIMIT}`)
      ]);
      setHealth(healthData);
      setOverview(overviewData);
      setAlerts(alertsData.alerts || []);
      setAlertsMeta(alertsData);
      setTasks((tasksData.tasks || []).slice(0, TASKS_HISTORY_LIMIT));
      setReports((reportsData.reports || []).slice(0, REPORTS_HISTORY_LIMIT));
      setSelectedAlert((current) => current || (alertsData.alerts || [])[0] || null);
      setSelectedReport((current) => current || (reportsData.reports || [])[0] || null);
    } catch (exc) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshTasks = useCallback(async () => {
    try {
      const tasksData = await apiGet(`/api/tasks?limit=${TASKS_HISTORY_LIMIT}`);
      setTasks((tasksData.tasks || []).slice(0, TASKS_HISTORY_LIMIT));
    } catch (exc) {
      setError(exc.message);
    }
  }, []);

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  useEffect(() => {
    if (!tasks.some((task) => ["queued", "running"].includes(task.status))) return undefined;
    const timer = window.setInterval(refreshTasks, RUNNING_TASK_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [refreshTasks, tasks]);

  const pollTask = useCallback(
    async (taskId) => {
      let lastTask = null;
      const deadline = Date.now() + MAX_TASK_POLL_MS;
      while (Date.now() < deadline) {
        const payload = await apiGet(`/api/tasks/${taskId}`);
        lastTask = payload.task;
        setTasks((current) => [lastTask, ...current.filter((task) => task.id !== lastTask.id)].slice(0, TASKS_HISTORY_LIMIT));
        if (["succeeded", "failed"].includes(lastTask.status)) break;
        await new Promise((resolve) => setTimeout(resolve, TASK_POLL_INTERVAL_MS));
      }
      await refreshAll();
      return lastTask;
    },
    [refreshAll]
  );

  const runTask = useCallback(
    async (taskType, extra = {}) => {
      const startedAt = Date.now();
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
        const elapsed = Date.now() - startedAt;
        if (elapsed < MIN_TASK_BUSY_MS) {
          await new Promise((resolve) => setTimeout(resolve, MIN_TASK_BUSY_MS - elapsed));
        }
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
      params.set("limit", String(ALERTS_LIMIT));
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

  const context = {
    activeView,
    setActiveView,
    health,
    overview,
    alerts,
    alertsMeta,
    tasks,
    reports,
    selectedAlert,
    setSelectedAlert,
    selectedReport,
    evidence,
    filters,
    setFilters,
    loading,
    busyTask,
    runTask,
    refreshAll,
    applyAlertFilters,
    loadEvidence,
    loadReport
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">MS</div>
          <div>
            <strong>MineShark</strong>
            <span>Console</span>
          </div>
        </div>
        <nav className="nav-list">
          {navItems.map((item) => {
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
        </nav>
        <div className="sidebar-footer">
          <span>旁路只读</span>
          <strong>{health?.config?.deepseek?.model || "DeepSeek"}</strong>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">AI Traffic Security Triage</p>
            <h1>MineShark Console</h1>
          </div>
          <div className="topbar-actions">
            <IconButton
              icon={busyTask === "preflight" ? Loader2 : Play}
              iconClassName={busyTask === "preflight" ? "spin" : ""}
              label={busyTask === "preflight" ? "运行中" : "Preflight"}
              onClick={() => runTask("preflight")}
              disabled={!!busyTask}
              variant="ghost"
            />
            <IconButton
              icon={busyTask === "agent-report" ? Loader2 : BrainCircuit}
              iconClassName={busyTask === "agent-report" ? "spin" : ""}
              label={busyTask === "agent-report" ? "生成中" : "生成报告"}
              onClick={() => runTask("agent-report")}
              disabled={!!busyTask}
            />
            <IconButton icon={RefreshCw} label="刷新" onClick={refreshAll} disabled={loading} variant="secondary" />
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
        {activeView === "evidence" ? <EvidencePage {...context} /> : null}
        {activeView === "reports" ? <ReportsPage {...context} /> : null}
        {activeView === "history" ? <HistoryPage {...context} /> : null}
      </main>
    </div>
  );
}

function OverviewPage({ overview, tasks, reports, runTask, setActiveView, loadEvidence, selectedAlert }) {
  const riskData = useMemo(() => {
    const counts = overview?.alerts?.risk_counts || {};
    return Object.entries(riskLabels).map(([key, label]) => ({ key, label, value: counts[key] || 0 }));
  }, [overview]);
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
  const latestTask = tasks?.[0];
  const latestReport = reports?.[0];

  return (
    <div className="view-grid overview-grid">
      <div className="metrics-row">
        <MetricCard label="AI 记录" value={totalAlerts} detail="最近 50 条告警记录" tone="blue" icon={ShieldAlert} />
        <MetricCard label="高危线索" value={highAlerts} detail="概率 0.9 及以上" tone="red" icon={AlertTriangle} />
        <MetricCard label="最近任务" value={latestTask?.status || "none"} detail={latestTask ? taskLabels[latestTask.task_type] : "暂无历史"} tone="green" icon={Activity} />
        <MetricCard
          label="报告状态"
          value={latestReport?.summary?.report_status || "none"}
          detail={latestReport ? formatDateTime(latestReport.finished_at || latestReport.created_at) : "暂无报告"}
          tone="amber"
          icon={FileText}
        />
      </div>

      <section className="panel chart-panel">
        <div className="panel-head">
          <h2>风险分布</h2>
          <BarChart3 size={18} />
        </div>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={riskData}>
            <CartesianGrid stroke="#223047" vertical={false} />
            <XAxis dataKey="label" stroke="#91a3ba" tickLine={false} axisLine={false} />
            <YAxis stroke="#91a3ba" tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip cursor={{ fill: "rgba(56,189,248,0.08)" }} contentStyle={{ background: "#111827", border: "1px solid #26364f" }} />
            <Bar dataKey="value" radius={[6, 6, 0, 0]}>
              {riskData.map((entry) => (
                <Cell key={entry.key} fill={riskColors[entry.key]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </section>

      <section className="panel sources-panel">
        <div className="panel-head">
          <h2>数据源健康</h2>
          <Server size={18} />
        </div>
        <div className="source-list">
          {sourceData.map((source) => (
            <div className="source-row" key={source.key}>
              <span>{source.label}</span>
              <StatusPill status={source.ok ? "ok" : "error"} />
            </div>
          ))}
        </div>
        <div className="quick-actions">
          <IconButton icon={TerminalSquare} label="证据聚合" onClick={() => runTask("evidence-only")} variant="secondary" />
          <IconButton
            icon={Network}
            label="查看拓扑"
            onClick={() => {
              if (selectedAlert) loadEvidence(selectedAlert);
              setActiveView("evidence");
            }}
            variant="secondary"
          />
        </div>
      </section>

      <section className="panel table-panel wide">
        <div className="panel-head">
          <h2>最新 AI 告警</h2>
          <button type="button" className="text-action" onClick={() => setActiveView("alerts")}>
            查看全部
          </button>
        </div>
        <AlertsTable alerts={overview?.alerts?.latest || []} compact />
      </section>
    </div>
  );
}

function AlertsPage({
  alerts,
  alertsMeta,
  filters,
  setFilters,
  selectedAlert,
  setSelectedAlert,
  applyAlertFilters,
  loadEvidence,
  setActiveView
}) {
  const [alertPage, setAlertPage] = useState(1);
  const recentAlerts = alerts.slice(0, ALERTS_LIMIT);
  const pageCount = Math.max(1, Math.ceil(recentAlerts.length / EVIDENCE_ALERTS_PER_PAGE));
  const visibleAlerts = recentAlerts.slice((alertPage - 1) * EVIDENCE_ALERTS_PER_PAGE, alertPage * EVIDENCE_ALERTS_PER_PAGE);

  useEffect(() => {
    setAlertPage((current) => Math.min(current, pageCount));
  }, [pageCount]);

  return (
    <div className="view-grid alerts-grid">
      <section className="panel filter-panel wide">
        <div className="panel-head">
          <h2>告警筛选</h2>
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
          <h2>AI 告警流</h2>
          <span className="muted">{alertsMeta.matched || 0} / {alertsMeta.total_records || 0}</span>
        </div>
        <div className="table-caption">
          当前筛选 {recentAlerts.length} 条
          {alertsMeta.matched > recentAlerts.length ? ` / 命中 ${alertsMeta.matched} 条` : ""}
        </div>
        <AlertsTable alerts={visibleAlerts} selectedAlert={selectedAlert} onSelect={setSelectedAlert} />
        <PaginationControls
          page={alertPage}
          pageCount={pageCount}
          total={recentAlerts.length}
          pageSize={EVIDENCE_ALERTS_PER_PAGE}
          onPageChange={setAlertPage}
        />
      </section>

      <section className="panel detail-panel">
        <div className="panel-head">
          <h2>告警详情</h2>
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
            <pre className="json-preview">{JSON.stringify(selectedAlert, null, 2)}</pre>
            <IconButton
              icon={Network}
              label="生成证据拓扑"
              onClick={() => {
                loadEvidence(selectedAlert);
                setActiveView("evidence");
              }}
            />
          </>
        ) : (
          <EmptyState title="暂无选中告警" detail="当前筛选条件没有返回 MineShark AI 告警。" />
        )}
      </section>
    </div>
  );
}

function EvidencePage({ selectedAlert, evidence, loadEvidence, alerts, setSelectedAlert, loading }) {
  const selected = selectedAlert || alerts?.[0];
  const [alertPage, setAlertPage] = useState(1);
  const [autoLoadedKey, setAutoLoadedKey] = useState("");
  const graph = useMemo(() => buildEvidenceGraph(selected, evidence), [selected, evidence]);
  const bundle = evidence?.evidence_bundle || {};
  const counts = {
    ai: bundle.selected_alerts?.length || 0,
    wazuh: bundle.wazuh_evidence?.alerts?.length || 0,
    zeek: bundle.zeek_context?.events?.length || 0,
    suricata: bundle.suricata_alerts?.alerts?.length || 0,
    rag: bundle.rag_matches?.matches?.length || 0
  };
  const recentAlerts = alerts.slice(0, ALERTS_LIMIT);
  const pageCount = Math.max(1, Math.ceil(recentAlerts.length / ALERTS_PER_PAGE));
  const visibleAlerts = recentAlerts.slice((alertPage - 1) * ALERTS_PER_PAGE, alertPage * ALERTS_PER_PAGE);

  useEffect(() => {
    setAlertPage((current) => Math.min(current, pageCount));
  }, [pageCount]);

  const selectedEvidenceKey = evidenceKeyFromAlert(selected);
  const loadedEvidenceKey = evidenceKeyFromBundle(evidence);
  const evidenceMatchesSelected = selectedEvidenceKey && selectedEvidenceKey === loadedEvidenceKey;
  const evidenceTotal = Object.values(counts).reduce((sum, value) => sum + value, 0);

  useEffect(() => {
    if (!selected || loading || evidenceMatchesSelected || autoLoadedKey === selectedEvidenceKey) return;
    setAutoLoadedKey(selectedEvidenceKey);
    loadEvidence(selected);
  }, [autoLoadedKey, evidenceMatchesSelected, loadEvidence, loading, selected, selectedEvidenceKey]);

  return (
    <div className="view-grid evidence-grid">
      <section className="panel graph-panel wide">
        <div className="panel-head">
          <h2>证据关系拓扑</h2>
          <div className="panel-actions">
            <IconButton icon={RefreshCw} label="刷新拓扑" onClick={() => loadEvidence(selected)} variant="secondary" disabled={!selected} />
          </div>
        </div>
        {selected ? (
          <div className="flow-wrap">
            <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView minZoom={0.5} maxZoom={1.4}>
              <MiniMap pannable zoomable nodeColor={(node) => node.data?.color || "#38bdf8"} />
              <Controls />
              <Background color="#334155" gap={18} />
            </ReactFlow>
          </div>
        ) : (
          <EmptyState title="暂无拓扑数据" detail="先在 AI 告警页选择一条告警。" />
        )}
      </section>

      <section className="panel evidence-side">
        <div className="panel-head">
          <h2>证据覆盖</h2>
          <Network size={18} />
        </div>
        {evidenceTotal ? (
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie dataKey="value" data={Object.entries(counts).map(([name, value]) => ({ name, value }))} innerRadius={50} outerRadius={78}>
                {Object.keys(counts).map((key) => (
                  <Cell key={key} fill={{ ai: "#38bdf8", wazuh: "#2dd4bf", zeek: "#a78bfa", suricata: "#f97316", rag: "#facc15" }[key]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #26364f" }} />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <EmptyState
            title={loading ? "正在聚合证据" : "暂无证据覆盖"}
            detail={selected ? "系统会自动查询当前告警，也可以点击刷新拓扑重试。" : "先在 AI 告警页选择一条告警。"}
          />
        )}
        <div className="source-list compact-list">
          <div><span>AI</span><strong>{counts.ai}</strong></div>
          <div><span>Wazuh</span><strong>{counts.wazuh}</strong></div>
          <div><span>Zeek</span><strong>{counts.zeek}</strong></div>
          <div><span>Suricata</span><strong>{counts.suricata}</strong></div>
          <div><span>RAG</span><strong>{counts.rag}</strong></div>
        </div>
      </section>

      <section className="panel table-panel wide">
        <div className="panel-head">
          <h2>可选告警</h2>
          <span className="muted">点击后可刷新拓扑</span>
        </div>
        <div className="table-caption">最近 {recentAlerts.length} 条告警</div>
        <AlertsTable
          alerts={visibleAlerts}
          selectedAlert={selectedAlert}
          onSelect={(alert) => {
            setSelectedAlert(alert);
            loadEvidence(alert);
          }}
          compact
        />
        <PaginationControls
          page={alertPage}
          pageCount={pageCount}
          total={recentAlerts.length}
          pageSize={ALERTS_PER_PAGE}
          onPageChange={setAlertPage}
        />
      </section>
    </div>
  );
}

function MarkdownReport({ markdown }) {
  return (
    <div className="markdown-rendered">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown>
    </div>
  );
}

function PaginationControls({ page, pageCount, total, pageSize, onPageChange }) {
  if (total <= pageSize) return null;
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="pagination-bar" aria-label="Report list pagination">
      <span>
        {start}-{end} / {total}
      </span>
      <div className="pagination-actions">
        <button type="button" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>
          上一页
        </button>
        <strong>
          {page} / {pageCount}
        </strong>
        <button type="button" onClick={() => onPageChange(page + 1)} disabled={page >= pageCount}>
          下一页
        </button>
      </div>
    </div>
  );
}

function ReportsPage({ reports, selectedReport, loadReport, runTask }) {
  const [reportPage, setReportPage] = useState(1);
  const recentReports = reports.slice(0, REPORTS_HISTORY_LIMIT);
  const pageCount = Math.max(1, Math.ceil(recentReports.length / REPORTS_PER_PAGE));
  const visibleReports = recentReports.slice((reportPage - 1) * REPORTS_PER_PAGE, reportPage * REPORTS_PER_PAGE);
  useEffect(() => {
    setReportPage((current) => Math.min(current, pageCount));
  }, [pageCount]);
  const markdown = selectedReport?.markdown || selectedReport?.report?.markdown_report || "暂无 Markdown 内容";

  return (
    <div className="view-grid reports-grid">
      <section className="panel report-list">
        <div className="panel-head">
          <h2>报告列表</h2>
          <IconButton icon={BrainCircuit} label="生成报告" onClick={() => runTask("agent-report")} />
        </div>
        <div className="table-caption">最近 {recentReports.length} 条报告</div>
        <div className="report-items">
          {recentReports.length ? (
            visibleReports.map((report) => (
              <button
                key={report.id}
                type="button"
                className={`report-item ${selectedReport?.id === report.id ? "active" : ""}`}
                onClick={() => loadReport(report.id)}
              >
                <strong>{taskLabels[report.task_type] || report.task_type}</strong>
                <span className="time-text" title={report.finished_at || report.created_at || ""}>
                  {formatDateTime(report.finished_at || report.created_at)}
                </span>
                <StatusPill status={report.status} />
              </button>
            ))
          ) : (
            <EmptyState title="暂无报告" detail="运行 Agent 报告后会出现在这里。" />
          )}
        </div>
        <PaginationControls
          page={reportPage}
          pageCount={pageCount}
          total={recentReports.length}
          pageSize={REPORTS_PER_PAGE}
          onPageChange={setReportPage}
        />
      </section>
      <section className="panel report-reader">
        <div className="panel-head">
          <h2>研判报告</h2>
        </div>
        {selectedReport ? (
          <article className="markdown-body">
            <MarkdownReport markdown={markdown} />
          </article>
        ) : (
          <EmptyState title="未选择报告" detail="左侧列表为空或尚未加载报告快照。" />
        )}
      </section>
    </div>
  );
}

function HistoryPage({ health, tasks, runTask, refreshAll, busyTask }) {
  const sourceRows = Object.entries(health?.sources || {});
  const [taskPage, setTaskPage] = useState(1);
  const recentTasks = tasks.slice(0, TASKS_HISTORY_LIMIT);
  const pageCount = Math.max(1, Math.ceil(recentTasks.length / TASKS_PER_PAGE));
  const visibleTasks = recentTasks.slice((taskPage - 1) * TASKS_PER_PAGE, taskPage * TASKS_PER_PAGE);

  useEffect(() => {
    setTaskPage((current) => Math.min(current, pageCount));
  }, [pageCount]);

  return (
    <div className="view-grid history-grid">
      <section className="panel table-panel wide">
        <div className="panel-head">
          <h2>任务历史</h2>
          <div className="panel-actions">
            <IconButton
              icon={busyTask === "preflight" ? Loader2 : TerminalSquare}
              iconClassName={busyTask === "preflight" ? "spin" : ""}
              label={busyTask === "preflight" ? "运行中" : "Preflight"}
              onClick={() => runTask("preflight")}
              disabled={!!busyTask}
              variant="secondary"
            />
            <IconButton icon={RefreshCw} label="刷新" onClick={refreshAll} variant="secondary" />
          </div>
        </div>
        <div className="table-caption">
          最近 {recentTasks.length} 条记录
          {health?.database?.tasks > recentTasks.length ? ` / 共 ${health.database.tasks} 条` : ""}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>任务</th>
                <th>状态</th>
                <th>创建时间</th>
                <th>完成时间</th>
                <th>耗时</th>
                <th>摘要</th>
              </tr>
            </thead>
            <tbody>
              {visibleTasks.map((task) => (
                <tr key={task.id}>
                  <td>{taskLabels[task.task_type] || task.task_type}</td>
                  <td><StatusPill status={task.status} /></td>
                  <td title={task.created_at || ""}>{formatDateTime(task.created_at)}</td>
                  <td title={task.finished_at || ""}>{formatDateTime(task.finished_at)}</td>
                  <td>{taskDuration(task)}</td>
                  <td>{task.error || task.summary?.report_status || task.summary?.preflight_ok?.toString() || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <PaginationControls
          page={taskPage}
          pageCount={pageCount}
          total={recentTasks.length}
          pageSize={TASKS_PER_PAGE}
          onPageChange={setTaskPage}
        />
      </section>

      <section className="panel source-status">
        <div className="panel-head">
          <h2>系统状态</h2>
          <Server size={18} />
        </div>
        <div className="source-list">
          {sourceRows.map(([key, value]) => {
            const ok = key === "rag_index" ? value.knowledge_faiss && value.metadata_json : value.ok;
            return (
              <div className="source-row" key={key}>
                <span>{sourceLabels[key] || key}</span>
                <StatusPill status={ok ? "ok" : "error"} />
              </div>
            );
          })}
        </div>
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

function AlertsTable({ alerts = [], selectedAlert, onSelect, compact = false }) {
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
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => {
            const risk = riskOf(alert);
            const selected = selectedAlert && alertKey(selectedAlert) === alertKey(alert);
            return (
              <tr key={`${alertKey(alert)}-${index}`} className={selected ? "selected-row" : ""} onClick={() => onSelect?.(alert)}>
                <td><span className={`risk-badge risk-${risk}`}>{riskLabels[risk]}</span></td>
                <td>{alertKey(alert)}</td>
                <td>{alertTime(alert)}</td>
                <td>{srcIp(alert)}</td>
                <td>{dstIp(alert)}</td>
                <td>{scoreOf(alert)?.toFixed(3) || "-"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function buildEvidenceGraph(alert, evidence) {
  const bundle = evidence?.evidence_bundle || {};
  const query = bundle.query_keys || {};
  const source = query.ip || srcIp(alert || {});
  const dest = dstIp(alert || {});
  const nodeBase = {
    source: { label: `源主机\n${source}`, color: "#38bdf8", x: 0, y: 120 },
    ai: { label: `MineShark AI\n${bundle.selected_alerts?.length || (alert ? 1 : 0)} 条`, color: "#22d3ee", x: 230, y: 20 },
    wazuh: { label: `Wazuh\n${bundle.wazuh_evidence?.alerts?.length || 0} 条`, color: "#2dd4bf", x: 460, y: 20 },
    zeek: { label: `Zeek\n${bundle.zeek_context?.events?.length || 0} 条`, color: "#a78bfa", x: 230, y: 220 },
    suricata: { label: `Suricata\n${bundle.suricata_alerts?.alerts?.length || 0} 条`, color: "#f97316", x: 460, y: 220 },
    rag: { label: `RAG\n${bundle.rag_matches?.matches?.length || 0} 条`, color: "#facc15", x: 690, y: 120 },
    report: { label: "研判报告\nMarkdown/JSON", color: "#34d399", x: 920, y: 120 }
  };
  const nodes = Object.entries(nodeBase).map(([id, item]) => ({
    id,
    position: { x: item.x, y: item.y },
    data: { label: item.label, color: item.color },
    style: {
      background: "#111827",
      color: "#e5edf7",
      border: `1px solid ${item.color}`,
      borderRadius: 8,
      width: 168,
      minHeight: 64,
      whiteSpace: "pre-line",
      boxShadow: "0 18px 40px rgba(0,0,0,0.28)"
    }
  }));
  if (dest && dest !== "-") {
    nodes.push({
      id: "dest",
      position: { x: 0, y: 260 },
      data: { label: `目的地址\n${dest}`, color: "#f43f5e" },
      style: {
        background: "#111827",
        color: "#e5edf7",
        border: "1px solid #f43f5e",
        borderRadius: 8,
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
    ["ai", "rag"],
    ["wazuh", "report"],
    ["zeek", "report"],
    ["suricata", "report"],
    ["rag", "report"]
  ];
  if (dest && dest !== "-") edgeBase.push(["source", "dest"]);
  const edges = edgeBase.map(([from, to], index) => ({
    id: `e-${from}-${to}-${index}`,
    source: from,
    target: to,
    animated: true,
    style: { stroke: "#5b6f8f", strokeWidth: 2 }
  }));
  return { nodes, edges };
}

export default App;
