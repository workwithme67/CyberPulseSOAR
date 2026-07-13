import { useEffect, useMemo, useState } from 'react';

type DashboardSummary = {
  total_alerts: number;
  open_alerts: number;
  investigating_alerts: number;
  resolved_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  malicious_ips: number;
  suspicious_ips: number;
  avg_risk_score: number;
  blocked_ips: number;
};

type RiskBucket = {
  label: string;
  range: string;
  count: number;
  pct: number;
};

type RiskDistributionResponse = {
  total: number;
  buckets: RiskBucket[];
};

type Alert = {
  id: number;
  alert_id: string;
  alert_type: string;
  source_ip: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'Open' | 'Investigating' | 'Resolved';
  description: string | null;
  risk_score: number;
  threat_verdict: string | null;
  enrichment_data?: string | null;
  created_at: string;
  updated_at: string;
};

type RecentAlertsResponse = {
  count: number;
  alerts: Alert[];
};

type LoadState = {
  loading: boolean;
  error: string | null;
};

const apiBase = import.meta.env.VITE_API_BASE_URL ?? '';
const refreshIntervalMs = 15_000;

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat('en-US').format(value);
}

function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
}

function riskTone(score: number): string {
  if (score >= 76) return 'Critical';
  if (score >= 51) return 'High';
  if (score >= 26) return 'Medium';
  return 'Low';
}

function verdictTone(verdict: string | null): string {
  if (!verdict) return 'Unknown';
  return verdict;
}

function ageLabel(isoDate: string): string {
  const created = new Date(isoDate).getTime();
  const minutes = Math.max(0, Math.round((Date.now() - created) / 60000));
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

function metricClass(value: number, label: string): string {
  const base = 'metric-card';
  if (label === 'Critical') return `${base} metric-critical`;
  if (label === 'High') return `${base} metric-high`;
  if (label === 'Open') return `${base} metric-open`;
  if (label === 'Resolved') return `${base} metric-resolved`;
  return base;
}

export default function App() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [risk, setRisk] = useState<RiskDistributionResponse | null>(null);
  const [alerts, setAlerts] = useState<RecentAlertsResponse | null>(null);
  const [state, setState] = useState<LoadState>({ loading: true, error: null });
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;

    const load = async () => {
      try {
        if (!active) return;
        setState({ loading: true, error: null });
        const [summaryData, riskData, alertsData] = await Promise.all([
          fetchJson<DashboardSummary>('/dashboard/summary'),
          fetchJson<RiskDistributionResponse>('/dashboard/risk-distribution'),
          fetchJson<RecentAlertsResponse>('/dashboard/recent-alerts?limit=10'),
        ]);
        if (!active) return;
        setSummary(summaryData);
        setRisk(riskData);
        setAlerts(alertsData);
        setLastUpdated(new Date().toLocaleTimeString());
        setState({ loading: false, error: null });
      } catch (error) {
        if (!active) return;
        setState({
          loading: false,
          error: error instanceof Error ? error.message : 'Unable to load dashboard data',
        });
      }
    };

    void load();
    timer = window.setInterval(() => {
      void load();
    }, refreshIntervalMs);

    return () => {
      active = false;
      if (timer) window.clearInterval(timer);
    };
  }, []);

  const activityLabel = useMemo(() => {
    if (!summary) return 'Waiting for live metrics';
    return `${formatNumber(summary.total_alerts)} alerts tracked across the environment`;
  }, [summary]);

  const strongestBucket = useMemo(() => {
    if (!risk || risk.buckets.length === 0) return null;
    return risk.buckets.reduce((highest, bucket) => (bucket.count > highest.count ? bucket : highest));
  }, [risk]);

  return (
    <div className="page-shell">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <main className="dashboard">
        <section className="hero-card">
          <div className="hero-copy">
            <p className="eyebrow">SOAR Incident Containment Engine</p>
            <h1>Live dashboard for incident containment, risk, and response posture.</h1>
            <p className="hero-text">
              Monitor alert volume, risk distribution, and recent incidents with a streamlined
              operational view built directly on the backend analytics API.
            </p>
            <div className="hero-meta">
              <span className="pill">Auto-refresh every 15s</span>
              <span className="pill">Backend connected via /dashboard</span>
              <span className="pill">Responsive operator console</span>
            </div>
          </div>
          <div className="hero-stat">
            <span className="hero-stat-label">Status</span>
            <strong>{state.error ? 'Degraded' : state.loading ? 'Syncing' : 'Healthy'}</strong>
            <p>{activityLabel}</p>
            <div className="hero-stat-footer">
              <span>Last updated</span>
              <strong>{lastUpdated ?? 'Waiting...'}</strong>
            </div>
          </div>
        </section>

        {state.error ? <section className="banner error">{state.error}</section> : null}

        <section className="metrics-grid">
          <MetricCard label="Total Alerts" value={summary?.total_alerts ?? 0} tone="neutral" />
          <MetricCard label="Open" value={summary?.open_alerts ?? 0} tone="open" />
          <MetricCard label="Investigating" value={summary?.investigating_alerts ?? 0} tone="neutral" />
          <MetricCard label="Resolved" value={summary?.resolved_alerts ?? 0} tone="resolved" />
          <MetricCard label="Critical" value={summary?.critical_alerts ?? 0} tone="critical" />
          <MetricCard label="High" value={summary?.high_alerts ?? 0} tone="high" />
          <MetricCard label="Malicious IPs" value={summary?.malicious_ips ?? 0} tone="critical" />
          <MetricCard label="Avg Risk" value={summary ? Math.round(summary.avg_risk_score) : 0} tone="neutral" suffix="/100" />
        </section>

        <section className="content-grid">
          <article className="panel chart-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Risk distribution</p>
                <h2>Weighted score bands</h2>
              </div>
              {strongestBucket ? <span className="panel-chip">Most common: {strongestBucket.label}</span> : null}
            </div>
            <div className="bars">
              {(risk?.buckets ?? []).map((bucket) => (
                <div className="bar-row" key={bucket.label}>
                  <div className="bar-meta">
                    <span className="bar-label">{bucket.label}</span>
                    <span className="bar-range">{bucket.range}</span>
                  </div>
                  <div className="bar-track">
                    <div className={`bar-fill bar-${bucket.label.toLowerCase()}`} style={{ width: `${Math.max(bucket.pct, bucket.count > 0 ? 6 : 0)}%` }} />
                  </div>
                  <div className="bar-values">
                    <strong>{formatNumber(bucket.count)}</strong>
                    <span>{formatPercent(bucket.pct)}</span>
                  </div>
                </div>
              ))}
              {risk?.buckets.length === 0 ? <p className="empty-state">No risk data returned yet.</p> : null}
            </div>
          </article>

          <article className="panel alerts-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Recent alerts</p>
                <h2>Latest incident activity</h2>
              </div>
              <span className="panel-chip">{alerts?.count ?? 0} returned</span>
            </div>
            <div className="alerts-table">
              {(alerts?.alerts ?? []).map((alert) => (
                <div className="alert-row" key={alert.id}>
                  <div>
                    <strong>{alert.alert_type}</strong>
                    <p>{alert.alert_id}</p>
                  </div>
                  <div>
                    <span className={`badge badge-${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                    <p>{alert.source_ip}</p>
                  </div>
                  <div>
                    <span className={`badge badge-status badge-${alert.status.toLowerCase()}`}>{alert.status}</span>
                    <p>{ageLabel(alert.created_at)}</p>
                  </div>
                  <div>
                    <strong>{alert.risk_score.toFixed(1)}</strong>
                    <p>{verdictTone(alert.threat_verdict)}</p>
                  </div>
                </div>
              ))}
              {!state.loading && (alerts?.alerts.length ?? 0) === 0 ? <p className="empty-state">No recent alerts available.</p> : null}
            </div>
          </article>
        </section>

        <section className="footer-grid">
          <div className="panel status-panel">
            <p className="section-label">Operational summary</p>
            <div className="status-list">
              <StatusRow label="Blocked IPs" value={summary?.blocked_ips ?? 0} />
              <StatusRow label="Suspicious IPs" value={summary?.suspicious_ips ?? 0} />
              <StatusRow label="Critical alerts" value={summary?.critical_alerts ?? 0} />
            </div>
          </div>
          <div className="panel note-panel">
            <p className="section-label">Connection</p>
            <h2>Backend-ready frontend</h2>
            <p>
              This dashboard is wired to the existing FastAPI analytics endpoints and can be
              pointed at a remote backend by setting VITE_API_BASE_URL.
            </p>
          </div>
        </section>
      </main>
    </div>
  );
}

function MetricCard(props: { label: string; value: number; tone: 'neutral' | 'open' | 'resolved' | 'critical' | 'high'; suffix?: string }) {
  const suffix = props.suffix ?? '';
  return (
    <article className={metricClass(props.value, props.label)}>
      <span className="metric-label">{props.label}</span>
      <strong className="metric-value">
        {formatNumber(props.value)}{suffix}
      </strong>
      <span className="metric-tone">{props.tone === 'neutral' ? 'Live metric' : props.tone}</span>
    </article>
  );
}

function StatusRow(props: { label: string; value: number }) {
  return (
    <div className="status-row">
      <span>{props.label}</span>
      <strong>{formatNumber(props.value)}</strong>
    </div>
  );
}
