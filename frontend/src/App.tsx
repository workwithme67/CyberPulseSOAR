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

type TimelineEvent = {
  id: number;
  alert_id: string;
  event_type: 'AlertCreated' | 'AlertEnriched' | 'RiskCalculated' | 'StatusUpdated' | 'PlaybookExecuted';
  description: string;
  occurred_at: string;
  metadata: any | null;
};

type PlaybookExecution = {
  id: number;
  alert_id: string;
  playbook_name: string;
  target: string;
  status: 'Success' | 'Failed' | 'Running';
  executed_by: string;
  executed_at: string;
  notes: string | null;
};

type Playbook = {
  name: string;
  description: string;
  action: string;
  target_type: string;
};

type UserProfile = {
  id: number;
  username: string;
  role: 'Admin' | 'SOCAnalyst' | 'Viewer';
  is_active: boolean;
};

const apiBase = import.meta.env.VITE_API_BASE_URL ?? '';
const refreshIntervalMs = 15_000;

function formatNumber(value: number): string {
  return new Intl.NumberFormat('en-US').format(value);
}

function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
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

export default function App() {
  // Tabs & Navigation
  const [activeTab, setActiveTab] = useState<'dashboard' | 'history'>('dashboard');

  // API Data States
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [risk, setRisk] = useState<RiskDistributionResponse | null>(null);
  const [alerts, setAlerts] = useState<RecentAlertsResponse | null>(null);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  
  // Triage Side-sheet (Drawer) States
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedAlertTimeline, setSelectedAlertTimeline] = useState<TimelineEvent[]>([]);
  
  // Modals & Auth States
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authType, setAuthType] = useState<'login' | 'register'>('login');
  
  // Auth User Session
  const [token, setToken] = useState<string | null>(localStorage.getItem('soar_jwt_token'));
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  
  // Operation States
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  
  // Form input bindings
  const [ingestForm, setIngestForm] = useState({
    alert_type: 'Brute Force',
    source_ip: '',
    severity: 'High',
    description: '',
  });
  
  const [authForm, setAuthForm] = useState({
    username: '',
    password: '',
    role: 'SOCAnalyst',
  });
  
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>('');
  const [playbookNotes, setPlaybookNotes] = useState<string>('');
  const [playbookRunning, setPlaybookRunning] = useState(false);
  const [playbookMessage, setPlaybookMessage] = useState<string | null>(null);

  // Helper headers provider
  const headers = useMemo(() => {
    const r: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (token) {
      r['Authorization'] = `Bearer ${token}`;
    }
    return r;
  }, [token]);

  // Load User Profile on token change
  useEffect(() => {
    if (!token) {
      setUserProfile(null);
      return;
    }
    fetch(`${apiBase}/auth/me`, { headers })
      .then((res) => {
        if (!res.ok) throw new Error('Session invalid');
        return res.json() as Promise<UserProfile>;
      })
      .then((data) => setUserProfile(data))
      .catch(() => {
        localStorage.removeItem('soar_jwt_token');
        setToken(null);
        setUserProfile(null);
      });
  }, [token, headers]);

  // Load registered playbooks if authenticated
  useEffect(() => {
    if (!token) {
      setPlaybooks([]);
      return;
    }
    fetch(`${apiBase}/playbooks/`, { headers })
      .then((res) => {
        if (!res.ok) return { playbooks: [] };
        return res.json() as Promise<{ playbooks: Playbook[] }>;
      })
      .then((data) => {
        setPlaybooks(data.playbooks);
        if (data.playbooks.length > 0) {
          setSelectedPlaybook(data.playbooks[0].name);
        }
      })
      .catch(() => setPlaybooks([]));
  }, [token, headers]);

  // Core Data Loading Function
  const loadDashboardData = async (showSyncIndicator = true) => {
    try {
      if (showSyncIndicator) setLoading(true);
      setError(null);
      
      const [summaryData, riskData, alertsData] = await Promise.all([
        fetch(`${apiBase}/dashboard/summary`, { headers }).then((res) => res.json() as Promise<DashboardSummary>),
        fetch(`${apiBase}/dashboard/risk-distribution`, { headers }).then((res) => res.json() as Promise<RiskDistributionResponse>),
        fetch(`${apiBase}/dashboard/recent-alerts?limit=15`, { headers }).then((res) => res.json() as Promise<RecentAlertsResponse>),
      ]);

      setSummary(summaryData);
      setRisk(riskData);
      setAlerts(alertsData);
      setLastUpdated(new Date().toLocaleTimeString());
      setLoading(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to sync dashboard analytics');
      setLoading(false);
    }
  };

  // Sync Interval
  useEffect(() => {
    void loadDashboardData(true);
    const interval = setInterval(() => {
      void loadDashboardData(false);
    }, refreshIntervalMs);
    return () => clearInterval(interval);
  }, [token]);

  // Sync playbook executions history
  const loadExecutionsHistory = async () => {
    if (!token) return;
    try {
      const res = await fetch(`${apiBase}/playbooks/executions`, { headers });
      if (res.ok) {
        const data = await res.json() as PlaybookExecution[];
        setExecutions(data);
      }
    } catch (err) {
      console.error('Error fetching playbook executions', err);
    }
  };

  useEffect(() => {
    if (activeTab === 'history') {
      void loadExecutionsHistory();
    }
  }, [activeTab, token]);

  // Selected Alert Details & Timeline Sync
  const fetchTimeline = async (alertId: string) => {
    try {
      const res = await fetch(`${apiBase}/alerts/${alertId}/timeline`, { headers });
      if (res.ok) {
        const data = await res.json() as TimelineEvent[];
        setSelectedAlertTimeline(data);
      }
    } catch (err) {
      console.error('Timeline fetch failed', err);
    }
  };

  const handleSelectAlert = (alert: Alert) => {
    setSelectedAlert(alert);
    setSelectedAlertTimeline([]);
    void fetchTimeline(alert.alert_id);
    setPlaybookMessage(null);
    setPlaybookNotes('');
  };

  // Change Status Handler
  const handleChangeStatus = async (statusVal: string) => {
    if (!selectedAlert) return;
    try {
      const res = await fetch(`${apiBase}/alerts/${selectedAlert.id}/status?new_status=${statusVal}`, {
        method: 'PATCH',
        headers,
      });
      if (res.ok) {
        const updated = await res.json() as Alert;
        setSelectedAlert(updated);
        void fetchTimeline(updated.alert_id);
        void loadDashboardData(false);
      } else {
        alert('Failed to update status');
      }
    } catch (err) {
      alert('Error updating status: ' + String(err));
    }
  };

  // Refresh Threat Intel Handler
  const handleRefreshTI = async () => {
    if (!selectedAlert) return;
    try {
      const res = await fetch(`${apiBase}/alerts/${selectedAlert.id}/enrich`, { headers });
      if (res.ok) {
        const updated = await res.json() as Alert;
        setSelectedAlert(updated);
        void fetchTimeline(updated.alert_id);
        void loadDashboardData(false);
      }
    } catch (err) {
      alert('Error refreshing threat intelligence');
    }
  };

  // Ingest Alert Submit Handler
  const handleIngestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${apiBase}/alerts/`, {
        method: 'POST',
        headers,
        body: JSON.stringify(ingestForm),
      });
      if (res.ok) {
        setShowIngestModal(false);
        setIngestForm({
          alert_type: 'Brute Force',
          source_ip: '',
          severity: 'High',
          description: '',
        });
        void loadDashboardData(true);
      } else {
        const txt = await res.text();
        alert('Validation error during alert ingestion: ' + txt);
      }
    } catch (err) {
      alert('Network error in alert creation');
    }
  };

  // Authenticate (Login / Register) Submit Handler
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const url = authType === 'login' ? `${apiBase}/auth/login` : `${apiBase}/auth/register`;
      const payload = authType === 'login' 
        ? { username: authForm.username, password: authForm.password }
        : { username: authForm.username, password: authForm.password, role: authForm.role };

      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errText = await res.text();
        alert(`Authentication failed: ${errText}`);
        return;
      }

      if (authType === 'login') {
        const data = await res.json() as { access_token: string };
        localStorage.setItem('soar_jwt_token', data.access_token);
        setToken(data.access_token);
        setShowAuthModal(false);
      } else {
        alert('Account registered! You can now log in.');
        setAuthType('login');
      }
    } catch (err) {
      alert('Authentication error');
    }
  };

  // Log Out Handler
  const handleLogout = () => {
    localStorage.removeItem('soar_jwt_token');
    setToken(null);
    setUserProfile(null);
  };

  // Playbook execution handler
  const handleExecutePlaybook = async () => {
    if (!selectedAlert || !selectedPlaybook) return;
    setPlaybookRunning(true);
    setPlaybookMessage(null);
    try {
      const res = await fetch(`${apiBase}/playbooks/execute`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          alert_id: selectedAlert.alert_id,
          playbook_name: selectedPlaybook,
          target: selectedAlert.source_ip,
          notes: playbookNotes,
        }),
      });

      if (res.ok) {
        const data = await res.json() as PlaybookExecution;
        setPlaybookMessage(`Success: Playbook ${data.playbook_name} completed. Status: ${data.status}`);
        setPlaybookNotes('');
        void fetchTimeline(selectedAlert.alert_id);
        void loadDashboardData(false);
      } else {
        const txt = await res.text();
        setPlaybookMessage(`Error: ${txt}`);
      }
    } catch (err) {
      setPlaybookMessage('Connection error executing playbook');
    } finally {
      setPlaybookRunning(false);
    }
  };

  // Deriving descriptive values
  const activityLabel = useMemo(() => {
    if (!summary) return 'Connecting to SOAR...';
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
        {/* Navigation & Controls Header */}
        <header className="header-row">
          <div className="header-brand">
            <h1>🛡️ SOAR Containment Console</h1>
          </div>
          
          <div className="header-controls">
            <nav className="tabs-nav">
              <button 
                className={`tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
                onClick={() => setActiveTab('dashboard')}
              >
                Dashboard
              </button>
              <button 
                className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
                onClick={() => setActiveTab('history')}
                disabled={!token}
                title={!token ? 'Log in to view playbook history' : ''}
              >
                Playbook Log
              </button>
            </nav>

            <button 
              className="btn btn-primary"
              onClick={() => setShowIngestModal(true)}
            >
              ➕ Ingest Alert
            </button>

            {/* Authenticated session widget */}
            {userProfile ? (
              <div className="auth-bar">
                <span className="auth-user">
                  👤 <strong>{userProfile.username}</strong> ({userProfile.role})
                </span>
                <button className="btn btn-secondary btn-sm" onClick={handleLogout}>
                  Log Out
                </button>
              </div>
            ) : (
              <button 
                className="btn btn-secondary"
                onClick={() => {
                  setAuthType('login');
                  setShowAuthModal(true);
                }}
              >
                🔑 Analyst Login
              </button>
            )}
          </div>
        </header>

        {activeTab === 'dashboard' ? (
          <>
            {/* Hero / Summary Section */}
            <section className="hero-card">
              <div className="hero-copy">
                <p className="eyebrow">SOAR Incident Containment Engine</p>
                <h1>Live dashboard for incident containment, risk, and response posture.</h1>
                <p className="hero-text">
                  Monitor alert volume, risk distribution, and recent incidents with a streamlined
                  operational view. Click on any alert to open the Analyst Triage Sheet.
                </p>
                <div className="hero-meta">
                  <span className="pill">Auto-refresh every 15s</span>
                  <span className="pill">SQLite DB Connected</span>
                  <span className="pill">Interactive Playbooks</span>
                </div>
              </div>
              <div className="hero-stat">
                <span className="hero-stat-label">Status</span>
                <strong>{error ? 'Degraded' : loading ? 'Syncing' : 'Healthy'}</strong>
                <p>{activityLabel}</p>
                <div className="hero-stat-footer">
                  <span>Last sync</span>
                  <strong>{lastUpdated ?? 'Waiting...'}</strong>
                </div>
              </div>
            </section>

            {error ? <section className="banner error">{error}</section> : null}

            {/* Top Metrics Row */}
            <section className="metrics-grid">
              <article className="metric-card">
                <span className="metric-label">Total Alerts</span>
                <strong className="metric-value">{summary?.total_alerts ?? 0}</strong>
                <span className="metric-tone">Environment</span>
              </article>
              <article className="metric-card metric-open">
                <span className="metric-label">Open Alerts</span>
                <strong className="metric-value">{summary?.open_alerts ?? 0}</strong>
                <span className="metric-tone">Triage Queue</span>
              </article>
              <article className="metric-card metric-resolved">
                <span className="metric-label">Resolved Alerts</span>
                <strong className="metric-value">{summary?.resolved_alerts ?? 0}</strong>
                <span className="metric-tone">Mitigated</span>
              </article>
              <article className="metric-card metric-critical">
                <span className="metric-label">Critical Alerts</span>
                <strong className="metric-value">{summary?.critical_alerts ?? 0}</strong>
                <span className="metric-tone">Mitigation Pending</span>
              </article>
            </section>

            {/* Bottom Content Grid */}
            <section className="content-grid">
              {/* Risk Score distribution histogram */}
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

              {/* Alert Ingestion Table */}
              <article className="panel alerts-panel">
                <div className="panel-header">
                  <div>
                    <p className="section-label">Incident triage feed</p>
                    <h2>Latest activities</h2>
                  </div>
                  <span className="panel-chip">{alerts?.count ?? 0} returned</span>
                </div>
                <div className="alerts-table">
                  {(alerts?.alerts ?? []).map((alert) => (
                    <div 
                      className={`alert-row alert-row-clickable ${selectedAlert?.id === alert.id ? 'selected' : ''}`} 
                      key={alert.id}
                      onClick={() => handleSelectAlert(alert)}
                    >
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
                        <p>{alert.threat_verdict ?? 'Unknown'}</p>
                      </div>
                    </div>
                  ))}
                  {!loading && (alerts?.alerts.length ?? 0) === 0 ? <p className="empty-state">No alerts available in database. Create one above!</p> : null}
                </div>
              </article>
            </section>

            {/* Bottom summary metrics panel */}
            <section className="footer-grid">
              <div className="panel status-panel">
                <p className="section-label">Containment health metrics</p>
                <div className="status-list">
                  <StatusRow label="Firewall Blocked IPs" value={summary?.blocked_ips ?? 0} />
                  <StatusRow label="Threat Intel Malicious Hits" value={summary?.malicious_ips ?? 0} />
                  <StatusRow label="Threat Intel Suspicious Hits" value={summary?.suspicious_ips ?? 0} />
                </div>
              </div>
              <div className="panel note-panel">
                <p className="section-label">Security Orchestration, Automation & Response</p>
                <h2>Containment Engine Integration</h2>
                <p>
                  Click any security alert in the feed above to review its full audit trail timeline, 
                  inspect AbuseIPDB + VirusTotal reputation markers, transition its lifecycle state, and execute 
                  automated host-isolation or firewall blocking playbooks.
                </p>
              </div>
            </section>
          </>
        ) : (
          /* Playbook history tab view */
          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Audit Logs</p>
                <h2>Playbook execution history</h2>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={loadExecutionsHistory}>
                🔄 Refresh Logs
              </button>
            </div>
            
            <table className="history-table">
              <thead>
                <tr>
                  <th>Playbook</th>
                  <th>Alert ID</th>
                  <th>Target</th>
                  <th>Executed By</th>
                  <th>Executed At</th>
                  <th>Status</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {executions.map((exec) => (
                  <tr key={exec.id}>
                    <td><strong>{exec.playbook_name}</strong></td>
                    <td>{exec.alert_id}</td>
                    <td><code>{exec.target}</code></td>
                    <td>{exec.executed_by}</td>
                    <td>{new Date(exec.executed_at).toLocaleString()}</td>
                    <td>
                      <span className={`badge ${exec.status === 'Success' ? 'badge-low' : 'badge-critical'}`}>
                        {exec.status}
                      </span>
                    </td>
                    <td>{exec.notes ?? '—'}</td>
                  </tr>
                ))}
                {executions.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', color: 'var(--muted)' }}>
                      No playbook executions logged.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </section>
        )}
      </main>

      {/* ── Slide-over drawer: Alert detail & triage ──────────────────────── */}
      {selectedAlert && (
        <>
          <div className="drawer-overlay" onClick={() => setSelectedAlert(null)} />
          <aside className="drawer-content">
            <header className="drawer-header">
              <div className="drawer-title-area">
                <span className="eyebrow">{selectedAlert.alert_id}</span>
                <h2>{selectedAlert.alert_type}</h2>
              </div>
              <button className="close-btn" onClick={() => setSelectedAlert(null)}>
                &times;
              </button>
            </header>
            
            <div className="drawer-body">
              {/* Actions Section */}
              <section className="drawer-section">
                <span className="drawer-section-title">Workflow management</span>
                <div className="info-grid">
                  <div className="form-group">
                    <label>Lifecycle status</label>
                    <select 
                      className="select-field" 
                      value={selectedAlert.status}
                      onChange={(e) => handleChangeStatus(e.target.value)}
                    >
                      <option value="Open">Open</option>
                      <option value="Investigating">Investigating</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Severity</label>
                    <div>
                      <span className={`badge badge-${selectedAlert.severity.toLowerCase()}`} style={{ fontSize: '1rem', padding: '6px 12px' }}>
                        {selectedAlert.severity}
                      </span>
                    </div>
                  </div>
                </div>
              </section>

              {/* Threat Information */}
              <section className="drawer-section">
                <span className="drawer-section-title">Incident details</span>
                <div className="info-grid">
                  <div className="info-item">
                    <span>Source IP Address</span>
                    <strong>{selectedAlert.source_ip}</strong>
                  </div>
                  <div className="info-item">
                    <span>Calculated Risk Score</span>
                    <strong style={{ color: selectedAlert.risk_score >= 76 ? 'var(--danger)' : 'inherit' }}>
                      {selectedAlert.risk_score.toFixed(1)} / 100
                    </strong>
                  </div>
                  <div className="info-item">
                    <span>Threat Intel Verdict</span>
                    <strong>{selectedAlert.threat_verdict ?? 'Unknown'}</strong>
                  </div>
                  <div className="info-item" style={{ justifyContent: 'center' }}>
                    <button className="btn btn-secondary btn-sm" style={{ width: 'fit-content' }} onClick={handleRefreshTI}>
                      🔄 Sync Threat Intel
                    </button>
                  </div>
                </div>
                {selectedAlert.description && (
                  <div style={{ marginTop: '12px' }}>
                    <span style={{ fontSize: '0.8rem', color: 'var(--muted)' }}>Description</span>
                    <p style={{ margin: '4px 0 0', fontSize: '0.9rem', background: 'rgba(255,255,255,0.03)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                      {selectedAlert.description}
                    </p>
                  </div>
                )}
              </section>

              {/* Automated Containment Playbooks */}
              <section className="drawer-section">
                <span className="drawer-section-title">Containment Orchestration</span>
                {token ? (
                  <div className="playbook-exec-box">
                    <div className="form-group">
                      <label>Select Response Action</label>
                      <select 
                        className="select-field"
                        value={selectedPlaybook}
                        onChange={(e) => setSelectedPlaybook(e.target.value)}
                      >
                        {playbooks.map((pb) => (
                          <option key={pb.name} value={pb.name}>
                            {pb.name} - {pb.description}
                          </option>
                        ))}
                        {playbooks.length === 0 && <option value="">No playbooks loaded</option>}
                      </select>
                    </div>

                    <div className="form-group">
                      <label>Analyst execution notes</label>
                      <input 
                        type="text"
                        className="input-field"
                        placeholder="Explain reason for isolation or blocking..."
                        value={playbookNotes}
                        onChange={(e) => setPlaybookNotes(e.target.value)}
                      />
                    </div>

                    <button 
                      className="btn btn-danger" 
                      onClick={handleExecutePlaybook}
                      disabled={playbookRunning || !selectedPlaybook}
                    >
                      🚀 Run Playbook
                    </button>

                    {playbookMessage && (
                      <p style={{ margin: '8px 0 0', fontSize: '0.85rem', color: playbookMessage.startsWith('Success') ? 'var(--good)' : 'var(--danger)' }}>
                        {playbookMessage}
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="banner" style={{ background: 'rgba(245, 197, 66, 0.08)', borderColor: 'rgba(245, 197, 66, 0.2)', color: '#fde8a6' }}>
                    ⚠️ <strong>Access Denied:</strong> You must log in as a SOC Analyst to execute containment playbooks on the network.
                  </div>
                )}
              </section>

              {/* Incident Lifecycle Timeline */}
              <section className="drawer-section">
                <span className="drawer-section-title">Incident Audit Timeline</span>
                <div className="timeline-list">
                  {selectedAlertTimeline.map((evt) => {
                    const dotClass = 
                      evt.event_type === 'AlertCreated' ? 'created' :
                      evt.event_type === 'AlertEnriched' ? 'enriched' :
                      evt.event_type === 'RiskCalculated' ? 'risk' :
                      evt.event_type === 'StatusUpdated' ? 'status' :
                      'playbook';
                      
                    return (
                      <div className="timeline-item" key={evt.id}>
                        <div className={`timeline-dot ${dotClass}`} />
                        <div className="timeline-meta">
                          <span className="timeline-type">{evt.event_type}</span>
                          <span className="timeline-time">{new Date(evt.occurred_at).toLocaleTimeString()}</span>
                        </div>
                        <p className="timeline-desc">{evt.description}</p>
                      </div>
                    );
                  })}
                  {selectedAlertTimeline.length === 0 && (
                    <p className="empty-state">Loading timeline history...</p>
                  )}
                </div>
              </section>
            </div>
          </aside>
        </>
      )}

      {/* ── Modal Dialog: Ingest Alert ────────────────────────────────────── */}
      {showIngestModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <header className="modal-header">
              <h2>Ingest Security Alert</h2>
              <button className="close-btn" onClick={() => setShowIngestModal(false)}>&times;</button>
            </header>
            
            <form onSubmit={handleIngestSubmit}>
              <div className="form-group">
                <label>Alert Type / Category</label>
                <select 
                  className="select-field"
                  value={ingestForm.alert_type}
                  onChange={(e) => setIngestForm({ ...ingestForm, alert_type: e.target.value })}
                >
                  <option value="Brute Force">Brute Force</option>
                  <option value="Malware Detection">Malware Detection</option>
                  <option value="Suspicious Login">Suspicious Login</option>
                  <option value="Port Scan">Port Scan</option>
                  <option value="Credential Stuffing">Credential Stuffing</option>
                  <option value="Ransomware Activity">Ransomware Activity</option>
                  <option value="SQL Injection">SQL Injection</option>
                </select>
              </div>

              <div className="form-group">
                <label>Source IPv4 Address</label>
                <input 
                  type="text" 
                  className="input-field"
                  placeholder="e.g. 192.168.1.105"
                  required
                  value={ingestForm.source_ip}
                  onChange={(e) => setIngestForm({ ...ingestForm, source_ip: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Reported Severity</label>
                <select 
                  className="select-field"
                  value={ingestForm.severity}
                  onChange={(e) => setIngestForm({ ...ingestForm, severity: e.target.value })}
                >
                  <option value="Low">Low</option>
                  <option value="Medium">Medium</option>
                  <option value="High">High</option>
                  <option value="Critical">Critical</option>
                </select>
              </div>

              <div className="form-group">
                <label>Incident Description / Payload context</label>
                <textarea 
                  className="textarea-field"
                  rows={3}
                  placeholder="Provide payload context, raw log outputs or endpoint info..."
                  value={ingestForm.description}
                  onChange={(e) => setIngestForm({ ...ingestForm, description: e.target.value })}
                />
              </div>

              <footer className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowIngestModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Ingest & Enrich
                </button>
              </footer>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal Dialog: Login / Registration ───────────────────────────── */}
      {showAuthModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <header className="modal-header">
              <h2>{authType === 'login' ? 'SOC Analyst Log In' : 'Create SOC Account'}</h2>
              <button className="close-btn" onClick={() => setShowAuthModal(false)}>&times;</button>
            </header>
            
            <form onSubmit={handleAuthSubmit}>
              <div className="form-group">
                <label>Username</label>
                <input 
                  type="text" 
                  className="input-field" 
                  required
                  placeholder="Enter username..."
                  value={authForm.username}
                  onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Password</label>
                <input 
                  type="password" 
                  className="input-field" 
                  required
                  placeholder="Enter secure password..."
                  value={authForm.password}
                  onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                />
              </div>

              {authType === 'register' && (
                <div className="form-group">
                  <label>Assign Role</label>
                  <select 
                    className="select-field"
                    value={authForm.role}
                    onChange={(e) => setAuthForm({ ...authForm, role: e.target.value })}
                  >
                    <option value="SOCAnalyst">SOC Analyst (Can trigger playbooks)</option>
                    <option value="Admin">System Admin (Full operations)</option>
                    <option value="Viewer">Viewer (Read-only)</option>
                  </select>
                </div>
              )}

              <div style={{ fontSize: '0.85rem', color: 'var(--muted)', margin: '8px 0' }}>
                {authType === 'login' ? (
                  <>
                    No account?{' '}
                    <a href="#" style={{ color: 'var(--accent)' }} onClick={() => setAuthType('register')}>
                      Register account
                    </a>
                  </>
                ) : (
                  <>
                    Already registered?{' '}
                    <a href="#" style={{ color: 'var(--accent)' }} onClick={() => setAuthType('login')}>
                      Sign in here
                    </a>
                  </>
                )}
              </div>

              <footer className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowAuthModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  {authType === 'login' ? 'Log In' : 'Register Account'}
                </button>
              </footer>
            </form>
          </div>
        </div>
      )}
    </div>
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
