import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

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

type Toast = {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
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
  const [activeTab, setActiveTab] = useState<'dashboard' | 'history' | 'analytics'>('dashboard');

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
    email: '',
    password: '',
    role: 'SOCAnalyst',
  });
  
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>('');
  const [playbookNotes, setPlaybookNotes] = useState<string>('');
  const [playbookRunning, setPlaybookRunning] = useState(false);
  const [playbookMessage, setPlaybookMessage] = useState<string | null>(null);

  const [activeTiData, setActiveTiData] = useState<any>(null);
  const [tiTab, setTiTab] = useState<'abuseipdb' | 'virustotal' | 'ipinfo'>('abuseipdb');
  const [tiDiagnostics, setTiDiagnostics] = useState<any>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Search & filter
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [filterStatus, setFilterStatus] = useState<string>('All');
  const [sortBy, setSortBy] = useState<'time' | 'risk' | 'severity'>('time');
  const searchRef = useRef<HTMLInputElement>(null);

  // Live pulse
  const [isPulsing, setIsPulsing] = useState(false);
  const [copiedIp, setCopiedIp] = useState(false);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelectedAlert(null);
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const addToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

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

  // Load TI Diagnostics on mount
  useEffect(() => {
    fetch(`${apiBase}/health/ti-diagnostics`)
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load TI diagnostics');
        return res.json();
      })
      .then((data) => setTiDiagnostics(data))
      .catch((err) => console.error("Error loading TI diagnostics", err));
  }, []);

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

  const severityOrder: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

  // Filtered + sorted alerts derived state
  const filteredAlerts = useMemo(() => {
    const list = (alerts?.alerts ?? []).filter((a) => {
      const matchSearch =
        !searchQuery ||
        a.alert_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        a.source_ip.includes(searchQuery) ||
        a.alert_id.toLowerCase().includes(searchQuery.toLowerCase());
      const matchSeverity = filterSeverity === 'All' || a.severity === filterSeverity;
      const matchStatus = filterStatus === 'All' || a.status === filterStatus;
      return matchSearch && matchSeverity && matchStatus;
    });
    if (sortBy === 'risk') return [...list].sort((a, b) => b.risk_score - a.risk_score);
    if (sortBy === 'severity') return [...list].sort((a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0));
    return list; // default: time (API order)
  }, [alerts, searchQuery, filterSeverity, filterStatus, sortBy]);

  // Core Data Loading Function
  const loadDashboardData = async (showSyncIndicator = true) => {
    try {
      if (showSyncIndicator) setLoading(true);
      setError(null);

      const fetchJson = async <T,>(url: string, options?: RequestInit): Promise<T> => {
        const res = await fetch(url, options);
        if (!res.ok) {
          throw new Error(`Failed to fetch data (status ${res.status})`);
        }
        return res.json() as Promise<T>;
      };
      
      const [summaryData, riskData, alertsData] = await Promise.all([
        fetchJson<DashboardSummary>(`${apiBase}/dashboard/summary`, { headers }),
        fetchJson<RiskDistributionResponse>(`${apiBase}/dashboard/risk-distribution`, { headers }),
        fetchJson<RecentAlertsResponse>(`${apiBase}/dashboard/recent-alerts?limit=15`, { headers }),
      ]);

      setSummary(summaryData);
      setRisk(riskData);
      setAlerts(alertsData);
      setLastUpdated(new Date().toLocaleTimeString());
      setLoading(false);
      setIsPulsing(true);
      setTimeout(() => setIsPulsing(false), 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to sync dashboard analytics');
      setLoading(false);
    }
  };

  // Sync Interval
  const stableLoad = useCallback(loadDashboardData, [token]);
  useEffect(() => {
    void stableLoad(true);
    const interval = setInterval(() => void stableLoad(false), refreshIntervalMs);
    return () => clearInterval(interval);
  }, [stableLoad]);

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

  const downloadCSV = async (url: string, filename: string) => {
    try {
      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error("Failed to download CSV");
      const blob = await res.blob();
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      addToast("CSV Report downloaded successfully", "success");
    } catch (e) {
      addToast("Failed to download CSV Report", "error");
    }
  };

  const handleSelectAlert = (alert: Alert) => {
    setSelectedAlert(alert);
    setSelectedAlertTimeline([]);
    setActiveTiData(null);
    void fetchTimeline(alert.alert_id);

    if (alert.enrichment_data) {
      try {
        const parsed = JSON.parse(alert.enrichment_data);
        setActiveTiData(parsed);
      } catch (e) {
        console.error("Failed to parse cached enrichment_data", e);
      }
    } else {
      void fetchLiveTi(alert.id);
    }

    setPlaybookMessage(null);
    setPlaybookNotes('');
  };

  const fetchLiveTi = async (id: number) => {
    try {
      const res = await fetch(`${apiBase}/alerts/${id}/enrich`, { headers });
      if (res.ok) {
        const data = await res.json();
        if (data.threat_intelligence) {
          setActiveTiData(data.threat_intelligence);
        }
      }
    } catch (e) {
      console.error("Failed to fetch live TI report", e);
    }
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
        addToast(`Alert status changed to ${statusVal}`, "success");
      } else {
        addToast('Failed to update status', "error");
      }
    } catch (err) {
      addToast('Error updating status', "error");
    }
  };

  // Refresh Threat Intel Handler
  const handleRefreshTI = async () => {
    if (!selectedAlert) return;
    try {
      addToast("Synchronizing threat intelligence...", "info");
      const res = await fetch(`${apiBase}/alerts/${selectedAlert.id}/enrich`, { headers });
      if (res.ok) {
        const data = await res.json();
        if (data.threat_intelligence) {
          setActiveTiData(data.threat_intelligence);
          addToast("Threat intelligence report synchronized", "success");
          
          // Re-fetch the alert to get the updated DB state
          const alertRes = await fetch(`${apiBase}/alerts/${selectedAlert.id}`, { headers });
          if (alertRes.ok) {
            const alertData = await alertRes.json() as Alert;
            setSelectedAlert(alertData);
          }
          void fetchTimeline(selectedAlert.alert_id);
          void loadDashboardData(false);
        }
      } else {
        addToast('Failed to sync threat intelligence', "error");
      }
    } catch (err) {
      addToast('Error refreshing threat intelligence', "error");
    }
  };


  // Ingest Alert Submit Handler
  const handleIngestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Client-side IPv4 regex validation
    const ipv4Regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipv4Regex.test(ingestForm.source_ip.trim())) {
      addToast("Invalid IP Address format. Provide a valid IPv4 address (e.g. 192.168.1.1)", "error");
      return;
    }

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
        addToast("Alert ingested and enriched successfully", "success");
      } else {
        const txt = await res.text();
        addToast('Validation error during alert ingestion: ' + txt, "error");
      }
    } catch (err) {
      addToast('Network error in alert creation', "error");
    }
  };

  // Authenticate (Login / Register) Submit Handler
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const url = authType === 'login' ? `${apiBase}/auth/login` : `${apiBase}/auth/register`;
      const payload = authType === 'login' 
        ? { username: authForm.username, password: authForm.password }
        : { 
            username: authForm.username, 
            email: authForm.email || `${authForm.username}@soar.local`,
            password: authForm.password, 
            role: authForm.role 
          };

      const reqHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) {
        reqHeaders['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch(url, {
        method: 'POST',
        headers: reqHeaders,
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errText = await res.text();
        addToast(`Authentication failed: ${errText}`, "error");
        return;
      }

      if (authType === 'login') {
        const data = await res.json() as { access_token: string };
        localStorage.setItem('soar_jwt_token', data.access_token);
        setToken(data.access_token);
        setShowAuthModal(false);
        addToast(`Successfully logged in as ${authForm.username}`, "success");
      } else {
        addToast('Account registered! You can now log in.', "success");
        setAuthType('login');
      }
    } catch (err) {
      addToast('Authentication error', "error");
    }
  };

  // Log Out Handler
  const handleLogout = () => {
    localStorage.removeItem('soar_jwt_token');
    setToken(null);
    setUserProfile(null);
    addToast("Logged out successfully", "info");
  };

  const handleCopyIp = (ip: string) => {
    navigator.clipboard.writeText(ip).then(() => {
      setCopiedIp(true);
      setTimeout(() => setCopiedIp(false), 1800);
      addToast(`Copied ${ip} to clipboard`, 'info');
    });
  };

  const riskColor = (score: number) =>
    score >= 76 ? 'var(--danger)' : score >= 51 ? 'var(--accent-2)' : score >= 26 ? 'var(--warning)' : 'var(--good)';

  // Playbook execution handler
  const handleExecutePlaybook = async () => {
    if (!selectedAlert || !selectedPlaybook) return;
    setPlaybookRunning(true);
    setPlaybookMessage(null);
    try {
      addToast(`Triggering playbook ${selectedPlaybook}...`, "info");
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
        addToast(`Playbook ${data.playbook_name} executed successfully!`, "success");
      } else {
        const txt = await res.text();
        setPlaybookMessage(`Error: ${txt}`);
        addToast(`Playbook execution failed: ${txt}`, "error");
      }
    } catch (err) {
      setPlaybookMessage('Connection error executing playbook');
      addToast('Connection error executing playbook', "error");
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
    if (!risk || !risk.buckets || risk.buckets.length === 0) return null;
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
            <h1>🛡️ CyberPulse SOAR</h1>
            <div className="live-indicator">
              <span className={`pulse-dot ${isPulsing ? 'syncing' : ''}`} />
              <span className="live-label">{loading ? 'Syncing...' : 'Live'}</span>
            </div>
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
                className={`tab-btn ${activeTab === 'analytics' ? 'active' : ''}`}
                onClick={() => setActiveTab('analytics')}
              >
                Analytics
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
            {/* Search & Filter Bar */}
            <section className="filter-bar">
              <div className="search-wrap">
                <span className="search-icon">🔍</span>
                <input
                  ref={searchRef}
                  type="text"
                  className="search-input"
                  placeholder="Search alerts by type, IP, or ID… (Ctrl+K)"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                {searchQuery && (
                  <button className="search-clear" onClick={() => setSearchQuery('')}>×</button>
                )}
              </div>
              <div className="filter-chips">
                {(['All', 'Low', 'Medium', 'High', 'Critical'] as const).map((s) => (
                  <button
                    key={s}
                    className={`filter-chip ${filterSeverity === s ? 'active severity-' + s.toLowerCase() : ''}`}
                    onClick={() => setFilterSeverity(s)}
                  >
                    {s}
                  </button>
                ))}
              </div>
              <div className="filter-chips">
                {(['All', 'Open', 'Investigating', 'Resolved'] as const).map((s) => (
                  <button
                    key={s}
                    className={`filter-chip ${filterStatus === s ? 'active' : ''}`}
                    onClick={() => setFilterStatus(s)}
                  >
                    {s}
                  </button>
                ))}
              </div>
              {(searchQuery || filterSeverity !== 'All' || filterStatus !== 'All') && (
                <button className="btn btn-secondary btn-sm" onClick={() => { setSearchQuery(''); setFilterSeverity('All'); setFilterStatus('All'); }}>
                  Clear Filters
                </button>
              )}
            </section>

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
            <section className="metrics-grid metrics-grid-5">
              <article className="metric-card">
                <span className="metric-label">Total Alerts</span>
                <strong className="metric-value">{summary?.total_alerts ?? 0}</strong>
                <span className="metric-tone">Environment</span>
              </article>
              <article className="metric-card metric-open">
                <span className="metric-label">Open</span>
                <strong className="metric-value">{summary?.open_alerts ?? 0}</strong>
                <span className="metric-tone">Triage Queue</span>
              </article>
              <article className="metric-card metric-investigating">
                <span className="metric-label">Investigating</span>
                <strong className="metric-value">{summary?.investigating_alerts ?? 0}</strong>
                <span className="metric-tone">In Progress</span>
              </article>
              <article className="metric-card metric-resolved">
                <span className="metric-label">Resolved</span>
                <strong className="metric-value">{summary?.resolved_alerts ?? 0}</strong>
                <span className="metric-tone">Mitigated</span>
              </article>
              <article className="metric-card metric-critical">
                <span className="metric-label">Critical</span>
                <strong className="metric-value">{summary?.critical_alerts ?? 0}</strong>
                <span className="metric-tone">Pending Action</span>
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
                  {(!risk?.buckets || risk.buckets.length === 0) ? <p className="empty-state">No risk data returned yet.</p> : null}
                </div>
              </article>

              {/* Alert Ingestion Table */}
              <article className="panel alerts-panel">
                <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <p className="section-label">Incident triage feed</p>
                    <h2>Latest activities</h2>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <div className="sort-control">
                      <span>Sort:</span>
                      <select value={sortBy} onChange={(e) => setSortBy(e.target.value as typeof sortBy)}>
                        <option value="time">Latest</option>
                        <option value="risk">Risk Score</option>
                        <option value="severity">Severity</option>
                      </select>
                    </div>
                    <button 
                      className="btn btn-secondary btn-sm" 
                      onClick={(e) => {
                        e.stopPropagation();
                        downloadCSV(`${apiBase}/alerts/export/csv`, 'soar_alerts_report.csv');
                      }}
                      title="Download full CSV report"
                    >
                      📥 Export CSV
                    </button>
                    <span className="panel-chip">
                      {filteredAlerts.length !== (alerts?.count ?? 0)
                        ? `${filteredAlerts.length} / ${alerts?.count ?? 0}`
                        : `${alerts?.count ?? 0} alerts`}
                    </span>
                  </div>
                </div>
                <div className="alerts-table">
                  {filteredAlerts.length === 0 && !loading && (
                    <p className="empty-state">No alerts match the current filters.</p>
                  )}
                  {loading && (alerts?.alerts.length ?? 0) === 0 && (
                    <>
                      <div className="skeleton-row" />
                      <div className="skeleton-row" style={{ opacity: 0.7 }} />
                      <div className="skeleton-row" style={{ opacity: 0.4 }} />
                    </>
                  )}
                  {filteredAlerts.map((alert) => (
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
                      <div className="alert-risk-col">
                        <strong style={{ color: riskColor(alert.risk_score) }}>{alert.risk_score.toFixed(1)}</strong>
                        <div className="risk-mini-bar-track">
                          <div
                            className="risk-mini-bar-fill"
                            style={{
                              width: `${alert.risk_score}%`,
                              background: riskColor(alert.risk_score),
                            }}
                          />
                        </div>
                        <p style={{ fontSize: '0.72rem' }}>{alert.threat_verdict ?? 'Unknown'}</p>
                      </div>
                    </div>
                  ))}
                  {!loading && (alerts?.alerts.length ?? 0) === 0 ? <p className="empty-state">No alerts in database. Ingest one above!</p> : null}
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

                <p className="section-label" style={{ marginTop: '18px', marginBottom: '8px' }}>System integration checklist</p>
                <div className="integration-list">
                  <div className="integration-item">
                    <span className="dot-indicator connected" />
                    <span>SQLite DB: Connected</span>
                  </div>
                  <div className="integration-item">
                    <span className={`dot-indicator ${tiDiagnostics?.abuseipdb?.status === 'live' ? 'live' : 'mock'}`} />
                    <span>AbuseIPDB: {tiDiagnostics?.abuseipdb?.status === 'live' ? 'Live' : 'Mock'}</span>
                  </div>
                  <div className="integration-item">
                    <span className={`dot-indicator ${tiDiagnostics?.virustotal?.status === 'live' ? 'live' : 'mock'}`} />
                    <span>VirusTotal: {tiDiagnostics?.virustotal?.status === 'live' ? 'Live' : 'Mock'}</span>
                  </div>
                  <div className="integration-item">
                    <span className={`dot-indicator ${tiDiagnostics?.ipinfo?.status === 'live' ? 'live' : 'mock'}`} />
                    <span>IPInfo: {tiDiagnostics?.ipinfo?.status === 'live' ? 'Live' : 'Mock'}</span>
                  </div>
                  <div className="integration-item">
                    <span className="dot-indicator live" />
                    <span>Playbooks: Active</span>
                  </div>
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
        ) : activeTab === 'analytics' ? (
          /* Analytics tab */
          <section className="analytics-grid">
            <div className="panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">Severity breakdown</p>
                  <h2>Alert distribution by severity</h2>
                </div>
              </div>
              <div className="bars">
                {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
                  const count = summary?.[`${sev}_alerts` as keyof DashboardSummary] as number ?? 0;
                  const total = summary?.total_alerts || 1;
                  const pct = (count / total) * 100;
                  return (
                    <div className="bar-row" key={sev}>
                      <div className="bar-meta">
                        <span className="bar-label" style={{ textTransform: 'capitalize' }}>{sev}</span>
                      </div>
                      <div className="bar-track">
                        <div className={`bar-fill bar-${sev}`} style={{ width: `${Math.max(pct, count > 0 ? 4 : 0)}%` }} />
                      </div>
                      <div className="bar-values">
                        <strong>{count}</strong>
                        <span>{pct.toFixed(1)}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">Threat posture</p>
                  <h2>Key risk indicators</h2>
                </div>
              </div>
              <div className="kri-grid">
                <div className="kri-card">
                  <span className="kri-label">Avg Risk Score</span>
                  <strong className="kri-value" style={{ color: (summary?.avg_risk_score ?? 0) > 60 ? 'var(--danger)' : 'var(--good)' }}>
                    {summary?.avg_risk_score?.toFixed(1) ?? '—'}
                  </strong>
                  <span className="kri-sub">out of 100</span>
                </div>
                <div className="kri-card">
                  <span className="kri-label">Malicious IPs</span>
                  <strong className="kri-value" style={{ color: 'var(--danger)' }}>{summary?.malicious_ips ?? 0}</strong>
                  <span className="kri-sub">TI confirmed</span>
                </div>
                <div className="kri-card">
                  <span className="kri-label">Suspicious IPs</span>
                  <strong className="kri-value" style={{ color: 'var(--warning)' }}>{summary?.suspicious_ips ?? 0}</strong>
                  <span className="kri-sub">Under review</span>
                </div>
                <div className="kri-card">
                  <span className="kri-label">Blocked IPs</span>
                  <strong className="kri-value" style={{ color: 'var(--accent)' }}>{summary?.blocked_ips ?? 0}</strong>
                  <span className="kri-sub">Firewall enforced</span>
                </div>
                <div className="kri-card">
                  <span className="kri-label">High Severity</span>
                  <strong className="kri-value" style={{ color: 'var(--accent-2)' }}>{summary?.high_alerts ?? 0}</strong>
                  <span className="kri-sub">Needs triage</span>
                </div>
                <div className="kri-card">
                  <span className="kri-label">Resolution Rate</span>
                  <strong className="kri-value" style={{ color: 'var(--good)' }}>
                    {summary?.total_alerts ? ((summary.resolved_alerts / summary.total_alerts) * 100).toFixed(1) + '%' : '—'}
                  </strong>
                  <span className="kri-sub">of total alerts</span>
                </div>
              </div>
            </div>

            <div className="panel" style={{ gridColumn: '1 / -1' }}>
              <div className="panel-header">
                <div>
                  <p className="section-label">Risk score distribution</p>
                  <h2>Weighted score bands</h2>
                </div>
                {strongestBucket && <span className="panel-chip">Peak band: {strongestBucket.label}</span>}
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
              </div>
            </div>
          </section>
        ) : (
          /* Playbook history tab view */
          <section className="panel">
            <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <p className="section-label">Audit Logs</p>
                <h2>Playbook execution history</h2>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button 
                  className="btn btn-secondary btn-sm" 
                  onClick={() => downloadCSV(`${apiBase}/playbooks/export/csv`, 'soar_playbook_history.csv')}
                  title="Export playbook logs to CSV"
                >
                  📥 Export Logs CSV
                </button>
                <button className="btn btn-secondary btn-sm" onClick={loadExecutionsHistory}>
                  🔄 Refresh Logs
                </button>
              </div>
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
                <div className="drawer-nav">
                  <span>Alerts</span> › <span>{selectedAlert.alert_id}</span>
                </div>
                <h2>{selectedAlert.alert_type}</h2>
                <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                  <span className={`badge badge-${selectedAlert.severity.toLowerCase()}`}>{selectedAlert.severity}</span>
                  <span className={`badge badge-status badge-${selectedAlert.status.toLowerCase()}`}>{selectedAlert.status}</span>
                </div>
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
                    <strong>
                      {selectedAlert.source_ip}
                      <button className="copy-btn" onClick={() => handleCopyIp(selectedAlert.source_ip)}>
                        {copiedIp ? '✓ Copied' : 'Copy'}
                      </button>
                    </strong>
                  </div>
                  <div className="info-item">
                    <span>Risk Score</span>
                    <div className="threat-meter">
                      <strong style={{ color: riskColor(selectedAlert.risk_score) }}>
                        {selectedAlert.risk_score.toFixed(1)} / 100
                      </strong>
                      <div className="threat-meter-track">
                        <div
                          className="threat-meter-fill"
                          style={{
                            width: `${selectedAlert.risk_score}%`,
                            background: `linear-gradient(90deg, ${riskColor(selectedAlert.risk_score)}, ${riskColor(selectedAlert.risk_score)}88)`,
                          }}
                        />
                      </div>
                      <div className="threat-meter-labels"><span>0</span><span>50</span><span>100</span></div>
                    </div>
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
                <div className="drawer-timestamp">
                  <span>🕐 Created: <strong>{new Date(selectedAlert.created_at).toLocaleString()}</strong></span>
                  <span>🔄 Updated: <strong>{new Date(selectedAlert.updated_at).toLocaleString()}</strong></span>
                </div>
              </section>

              {/* Threat Intelligence Explorer */}
              <section className="drawer-section">
                <span className="drawer-section-title">Threat Intelligence Explorer</span>
                {activeTiData ? (
                  <>
                    <div className="ti-tabs">
                      <button 
                        type="button"
                        className={`ti-tab-btn ${tiTab === 'abuseipdb' ? 'active' : ''}`}
                        onClick={() => setTiTab('abuseipdb')}
                      >
                        AbuseIPDB
                      </button>
                      <button 
                        type="button"
                        className={`ti-tab-btn ${tiTab === 'virustotal' ? 'active' : ''}`}
                        onClick={() => setTiTab('virustotal')}
                      >
                        VirusTotal
                      </button>
                      <button 
                        type="button"
                        className={`ti-tab-btn ${tiTab === 'ipinfo' ? 'active' : ''}`}
                        onClick={() => setTiTab('ipinfo')}
                      >
                        IPInfo (Geo)
                      </button>
                    </div>

                    {tiTab === 'abuseipdb' && (
                      <div className="ti-content-card">
                        <div className="ti-grid-info">
                          <div className="ti-badge-pill">
                            <span>Confidence Score</span>
                            <strong style={{ color: activeTiData.abuseipdb?.abuse_confidence_score > 50 ? 'var(--danger)' : 'var(--good)' }}>
                              {activeTiData.abuseipdb?.abuse_confidence_score}%
                            </strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>Total Reports</span>
                            <strong>{activeTiData.abuseipdb?.total_reports}</strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>ISP / Carrier</span>
                            <strong style={{ fontSize: '0.8rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {activeTiData.abuseipdb?.isp || 'Unknown'}
                            </strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>Country</span>
                            <strong>{activeTiData.abuseipdb?.country_code || 'Unknown'}</strong>
                          </div>
                        </div>
                        <div style={{ marginTop: '10px', fontSize: '0.75rem', color: 'var(--muted)', textAlign: 'right' }}>
                          Source: {activeTiData.abuseipdb?.source || 'Mock'}
                        </div>
                      </div>
                    )}

                    {tiTab === 'virustotal' && (
                      <div className="ti-content-card">
                        <div className="ti-grid-info">
                          <div className="ti-badge-pill">
                            <span>Flagged Engines</span>
                            <strong style={{ color: activeTiData.virustotal?.malicious_count > 0 ? 'var(--danger)' : 'var(--good)' }}>
                              {activeTiData.virustotal?.malicious_count} / {activeTiData.virustotal?.total_engines || 90}
                            </strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>Reputation</span>
                            <strong style={{ color: activeTiData.virustotal?.reputation < 0 ? 'var(--danger)' : 'var(--good)' }}>
                              {activeTiData.virustotal?.reputation}
                            </strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>AS Owner</span>
                            <strong style={{ fontSize: '0.8rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {activeTiData.virustotal?.as_owner || 'Unknown'}
                            </strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>Regional Registry</span>
                            <strong>{activeTiData.virustotal?.regional_internet_registry || 'Unknown'}</strong>
                          </div>
                        </div>
                        {activeTiData.virustotal?.tags && activeTiData.virustotal.tags.length > 0 && (
                          <div style={{ marginTop: '12px' }}>
                            <span style={{ fontSize: '0.72rem', color: 'var(--muted)', textTransform: 'uppercase' }}>Analysis Tags</span>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                              {activeTiData.virustotal.tags.map((t: string) => (
                                <span key={t} className="badge" style={{ padding: '2px 8px', fontSize: '0.75rem' }}>{t}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        <div style={{ marginTop: '10px', fontSize: '0.75rem', color: 'var(--muted)', textAlign: 'right' }}>
                          Source: {activeTiData.virustotal?.source || 'Mock'}
                        </div>
                      </div>
                    )}

                    {tiTab === 'ipinfo' && (
                      <div className="ti-content-card">
                        <div className="ti-grid-info">
                          <div className="ti-badge-pill">
                            <span>City, Region</span>
                            <strong>{activeTiData.ipinfo?.city || 'Unknown'}, {activeTiData.ipinfo?.region}</strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>Country</span>
                            <strong>{activeTiData.ipinfo?.country || 'Unknown'}</strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>Organization</span>
                            <strong style={{ fontSize: '0.8rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {activeTiData.ipinfo?.org || 'Unknown'}
                            </strong>
                          </div>
                          <div className="ti-badge-pill">
                            <span>Timezone</span>
                            <strong>{activeTiData.ipinfo?.timezone || 'Unknown'}</strong>
                          </div>
                        </div>
                        <div style={{ marginTop: '10px', fontSize: '0.75rem', color: 'var(--muted)', textAlign: 'right' }}>
                          Source: {activeTiData.ipinfo?.source || 'Mock'}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="empty-state">Ingesting threat intelligence reports...</p>
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
                      {playbookRunning ? <><span className="spinner" /> Running...</> : '🚀 Run Playbook'}
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
                  pattern="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                  title="Please enter a valid IPv4 address (e.g. 192.168.1.1)"
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

              {authType === 'register' && (
                <div className="form-group">
                  <label>Email Address</label>
                  <input 
                    type="email" 
                    className="input-field" 
                    required
                    placeholder="Enter email address..."
                    value={authForm.email}
                    onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })}
                  />
                </div>
              )}

              <div className="form-group">
                <label>Password</label>
                <input 
                  type="password" 
                  className="input-field" 
                  required
                  minLength={8}
                  placeholder="Enter secure password (min 8 characters)..."
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


      <div className="toast-container">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            <span>{t.message}</span>
            <button 
              type="button" 
              className="toast-close" 
              onClick={() => setToasts((prev) => prev.filter((toast) => toast.id !== t.id))}
            >
              &times;
            </button>
          </div>
        ))}
      </div>
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
