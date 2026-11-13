import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, AlertTriangle, CheckCircle, TrendingUp, Search,
  ArrowRight, Loader2, ExternalLink
} from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend
} from 'recharts';
import { getDashboardStats, scanUrl } from '../services/api';
import type { DashboardStats } from '../types';
import { getThreatLevelColor, formatDate, truncate } from '../utils';
import toast from 'react-hot-toast';
import clsx from 'clsx';

const PIE_COLORS = ['#16a34a', '#2563eb', '#d97706', '#ea580c', '#dc2626'];
const BAR_COLORS: Record<string, string> = {
  'SAFE-LOOKING': '#16a34a',
  'LOW RISK': '#2563eb',
  'MODERATE RISK': '#d97706',
  'HIGH RISK': '#ea580c',
  'CRITICAL RISK': '#dc2626',
};

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [quickUrl, setQuickUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    setLoading(true);
    getDashboardStats()
      .then(r => setStats(r.data))
      .catch(() => setError('Failed to load dashboard stats. Is the backend running?'))
      .finally(() => setLoading(false));
  }, []);

  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    setScanning(true);
    try {
      const res = await scanUrl(quickUrl.trim());
      navigate(`/history`, { state: { highlight: res.data.scan_id } });
      toast.success('Scan complete!');
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  if (loading && !stats) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <Loader2 className="w-8 h-8 text-blue-600 animate-spin" />
        <p className="text-gray-500">Loading dashboard...</p>
      </div>
    );
  }

  // Graceful fallback if stats is null
  const currentStats = stats || {
    total_scans: 0,
    safe_count: 0,
    suspicious_count: 0,
    critical_count: 0,
    threat_distribution: [{ name: 'URL', value: 0 }, { name: 'FILE', value: 0 }, { name: 'IMAGE', value: 0 }, { name: 'TEXT', value: 0 }],
    recent_scans: [],
    risk_level_distribution: [{ level: 'SAFE-LOOKING', count: 0 }, { level: 'LOW RISK', count: 0 }, { level: 'MODERATE RISK', count: 0 }, { level: 'HIGH RISK', count: 0 }, { level: 'CRITICAL RISK', count: 0 }],
    most_common_threats: []
  };

  return (
    <div className="space-y-6">
      {/* Welcome */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Welcome to THREATNEX</h1>
          <p className="text-gray-500 text-sm mt-1">AI-powered cybersecurity threat detection platform</p>
        </div>
        <button onClick={() => navigate('/scan')} className="btn-primary flex items-center gap-2 self-start sm:self-auto">
          <Search className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Scans', value: currentStats.total_scans, icon: Shield, color: 'blue', bg: 'bg-blue-50', border: 'border-blue-100' },
          { label: 'Safe', value: currentStats.safe_count, icon: CheckCircle, color: 'green', bg: 'bg-green-50', border: 'border-green-100' },
          { label: 'Suspicious', value: currentStats.suspicious_count, icon: AlertTriangle, color: 'amber', bg: 'bg-amber-50', border: 'border-amber-100' },
          { label: 'Critical', value: currentStats.critical_count, icon: TrendingUp, color: 'red', bg: 'bg-red-50', border: 'border-red-100' },
        ].map(card => (
          <div key={card.label} className={clsx('card border', card.border, card.bg)}>
            <div className="flex items-start justify-between">
              <div>
                <div className="text-3xl font-bold text-gray-900">{card.value}</div>
                <div className="text-sm text-gray-600 mt-1">{card.label}</div>
              </div>
              <div className={clsx('p-2.5 rounded-lg', card.bg)}>
                <card.icon className={`w-5 h-5 text-${card.color}-600`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Quick URL scan */}
      <div className="card border-blue-200 bg-blue-50">
        <h2 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
          <Search className="w-4 h-4 text-blue-600" />
          Quick URL Scan
        </h2>
        <form onSubmit={handleQuickScan} className="flex gap-3">
          <label htmlFor="quick-url-input" className="sr-only">Website URL to scan</label>
          <input
            id="quick-url-input"
            name="quickUrl"
            type="url"
            value={quickUrl}
            onChange={e => setQuickUrl(e.target.value)}
            placeholder="https://example.com"
            aria-label="Website URL to scan"
            className="flex-1 border border-blue-200 bg-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={scanning}
          />
          <button
            type="submit"
            disabled={scanning || !quickUrl.trim()}
            aria-label="Start quick threat scan"
            className="btn-primary flex items-center gap-2 whitespace-nowrap"
          >
            {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </form>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Threat distribution pie */}
        <div className="card">
          <h2 className="font-semibold text-gray-900 mb-4">Threat Distribution</h2>
          {currentStats.threat_distribution && currentStats.threat_distribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={currentStats.threat_distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                  nameKey="name"
                >
                  {currentStats.threat_distribution.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip formatter={(v: any) => [v, 'Scans']} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-60 flex items-center justify-center text-gray-400 text-sm">No scan data yet</div>
          )}
        </div>

        {/* Risk level bar chart */}
        <div className="card">
          <h2 className="font-semibold text-gray-900 mb-4">Risk Level Distribution</h2>
          {currentStats.risk_level_distribution && currentStats.risk_level_distribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={currentStats.risk_level_distribution} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <XAxis dataKey="level" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {currentStats.risk_level_distribution.map((entry, i) => (
                    <Cell key={i} fill={BAR_COLORS[entry.level] || '#6b7280'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-60 flex items-center justify-center text-gray-400 text-sm">No data yet</div>
          )}
        </div>
      </div>

      {/* Bottom row: recent scans + top threats */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent scans */}
        <div className="card lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-gray-900">Recent Scans</h2>
            <button onClick={() => navigate('/history')} className="text-xs text-blue-600 hover:underline flex items-center gap-1">
              View all <ExternalLink className="w-3 h-3" />
            </button>
          </div>
          {currentStats.recent_scans.length === 0 ? (
            <div className="text-center py-8 text-gray-400 text-sm">No scans yet. Run your first scan!</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs text-gray-500 border-b border-gray-100">
                    <th className="text-left pb-2 font-medium">Target</th>
                    <th className="text-left pb-2 font-medium">Type</th>
                    <th className="text-left pb-2 font-medium">Threat Level</th>
                    <th className="text-right pb-2 font-medium">Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {currentStats.recent_scans.map(scan => (
                    <tr
                      key={scan.scan_id}
                      className="hover:bg-gray-50 cursor-pointer"
                      onClick={() => navigate(`/reports?scan=${scan.scan_id}`)}
                    >
                      <td className="py-2.5 pr-4 font-mono text-xs text-gray-700 max-w-[180px] truncate">
                        {truncate(scan.input_reference, 40)}
                      </td>
                      <td className="py-2.5 pr-4">
                        <span className="px-2 py-0.5 rounded bg-gray-100 text-gray-600 text-xs capitalize">{scan.scan_type}</span>
                      </td>
                      <td className="py-2.5 pr-4">
                        <span className={clsx('px-2 py-0.5 rounded text-xs font-medium border', getThreatLevelColor(scan.threat_level))}>
                          {scan.threat_level}
                        </span>
                      </td>
                      <td className="py-2.5 text-right font-bold text-gray-900">{scan.risk_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Most common threats */}
        <div className="card">
          <h2 className="font-semibold text-gray-900 mb-4">Top Threat Categories</h2>
          {currentStats.most_common_threats.length === 0 ? (
            <div className="text-center py-8 text-gray-400 text-sm">No threat data yet</div>
          ) : (
            <div className="space-y-3">
              {currentStats.most_common_threats.slice(0, 8).map((t, i) => (
                <div key={t.category} className="flex items-center gap-3">
                  <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs font-bold flex items-center justify-center flex-shrink-0">
                    {i + 1}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium text-gray-700 truncate">{t.category}</div>
                    <div className="mt-1 h-1.5 rounded-full bg-gray-100 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-blue-500"
                        style={{ width: `${Math.min(100, (t.count / (currentStats.most_common_threats[0]?.count || 1)) * 100)}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-xs font-semibold text-gray-600 flex-shrink-0">{t.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
