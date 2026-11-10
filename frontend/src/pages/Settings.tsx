import { useState } from 'react';
import {
  Settings as SettingsIcon, Shield, Database, Key, Server,
  Trash2, AlertTriangle, CheckCircle2, RefreshCw
} from 'lucide-react';
import toast from 'react-hot-toast';
import axios from 'axios';

export default function Settings() {
  const [clearing, setClearing] = useState(false);

  const handleClearHistory = async () => {
    if (!window.confirm('Are you sure you want to delete all historical scan records from the database? This action cannot be undone.')) {
      return;
    }

    setClearing(true);
    try {
      await axios.delete('/api/history');
      toast.success('All scan records have been cleared from database');
    } catch (err) {
      toast.error('Failed to clear scan records');
    } finally {
      setClearing(false);
    }
  };

  const integrations = [
    {
      name: 'Google Safe Browsing API v4',
      envKey: 'GOOGLE_SAFE_BROWSING_API_KEY',
      status: 'Supported (Optional)',
      description: 'Global URL blacklists and malicious domain detection.'
    },
    {
      name: 'VirusTotal API v3',
      envKey: 'VIRUSTOTAL_API_KEY',
      status: 'Supported (Optional)',
      description: 'Aggregated scans from 70+ commercial antivirus engines.'
    },
    {
      name: 'URLhaus API',
      envKey: 'URLHAUS_API_KEY',
      status: 'Supported (Optional)',
      description: 'Active malware hosting URL feed operated by abuse.ch.'
    },
    {
      name: 'PhishTank API',
      envKey: 'PHISHTANK_API_KEY',
      status: 'Supported (Optional)',
      description: 'Community-verified live phishing website directory.'
    }
  ];

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Title */}
      <div className="card border-l-4 border-l-blue-600">
        <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-blue-600" />
          System Configuration & Threat Engine Settings
        </h1>
        <p className="text-sm text-gray-600 mt-1">
          Review operational parameters, external threat intelligence feeds, database storage, and security sandboxing safeguards.
        </p>
      </div>

      {/* Engine Status Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="card">
          <span className="text-xs font-semibold text-gray-500 uppercase">Detection Engine</span>
          <div className="text-lg font-bold text-gray-900 mt-1">ThreatNex Core</div>
          <p className="text-xs text-green-700 font-medium mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> v1.0.0 Active (Local Heuristics)
          </p>
        </div>
        <div className="card">
          <span className="text-xs font-semibold text-gray-500 uppercase">Database Storage</span>
          <div className="text-lg font-bold text-gray-900 mt-1">SQLite / PostgreSQL</div>
          <p className="text-xs text-blue-700 font-medium mt-1">
            SQLAlchemy ORM (Persistent)
          </p>
        </div>
        <div className="card">
          <span className="text-xs font-semibold text-gray-500 uppercase">SSRF Protection</span>
          <div className="text-lg font-bold text-gray-900 mt-1">Active Containment</div>
          <p className="text-xs text-green-700 font-medium mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> Private IP & Cloud Metadata Blocked
          </p>
        </div>
      </div>

      {/* API Integrations */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between border-b border-gray-100 pb-3">
          <div>
            <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
              <Key className="w-4 h-4 text-blue-600" />
              External Threat Intelligence Integrations
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Configured via environment variables in <code className="bg-gray-100 px-1 py-0.5 rounded text-gray-800">backend/.env</code>.
              Never exposed to client browsers.
            </p>
          </div>
        </div>

        <div className="divide-y divide-gray-100">
          {integrations.map((item) => (
            <div key={item.name} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="text-sm font-semibold text-gray-900">{item.name}</div>
                <div className="text-xs text-gray-500">{item.description}</div>
                <div className="text-[11px] font-mono text-gray-400 mt-0.5">ENV: {item.envKey}</div>
              </div>
              <span className="self-start sm:self-auto text-xs px-2.5 py-1 rounded bg-gray-100 text-gray-700 font-medium">
                {item.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Sandboxing & Processing Limits */}
      <div className="card space-y-3">
        <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-600" />
          Security Policy & Processing Boundaries
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs text-gray-700">
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="font-bold text-gray-900 block">Maximum File Upload Size:</span>
            <span>15 MB per single file payload (enforced via streaming validator)</span>
          </div>
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="font-bold text-gray-900 block">Execution Sandbox Rule:</span>
            <span>Zero-execution policy — macro, script, and binaries are inspected statically</span>
          </div>
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="font-bold text-gray-900 block">Archive Inspection Depth:</span>
            <span>Maximum 100 entries parsed with directory traversal & zip-bomb ratio checks</span>
          </div>
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="font-bold text-gray-900 block">Network Request Timeout:</span>
            <span>15-second strict timeout for external URL inspection with max 5 redirects</span>
          </div>
        </div>
      </div>

      {/* Database Maintenance */}
      <div className="card border-red-200 bg-red-50/20 space-y-4">
        <div className="flex items-center gap-2 text-red-900 font-bold">
          <AlertTriangle className="w-5 h-5 text-red-600" />
          Database Maintenance & Privacy Clearing
        </div>
        <p className="text-xs text-gray-700 leading-relaxed">
          Clear all stored scan records, extracted URLs, and technical evidence logs from the local database.
          This resets dashboard metrics and empties scan history.
        </p>

        <div>
          <button
            onClick={handleClearHistory}
            disabled={clearing}
            className="btn-danger flex items-center gap-2 text-xs"
          >
            <Trash2 className="w-4 h-4" />
            <span>{clearing ? 'Clearing Records...' : 'Clear All Scan History'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
