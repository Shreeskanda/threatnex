import { useState } from 'react';
import { Brain, ShieldAlert, CheckCircle2, AlertCircle, Key, ExternalLink, Search } from 'lucide-react';
import { scanUrl } from '../services/api';
import type { ScanResult } from '../types';
import ScanResultView from '../components/ScanResultView';
import ScanProgress from '../components/ScanProgress';
import toast from 'react-hot-toast';

export default function ThreatIntelligence() {
  const [lookupTarget, setLookupTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupTarget.trim()) {
      toast.error('Please enter a domain or URL');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const res = await scanUrl(lookupTarget.trim());
      setResult(res.data);
      toast.success('Threat intelligence inquiry complete');
    } catch (err: any) {
      toast.error('Query failed. Ensure URL is valid.');
    } finally {
      setLoading(false);
    }
  };

  const threatFeeds = [
    {
      name: 'Google Safe Browsing v4',
      provider: 'Google Security',
      status: 'Ready (Local Fallback + API Support)',
      desc: 'Identifies dangerous web resources and known malware or phishing URLs across the global web.'
    },
    {
      name: 'VirusTotal API v3',
      provider: 'Chronicle / Google Cloud',
      status: 'Ready (Multi-Engine Aggregation)',
      desc: 'Aggregates threat intelligence from over 70 commercial antivirus scanners and URL blocklists.'
    },
    {
      name: 'URLhaus Threat Intel',
      provider: 'abuse.ch',
      status: 'Ready (Community Blacklist)',
      desc: 'Tracks and shares malicious URLs used for malware distribution and command-and-control operations.'
    },
    {
      name: 'PhishTank Feed',
      provider: 'Cisco OpenDNS',
      status: 'Ready (Collaborative Phishing Clearinghouse)',
      desc: 'Community-verified repository of live phishing links and credential-harvesting endpoints.'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="card border-l-4 border-l-blue-600">
        <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <Brain className="w-5 h-5 text-blue-600" />
          Threat Intelligence Feeds & Reputation Lookup
        </h1>
        <p className="text-sm text-gray-600 mt-1">
          THREATNEX operates a hybrid threat intelligence architecture. Local rule-based, heuristic,
          and behavioral engines function autonomously, supplemented by optional commercial feeds.
        </p>

        {/* Query Input */}
        <form onSubmit={handleLookup} className="mt-5 flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <label htmlFor="threat-intel-query" className="sr-only">Query reputation for domain or URL</label>
            <Search className="absolute left-3.5 top-3 w-4 h-4 text-gray-400" />
            <input
              id="threat-intel-query"
              name="query"
              type="text"
              value={lookupTarget}
              onChange={(e) => setLookupTarget(e.target.value)}
              placeholder="Query reputation for domain or URL (e.g. secure-login-bank.xyz)"
              aria-label="Query reputation for domain or URL"
              className="w-full pl-10 pr-4 py-2.5 bg-gray-50 border border-gray-300 rounded-lg text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            aria-label="Lookup threat intelligence reputation"
            className="btn-primary"
          >
            {loading ? 'Searching...' : 'Lookup Reputation'}
          </button>
        </form>
      </div>

      {/* Intelligence Provider Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {threatFeeds.map((feed) => (
          <div key={feed.name} className="card flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-700">
                  {feed.provider}
                </span>
                <span className="flex items-center gap-1 text-xs text-green-700 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" /> {feed.status}
                </span>
              </div>
              <h2 className="text-base font-bold text-gray-900 mt-2">{feed.name}</h2>
              <p className="text-xs text-gray-600 mt-1 leading-relaxed">{feed.desc}</p>
            </div>
            <div className="mt-4 pt-3 border-t border-gray-100 flex items-center justify-between text-xs text-gray-500">
              <span className="flex items-center gap-1">
                <Key className="w-3 h-3" /> Configurable via .env
              </span>
              <span className="italic">Local fallback active</span>
            </div>
          </div>
        ))}
      </div>

      {loading && <ScanProgress step="Querying threat intelligence databases and cross-referencing indicators..." />}

      {result && <ScanResultView result={result} />}
    </div>
  );
}
