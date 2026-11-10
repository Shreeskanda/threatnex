import { useState } from 'react';
import { Globe, ArrowRight, ShieldCheck, AlertTriangle } from 'lucide-react';
import { scanUrl } from '../services/api';
import type { ScanResult } from '../types';
import ScanResultView from '../components/ScanResultView';
import ScanProgress from '../components/ScanProgress';
import toast from 'react-hot-toast';

export default function WebsiteInspector() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleInspect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim()) {
      toast.error('Please enter a website URL to inspect');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const res = await scanUrl(url.trim());
      setResult(res.data);
      toast.success('Website inspection completed');
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to inspect website. Ensure host is accessible.');
    } finally {
      setLoading(false);
    }
  };

  const sampleTargets = [
    { label: 'Legitimate Portal', url: 'https://www.wikipedia.org' },
    { label: 'Security Test Target', url: 'https://malware.testing.google.test' },
    { label: 'Phishing Keyword Test', url: 'http://sbi-online-banking-kyc-update.xyz/verify' }
  ];

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="card border-l-4 border-l-blue-600">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-600" />
              Website Source-Code & Observable Behavior Inspector
            </h1>
            <p className="text-sm text-gray-600 mt-1">
              Performs deep inspection of frontend DOM, embedded JavaScript scripts, network redirect chains,
              SSL/TLS certificates, security response headers, and SSRF containment.
            </p>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleInspect} className="mt-5 flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-3.5 top-3 w-4 h-4 text-gray-400" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter full website URL (e.g. https://example.com)"
              className="w-full pl-10 pr-4 py-2.5 bg-gray-50 border border-gray-300 rounded-lg text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="btn-primary flex items-center justify-center gap-2 px-6 py-2.5"
          >
            <span>{loading ? 'Inspecting...' : 'Inspect Website'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Test Samples */}
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-gray-500">
          <span className="font-medium text-gray-700">Quick Test Targets:</span>
          {sampleTargets.map((item) => (
            <button
              key={item.label}
              type="button"
              onClick={() => {
                setUrl(item.url);
              }}
              className="px-2.5 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded transition-colors"
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Safety Notice */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3.5 flex items-start gap-3 text-xs text-blue-900">
        <ShieldCheck className="w-4 h-4 text-blue-600 flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold">Security Sandbox Safeguards Active:</span> All outgoing requests are filtered
          against SSRF rules, private IP addresses (RFC 1918) and cloud metadata targets (169.254.x.x). Scan actions are
          strictly non-destructive and do not submit user credentials.
        </div>
      </div>

      {/* Loading state */}
      {loading && <ScanProgress step="Fetching HTML DOM, analyzing JavaScript & evaluating certificates..." />}

      {/* Inspection Results */}
      {result && <ScanResultView result={result} />}
    </div>
  );
}
