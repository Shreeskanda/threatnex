import { useState } from 'react';
import {
  Download, Copy, Check, ChevronDown, ChevronUp,
  Globe, Shield, Server, FileCode, Eye, ExternalLink,
  AlertCircle, CheckCircle, Info, Clock
} from 'lucide-react';
import type { ScanResult } from '../types';
import { getThreatLevelColor, getSeverityColor, formatDate } from '../utils';
import RiskGauge from './RiskGauge';
import FindingCard from './FindingCard';
import { downloadPdfReport } from '../services/api';
import toast from 'react-hot-toast';
import clsx from 'clsx';

interface ScanResultViewProps {
  result: ScanResult;
}

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function CollapsibleSection({ title, icon: Icon, children, defaultOpen = true }: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="card">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between gap-3 text-left"
      >
        <div className="flex items-center gap-2 font-semibold text-gray-900">
          <Icon className="w-4 h-4 text-blue-600" />
          {title}
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
      </button>
      {open && <div className="mt-4">{children}</div>}
    </div>
  );
}

function KVTable({ data }: { data: Record<string, any> }) {
  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (!entries.length) return <p className="text-sm text-gray-500 italic">No data available</p>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k} className="border-b border-gray-100 last:border-0">
              <td className="py-2 pr-4 font-medium text-gray-600 whitespace-nowrap w-40">{k}</td>
              <td className="py-2 text-gray-900 break-all font-mono text-xs">
                {typeof v === 'boolean' ? (v ? 'Yes' : 'No') :
                  typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function ScanResultView({ result }: ScanResultViewProps) {
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const copyFindings = () => {
    const text = result.findings.map(f =>
      `[${f.severity.toUpperCase()}] ${f.title}\n${f.description}\nEvidence: ${f.evidence}`
    ).join('\n\n---\n\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success('Findings copied to clipboard');
  };

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-${result.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('JSON report downloaded');
  };

  const downloadPdf = async () => {
    setDownloading(true);
    try {
      await downloadPdfReport(result.scan_id);
      toast.success('PDF report downloaded');
    } catch {
      toast.error('PDF download failed');
    } finally {
      setDownloading(false);
    }
  };

  const findingsBySeverity = SEVERITY_ORDER.map(sev => ({
    severity: sev,
    items: result.findings.filter(f => f.severity === sev),
  })).filter(g => g.items.length > 0);

  const criticalCount = result.findings.filter(f => f.severity === 'critical').length;
  const highCount = result.findings.filter(f => f.severity === 'high').length;

  return (
    <div className="space-y-4">
      {/* Top summary bar */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-6 items-center md:items-start">
          <RiskGauge score={result.risk_score} threatLevel={result.threat_level} />

          <div className="flex-1 space-y-3">
            <div>
              <h2 className="text-lg font-bold text-gray-900 break-all">{result.input_reference}</h2>
              <div className="flex flex-wrap items-center gap-2 mt-2">
                <span className={clsx('px-2.5 py-1 rounded-full text-xs font-semibold border', getThreatLevelColor(result.threat_level))}>
                  {result.threat_level}
                </span>
                <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-700 border border-gray-200">
                  Confidence: {result.confidence}
                </span>
                <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-purple-50 text-purple-700 border border-purple-200 capitalize">
                  {result.scan_type} scan
                </span>
                <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-gray-50 text-gray-600 border border-gray-200">
                  {formatDate(result.timestamp)}
                </span>
              </div>
            </div>

            {/* Stat row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-gray-50 rounded-lg p-3 border border-gray-100">
                <div className="text-2xl font-bold text-gray-900">{result.findings.length}</div>
                <div className="text-xs text-gray-500">Total Findings</div>
              </div>
              <div className="bg-red-50 rounded-lg p-3 border border-red-100">
                <div className="text-2xl font-bold text-red-700">{criticalCount}</div>
                <div className="text-xs text-red-600">Critical</div>
              </div>
              <div className="bg-orange-50 rounded-lg p-3 border border-orange-100">
                <div className="text-2xl font-bold text-orange-700">{highCount}</div>
                <div className="text-xs text-orange-600">High</div>
              </div>
              <div className="bg-blue-50 rounded-lg p-3 border border-blue-100">
                <div className="text-2xl font-bold text-blue-700">{result.risk_score}</div>
                <div className="text-xs text-blue-600">Risk Score</div>
              </div>
            </div>

            {/* Scan ID & Duration */}
            <div className="text-xs text-gray-400 flex flex-wrap gap-4">
              <span>ID: <span className="font-mono">{result.scan_id}</span></span>
              {result.scan_duration_ms && (
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {(result.scan_duration_ms / 1000).toFixed(1)}s
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-gray-100">
          <button onClick={downloadPdf} disabled={downloading} className="btn-primary flex items-center gap-2 text-xs">
            <Download className="w-3.5 h-3.5" />
            {downloading ? 'Downloading...' : 'Download PDF'}
          </button>
          <button onClick={downloadJson} className="btn-secondary flex items-center gap-2 text-xs">
            <FileCode className="w-3.5 h-3.5" />
            Download JSON
          </button>
          <button onClick={copyFindings} className="btn-secondary flex items-center gap-2 text-xs">
            {copied ? <Check className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied!' : 'Copy Findings'}
          </button>
        </div>
      </div>

      {/* API Status */}
      {result.api_status && Object.keys(result.api_status).length > 0 && (
        <CollapsibleSection title="Security Check Status" icon={Shield} defaultOpen={false}>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {Object.entries(result.api_status).map(([key, status]) => (
              <div key={key} className={clsx('flex items-center gap-2 px-3 py-2 rounded-lg border text-xs', {
                'bg-green-50 border-green-200 text-green-700': status === 'checked' || status === 'ok',
                'bg-red-50 border-red-200 text-red-700': status === 'detected' || status === 'error',
                'bg-gray-50 border-gray-200 text-gray-600': status === 'not_configured' || status === 'unavailable',
                'bg-blue-50 border-blue-200 text-blue-700': status === 'clean',
              })}>
                {status === 'checked' || status === 'ok' || status === 'clean'
                  ? <CheckCircle className="w-3.5 h-3.5 flex-shrink-0" />
                  : status === 'detected' || status === 'error'
                    ? <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                    : <Info className="w-3.5 h-3.5 flex-shrink-0" />
                }
                <span className="font-medium">{key.replace(/_/g, ' ')}</span>
                <span className="ml-auto opacity-70">{status}</span>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Findings */}
      <CollapsibleSection title={`Findings (${result.findings.length})`} icon={AlertCircle}>
        {result.findings.length === 0 ? (
          <div className="flex flex-col items-center py-8 text-gray-500">
            <CheckCircle className="w-10 h-10 text-green-500 mb-2" />
            <p className="font-medium">No threats detected</p>
            <p className="text-sm">This scan returned no security findings.</p>
          </div>
        ) : (
          <div className="space-y-6">
            {findingsBySeverity.map(({ severity, items }) => (
              <div key={severity}>
                <h4 className={clsx('text-xs font-bold uppercase tracking-widest mb-2 flex items-center gap-2',
                  getSeverityColor(severity), 'px-2 py-1 rounded w-fit border'
                )}>
                  {severity} ({items.length})
                </h4>
                <div className="space-y-2">
                  {items.map((f, i) => (
                    <FindingCard key={i} finding={f} index={i} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </CollapsibleSection>

      {/* Domain Info */}
      {result.domain_info && Object.keys(result.domain_info).length > 0 && (
        <CollapsibleSection title="Domain Information" icon={Globe} defaultOpen={false}>
          <KVTable data={result.domain_info} />
        </CollapsibleSection>
      )}

      {/* Security Headers */}
      {result.security_headers && Object.keys(result.security_headers).length > 0 && (
        <CollapsibleSection title="Security Headers" icon={Shield} defaultOpen={false}>
          <KVTable data={result.security_headers} />
        </CollapsibleSection>
      )}

      {/* Network Info */}
      {result.network_info && Object.keys(result.network_info).length > 0 && (
        <CollapsibleSection title="Network Activity" icon={Server} defaultOpen={false}>
          <KVTable data={result.network_info} />
        </CollapsibleSection>
      )}

      {/* File Metadata */}
      {result.file_metadata && Object.keys(result.file_metadata).length > 0 && (
        <CollapsibleSection title="File Metadata" icon={FileCode} defaultOpen={false}>
          <KVTable data={result.file_metadata} />
        </CollapsibleSection>
      )}

      {/* Screenshot */}
      {result.screenshot && (
        <CollapsibleSection title="Screenshot" icon={Eye} defaultOpen={false}>
          <img
            src={`data:image/png;base64,${result.screenshot}`}
            alt="Screenshot"
            className="w-full rounded-lg border border-gray-200 max-h-96 object-contain bg-gray-50"
          />
        </CollapsibleSection>
      )}

      {/* Extracted Text */}
      {result.extracted_text && (
        <CollapsibleSection title="Extracted Text" icon={FileCode} defaultOpen={false}>
          <pre className="text-xs text-gray-700 font-mono bg-gray-50 p-3 rounded-lg border border-gray-200 max-h-64 overflow-y-auto whitespace-pre-wrap break-all">
            {result.extracted_text}
          </pre>
        </CollapsibleSection>
      )}

      {/* Extracted URLs */}
      {result.extracted_urls && result.extracted_urls.length > 0 && (
        <CollapsibleSection title={`Extracted URLs (${result.extracted_urls.length})`} icon={ExternalLink} defaultOpen={false}>
          <div className="space-y-1 max-h-64 overflow-y-auto">
            {result.extracted_urls.map((url, i) => (
              <div key={i} className="flex items-center gap-2 text-xs py-1 border-b border-gray-100 last:border-0">
                <ExternalLink className="w-3 h-3 text-gray-400 flex-shrink-0" />
                <span className="font-mono text-blue-700 break-all">{url}</span>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}
    </div>
  );
}
