import { useState, useEffect } from 'react';
import {
  FileBarChart, Download, FileText, Search, Copy, Check,
  ExternalLink, Clock, ShieldAlert, CheckCircle2
} from 'lucide-react';
import { getHistory, downloadPdfReport, getReport } from '../services/api';
import type { ScanHistoryItem } from '../types';
import { getThreatLevelColor, formatDate } from '../utils';
import toast from 'react-hot-toast';

export default function Reports() {
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const res = await getHistory({ limit: 25 });
        setItems(res.data.items);
      } catch (err) {
        toast.error('Failed to load recent security audit reports');
      } finally {
        setLoading(false);
      }
    };
    fetchReports();
  }, []);

  const handleDownloadJson = async (scanId: string) => {
    try {
      const res = await getReport(scanId);
      const jsonStr = JSON.stringify(res.data, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threatnex-report-${scanId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      toast.success('JSON report downloaded');
    } catch (err) {
      toast.error('Failed to export JSON report');
    }
  };

  const handleCopySummary = async (item: ScanHistoryItem) => {
    const text = `THREATNEX SECURITY AUDIT REPORT\nID: ${item.scan_id}\nType: ${item.scan_type.toUpperCase()}\nTarget: ${item.input_reference}\nThreat Level: ${item.threat_level}\nRisk Score: ${item.risk_score}/100\nDate: ${item.timestamp}`;
    await navigator.clipboard.writeText(text);
    setCopiedId(item.scan_id);
    toast.success('Summary copied to clipboard');
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="space-y-6">
      <div className="card border-l-4 border-l-blue-600">
        <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <FileBarChart className="w-5 h-5 text-blue-600" />
          Security Audit Reports & Forensic Export Center
        </h1>
        <p className="text-sm text-gray-600 mt-1">
          Export standardized cybersecurity audit reports for completed website inspections, document analyses,
          and multimodal artifact scans. Available in PDF and raw forensic JSON formats.
        </p>
      </div>

      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-600">
            <thead className="bg-gray-100 text-xs uppercase text-gray-700 font-semibold border-b border-gray-200">
              <tr>
                <th className="px-5 py-3">Scan Date</th>
                <th className="px-5 py-3">Type</th>
                <th className="px-5 py-3">Evaluated Target</th>
                <th className="px-5 py-3">Risk Assessment</th>
                <th className="px-5 py-3 text-right">Export Formats</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loading ? (
                <tr>
                  <td colSpan={5} className="text-center py-12 text-gray-500">
                    Loading audit reports...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-12 text-gray-500">
                    No scan reports available yet. Run a scan from the Scan Centre to generate reports.
                  </td>
                </tr>
              ) : (
                items.map((item) => (
                  <tr key={item.scan_id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-5 py-3.5 whitespace-nowrap text-xs text-gray-500">
                      {formatDate(item.timestamp)}
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-700 uppercase">
                        {item.scan_type}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 max-w-xs truncate font-medium text-gray-900" title={item.input_reference}>
                      {item.input_reference || 'N/A'}
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${getThreatLevelColor(item.threat_level)}`}>
                        {item.risk_score}/100 • {item.threat_level}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap text-right space-x-2">
                      <button
                        onClick={() => downloadPdfReport(item.scan_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded transition-colors"
                        title="Download PDF Report"
                      >
                        <Download className="w-3.5 h-3.5" /> PDF
                      </button>
                      <button
                        onClick={() => handleDownloadJson(item.scan_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold text-gray-700 bg-gray-100 hover:bg-gray-200 rounded transition-colors"
                        title="Download JSON Report"
                      >
                        <FileText className="w-3.5 h-3.5" /> JSON
                      </button>
                      <button
                        onClick={() => handleCopySummary(item)}
                        className="p-1 text-gray-500 hover:text-gray-900"
                        title="Copy Summary"
                      >
                        {copiedId === item.scan_id ? (
                          <Check className="w-4 h-4 text-green-600" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
