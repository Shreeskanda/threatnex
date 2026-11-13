import { useState, useEffect } from 'react';
import {
  Clock, Search, Filter, Trash2, Download, Eye,
  AlertCircle, ShieldCheck, ChevronLeft, ChevronRight, X
} from 'lucide-react';
import { getHistory, deleteScan, getScanResult, downloadPdfReport } from '../services/api';
import type { ScanHistoryItem, ScanResult } from '../types';
import { getThreatLevelColor, formatDate } from '../utils';
import ScanResultView from '../components/ScanResultView';
import toast from 'react-hot-toast';

export default function ScanHistory() {
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);

  // Filters
  const [search, setSearch] = useState('');
  const [threatLevel, setThreatLevel] = useState('');
  const [scanType, setScanType] = useState('');

  // Selected item detail view modal
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await getHistory({
        page,
        limit: 15,
        search: search || undefined,
        threat_level: threatLevel || undefined,
        scan_type: scanType || undefined,
      });
      setItems(res.data.items);
      setTotal(res.data.total);
      setPages(res.data.pages);
    } catch (err) {
      toast.error('Failed to load scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page, threatLevel, scanType]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const handleDelete = async (scanId: string) => {
    if (!window.confirm('Are you sure you want to delete this scan record?')) return;
    try {
      await deleteScan(scanId);
      toast.success('Scan record deleted');
      fetchHistory();
    } catch (err) {
      toast.error('Failed to delete scan record');
    }
  };

  const handleViewDetail = async (scanId: string) => {
    setDetailLoading(true);
    try {
      const res = await getScanResult(scanId);
      setSelectedScan(res.data);
    } catch (err) {
      toast.error('Failed to fetch full scan details');
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
              <Clock className="w-5 h-5 text-blue-600" />
              Historical Scan Records & Audit Log
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Persistent storage of evaluated URLs, files, images, and text artifacts with forensic evidence.
            </p>
          </div>
          <div className="text-sm font-semibold text-gray-700 bg-gray-100 px-3 py-1.5 rounded-lg self-start sm:self-auto">
            Total Scans Logged: {total}
          </div>
        </div>

        {/* Filter bar */}
        <div className="mt-5 grid grid-cols-1 sm:grid-cols-12 gap-3 pt-4 border-t border-gray-100">
          <form onSubmit={handleSearchSubmit} className="sm:col-span-6 relative">
            <label htmlFor="scan-history-search" className="sr-only">Search scan history</label>
            <Search className="absolute left-3.5 top-2.5 w-4 h-4 text-gray-400" />
            <input
              id="scan-history-search"
              name="search"
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by URL, file name, or keyword..."
              aria-label="Search by URL, file name, or keyword"
              className="w-full pl-9 pr-4 py-2 text-sm bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
            />
          </form>

          <div className="sm:col-span-3">
            <label htmlFor="filter-threat-level" className="sr-only">Filter by Threat Level</label>
            <select
              id="filter-threat-level"
              name="threatLevel"
              value={threatLevel}
              aria-label="Filter scan records by threat level"
              onChange={(e) => {
                setThreatLevel(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-sm bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600"
            >
              <option value="">All Threat Levels</option>
              <option value="CRITICAL RISK">Critical Risk</option>
              <option value="HIGH RISK">High Risk</option>
              <option value="MODERATE RISK">Moderate Risk</option>
              <option value="LOW RISK">Low Risk</option>
              <option value="SAFE-LOOKING">Safe-Looking</option>
            </select>
          </div>

          <div className="sm:col-span-3">
            <label htmlFor="filter-scan-type" className="sr-only">Filter by Scan Type</label>
            <select
              id="filter-scan-type"
              name="scanType"
              value={scanType}
              aria-label="Filter scan records by scan type"
              onChange={(e) => {
                setScanType(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-sm bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600"
            >
              <option value="">All Scan Types</option>
              <option value="url">URL Scans</option>
              <option value="file">File Scans</option>
              <option value="image">Image Scans</option>
              <option value="text">Text Scans</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-600">
            <thead className="bg-gray-100 text-xs uppercase text-gray-700 font-semibold border-b border-gray-200">
              <tr>
                <th className="px-5 py-3">Timestamp</th>
                <th className="px-5 py-3">Type</th>
                <th className="px-5 py-3">Target Reference</th>
                <th className="px-5 py-3">Risk Score</th>
                <th className="px-5 py-3">Threat Level</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loading ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-gray-500">
                    Loading scan history records...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-gray-500">
                    No scan records found matching filter criteria.
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
                    <td className="px-5 py-3.5 whitespace-nowrap font-bold text-gray-900">
                      {item.risk_score} / 100
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${getThreatLevelColor(item.threat_level)}`}>
                        {item.threat_level}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap text-right space-x-2">
                      <button
                        onClick={() => handleViewDetail(item.scan_id)}
                        className="p-1.5 text-gray-500 hover:text-blue-700 hover:bg-blue-50 rounded"
                        title="View Full Technical Report"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => downloadPdfReport(item.scan_id)}
                        className="p-1.5 text-gray-500 hover:text-green-700 hover:bg-green-50 rounded"
                        title="Download PDF Audit Report"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(item.scan_id)}
                        className="p-1.5 text-gray-500 hover:text-red-700 hover:bg-red-50 rounded"
                        title="Delete Record"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pages > 1 && (
          <div className="flex items-center justify-between px-5 py-3 bg-gray-50 border-t border-gray-200 text-xs text-gray-600">
            <div>
              Showing page {page} of {pages}
            </div>
            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="p-1.5 rounded border border-gray-300 disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                disabled={page >= pages}
                onClick={() => setPage(page + 1)}
                className="p-1.5 rounded border border-gray-300 disabled:opacity-40"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Selected Scan Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 bg-black/60 overflow-y-auto p-4 sm:p-6 flex items-start justify-center">
          <div className="bg-white rounded-2xl w-full max-w-5xl my-8 p-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedScan(null)}
              className="absolute top-5 right-5 p-2 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-full"
            >
              <X className="w-6 h-6" />
            </button>
            <div className="mb-4 pr-10">
              <h2 className="text-xl font-bold text-gray-900">Historical Scan Inspection Details</h2>
              <p className="text-xs text-gray-500 mt-1">Audit Record ID: {selectedScan.scan_id}</p>
            </div>
            <ScanResultView result={selectedScan} />
          </div>
        </div>
      )}
    </div>
  );
}
