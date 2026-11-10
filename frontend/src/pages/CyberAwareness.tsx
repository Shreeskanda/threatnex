import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  BookOpen, Search, ShieldAlert, AlertTriangle, Phone, ExternalLink,
  ChevronRight, ArrowRight, ShieldCheck
} from 'lucide-react';
import { getAwarenessCategories } from '../services/api';
import type { AwarenessCategory } from '../types';
import toast from 'react-hot-toast';

export default function CyberAwareness() {
  const [categories, setCategories] = useState<AwarenessCategory[]>([]);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCats = async () => {
      try {
        const res = await getAwarenessCategories();
        setCategories(res.data);
      } catch (err) {
        toast.error('Failed to load awareness catalog');
      } finally {
        setLoading(false);
      }
    };
    fetchCats();
  }, []);

  const filtered = categories.filter((c) => {
    const matchesSearch = c.title.toLowerCase().includes(search.toLowerCase()) ||
      c.description.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === 'ALL' || c.severity_level === severityFilter.toLowerCase();
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Emergency Helpline Banner */}
      <div className="bg-gradient-to-r from-blue-900 to-indigo-900 text-white rounded-2xl p-6 shadow-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-1.5 px-3 py-1 bg-red-600/90 text-white rounded-full text-xs font-bold tracking-wide uppercase">
              <ShieldAlert className="w-3.5 h-3.5" /> Emergency Response Resources
            </div>
            <h1 className="text-2xl font-extrabold mt-2">Digital Crime Awareness & Citizen Safety Portal</h1>
            <p className="text-sm text-blue-100 mt-1 max-w-2xl">
              Knowledge base covering the top 24 cyber threats in India with real-world scenarios,
              psychological manipulation anatomy, identification techniques, and actionable victim recovery procedures.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-3">
            <a
              href="tel:1930"
              className="flex items-center justify-center gap-2 px-5 py-3 bg-red-600 hover:bg-red-700 text-white rounded-xl font-bold text-sm shadow transition-all"
            >
              <Phone className="w-4 h-4" />
              <span>National Helpline: 1930</span>
            </a>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noreferrer"
              className="flex items-center justify-center gap-2 px-5 py-3 bg-white/10 hover:bg-white/20 text-white border border-white/20 rounded-xl font-medium text-sm transition-all"
            >
              <span>cybercrime.gov.in</span>
              <ExternalLink className="w-4 h-4" />
            </a>
          </div>
        </div>
      </div>

      {/* Featured Digital Arrest Spotlight Card */}
      <div className="card border-2 border-red-200 bg-red-50/50 flex flex-col md:flex-row items-center justify-between gap-4 p-5">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-red-600 text-white rounded-xl flex-shrink-0">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <span className="text-xs font-bold text-red-700 tracking-wide uppercase">Special Advisory</span>
            <h2 className="text-lg font-bold text-gray-900 mt-0.5">High-Alert: The 'Digital Arrest' Video Call Scam</h2>
            <p className="text-xs text-gray-700 mt-1 max-w-3xl leading-relaxed">
              Criminals impersonating Police, CBI, ED, or RBI officers threaten victims on video calls, placing them under
              a bogus 'Digital Arrest' and demanding money transfers. Remember: There is NO legal concept of Digital Arrest in India.
            </p>
          </div>
        </div>
        <Link
          to="/digital-arrest"
          className="btn-danger flex items-center gap-2 px-5 py-2.5 whitespace-nowrap text-xs font-bold uppercase tracking-wider"
        >
          <span>Open Interactive Module</span>
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>

      {/* Filter and Search Bar */}
      <div className="card flex flex-col sm:flex-row items-center justify-between gap-4 py-4">
        <div className="relative w-full sm:w-96">
          <Search className="absolute left-3.5 top-2.5 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search among 24 scam guides..."
            className="w-full pl-9 pr-4 py-2 text-sm bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
          />
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
          <span className="text-xs font-semibold text-gray-500 whitespace-nowrap">Filter Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors ${
                severityFilter === sev
                  ? 'bg-blue-700 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Grid of 24 Awareness Categories */}
      {loading ? (
        <div className="text-center py-16 text-gray-500 text-sm">
          Loading comprehensive cyber safety repository...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filtered.map((item) => (
            <Link
              key={item.id}
              to={`/awareness/${item.slug}`}
              className="card group hover:border-blue-400 hover:shadow-md transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider ${
                      item.severity_level === 'critical'
                        ? 'bg-red-100 text-red-800 border border-red-200'
                        : item.severity_level === 'high'
                        ? 'bg-orange-100 text-orange-800 border border-orange-200'
                        : 'bg-amber-100 text-amber-800 border border-amber-200'
                    }`}
                  >
                    {item.severity_level} Threat
                  </span>
                  <ChevronRight className="w-4 h-4 text-gray-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                </div>

                <h3 className="text-base font-bold text-gray-900 mt-3 group-hover:text-blue-700 transition-colors">
                  {item.title}
                </h3>
                <p className="text-xs text-gray-600 mt-2 line-clamp-3 leading-relaxed">
                  {item.description}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-gray-100 flex items-center justify-between text-xs text-blue-700 font-semibold">
                <span>View Full Security Guide</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
