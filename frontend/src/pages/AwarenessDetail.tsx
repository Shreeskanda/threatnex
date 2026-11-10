import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft, ShieldAlert, AlertTriangle, CheckCircle, Phone,
  ExternalLink, Eye, UserX, HelpCircle, ShieldCheck
} from 'lucide-react';
import { getAwarenessContent } from '../services/api';
import type { AwarenessContent } from '../types';
import toast from 'react-hot-toast';

export default function AwarenessDetail() {
  const { slug } = useParams<{ slug: string }>();
  const [data, setData] = useState<AwarenessContent | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!slug) return;
    const fetchDetail = async () => {
      setLoading(true);
      try {
        const res = await getAwarenessContent(slug);
        setData(res.data);
      } catch (err) {
        toast.error('Failed to load awareness guide.');
      } finally {
        setLoading(false);
      }
    };
    fetchDetail();
  }, [slug]);

  if (loading) {
    return (
      <div className="card text-center py-16 text-gray-500 text-sm">
        Loading cyber safety advisory...
      </div>
    );
  }

  if (!data) {
    return (
      <div className="card text-center py-16 space-y-4">
        <p className="text-gray-600">The requested scam awareness guide could not be located.</p>
        <Link to="/awareness" className="btn-primary inline-flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" /> Back to Awareness Center
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Back button */}
      <div>
        <Link
          to="/awareness"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-600 hover:text-blue-700 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to All Cyber Awareness Guides
        </Link>
      </div>

      {/* Main Header Card */}
      <div className="card border-l-4 border-l-blue-600">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span
            className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider ${
              data.severity_level === 'critical'
                ? 'bg-red-100 text-red-800 border border-red-200'
                : data.severity_level === 'high'
                ? 'bg-orange-100 text-orange-800 border border-orange-200'
                : 'bg-amber-100 text-amber-800 border border-amber-200'
            }`}
          >
            {data.severity_level} Threat Advisory
          </span>
          <span className="text-xs text-gray-500 font-medium">THREATNEX Intelligence Library</span>
        </div>

        <h1 className="text-2xl font-extrabold text-gray-900 mt-3">{data.title}</h1>
        <p className="text-sm text-gray-700 mt-2 leading-relaxed">{data.description}</p>
      </div>

      {/* How it Works */}
      <div className="card">
        <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
          <Eye className="w-5 h-5 text-blue-600" />
          How This Scam Operates
        </h2>
        <p className="text-sm text-gray-700 mt-3 leading-relaxed">{data.how_it_works}</p>
      </div>

      {/* Warning Signs */}
      <div className="card border-l-4 border-l-orange-500 bg-orange-50/20">
        <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-orange-600" />
          Common Warning Signs & Red Flags
        </h2>
        <ul className="mt-3 space-y-2.5">
          {data.warning_signs?.map((sign, idx) => (
            <li key={idx} className="flex items-start gap-2.5 text-sm text-gray-800">
              <span className="w-2 h-2 rounded-full bg-orange-500 flex-shrink-0 mt-1.5" />
              <span>{sign}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Example Scenario */}
      {data.example_scenario && (
        <div className="card bg-gray-50 border-gray-300">
          <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
            <HelpCircle className="w-5 h-5 text-gray-600" />
            Realistic Scenario Breakdown
          </h2>
          <div className="mt-3 p-4 bg-white border border-gray-200 rounded-lg text-sm text-gray-800 italic leading-relaxed">
            "{data.example_scenario}"
          </div>
        </div>
      )}

      {/* Psychological Manipulation Tactics */}
      {data.manipulation_tactics && (
        <div className="card">
          <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
            <UserX className="w-5 h-5 text-purple-600" />
            Psychological Manipulation & Social Engineering Tactics
          </h2>
          <p className="text-sm text-gray-700 mt-2 leading-relaxed">
            {data.manipulation_tactics}
          </p>
        </div>
      )}

      {/* Prevention Tips */}
      <div className="card border-l-4 border-l-green-600 bg-green-50/20">
        <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-green-700" />
          How to Protect Yourself (Best Practices Checklist)
        </h2>
        <ul className="mt-3 space-y-2.5">
          {data.prevention_tips?.map((tip, idx) => (
            <li key={idx} className="flex items-start gap-2.5 text-sm text-gray-800">
              <CheckCircle className="w-4 h-4 text-green-600 flex-shrink-0 mt-0.5" />
              <span>{tip}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* What to do if victimized */}
      <div className="card border-2 border-red-300 bg-red-50/40">
        <h2 className="text-base font-bold text-red-900 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-red-600" />
          Immediate Action Plan If You Have Been Victimized
        </h2>
        <ol className="mt-3 space-y-3">
          {data.victim_steps?.map((step, idx) => (
            <li key={idx} className="flex items-start gap-3 text-sm text-gray-900">
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-red-600 text-white font-bold text-xs flex-shrink-0 mt-0.5">
                {idx + 1}
              </span>
              <span>{step}</span>
            </li>
          ))}
        </ol>

        {/* Emergency contact callout */}
        <div className="mt-5 pt-4 border-t border-red-200 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-xs text-red-900 font-semibold">
            Act immediately within the "Golden Hour" to maximize chances of financial freezing.
          </div>
          <a
            href="tel:1930"
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-bold transition-all"
          >
            <Phone className="w-3.5 h-3.5" /> Call 1930 Helpline
          </a>
        </div>
      </div>
    </div>
  );
}
