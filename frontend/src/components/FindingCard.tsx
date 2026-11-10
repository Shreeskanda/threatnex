import { useState } from 'react';
import { ChevronDown, ChevronUp, Tag } from 'lucide-react';
import type { Finding } from '../types';
import { getSeverityColor } from '../utils';
import clsx from 'clsx';

interface FindingCardProps {
  finding: Finding;
  index?: number;
}

export default function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={clsx('border rounded-lg overflow-hidden', {
      'border-red-200 bg-red-50': finding.severity === 'critical',
      'border-orange-200 bg-orange-50': finding.severity === 'high',
      'border-amber-200 bg-amber-50': finding.severity === 'medium',
      'border-blue-200 bg-blue-50': finding.severity === 'low',
      'border-gray-200 bg-gray-50': finding.severity === 'info',
    })}>
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1.5">
              {index !== undefined && (
                <span className="text-xs text-gray-500 font-mono">#{index + 1}</span>
              )}
              <span className={clsx('px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide', getSeverityColor(finding.severity))}>
                {finding.severity}
              </span>
              <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-gray-100 text-gray-600 text-xs border border-gray-200">
                <Tag className="w-3 h-3" />
                {finding.category}
              </span>
            </div>
            <h3 className="font-semibold text-gray-900 text-sm">{finding.title}</h3>
            <p className="text-sm text-gray-700 mt-1 leading-relaxed">{finding.description}</p>
          </div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex-shrink-0 p-1.5 rounded hover:bg-white/50 text-gray-500 transition-colors"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>

        {expanded && finding.evidence && (
          <div className="mt-3 pt-3 border-t border-black/10">
            <div className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1.5">Evidence</div>
            <div className="bg-white/70 rounded p-3 text-xs font-mono text-gray-700 break-all whitespace-pre-wrap max-h-40 overflow-y-auto border border-black/10">
              {finding.evidence}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
