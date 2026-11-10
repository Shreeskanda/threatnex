import { Loader2, X } from 'lucide-react';

interface ScanProgressProps {
  step?: string;
  onCancel?: () => void;
}

const steps = [
  'Initializing scan engine...',
  'Resolving domain information...',
  'Fetching page content...',
  'Analyzing HTML structure...',
  'Checking external threat databases...',
  'Scanning for malicious patterns...',
  'Analyzing JavaScript behavior...',
  'Checking SSL/TLS configuration...',
  'Verifying security headers...',
  'Generating risk assessment...',
];

export default function ScanProgress({ step, onCancel }: ScanProgressProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-6">
      <div className="relative">
        <div className="w-16 h-16 rounded-full border-4 border-blue-100 flex items-center justify-center">
          <Loader2 className="w-8 h-8 text-blue-600 animate-spin" />
        </div>
        <div className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-blue-600 animate-pulse" />
      </div>

      <div className="text-center">
        <h3 className="font-semibold text-gray-900 mb-1">Analyzing Threat...</h3>
        <p className="text-sm text-gray-500 max-w-sm">
          {step || 'Running comprehensive security analysis. This may take up to 60 seconds.'}
        </p>
      </div>

      <div className="w-full max-w-sm space-y-1.5">
        {steps.map((s, i) => (
          <div key={s} className="flex items-center gap-2 text-xs text-gray-400">
            <div className="w-1.5 h-1.5 rounded-full bg-blue-300 animate-pulse" style={{ animationDelay: `${i * 0.2}s` }} />
            {s}
          </div>
        ))}
      </div>

      {onCancel && (
        <button
          onClick={onCancel}
          className="flex items-center gap-2 text-sm text-gray-500 hover:text-red-600 transition-colors px-4 py-2 rounded-lg hover:bg-red-50 border border-transparent hover:border-red-200"
        >
          <X className="w-4 h-4" />
          Cancel Scan
        </button>
      )}
    </div>
  );
}
