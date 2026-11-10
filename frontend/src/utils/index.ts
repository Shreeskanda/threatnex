export const getRiskColor = (score: number): string => {
  if (score >= 80) return 'text-red-700';
  if (score >= 60) return 'text-orange-600';
  if (score >= 40) return 'text-amber-600';
  if (score >= 20) return 'text-blue-600';
  return 'text-green-600';
};

export const getRiskBg = (score: number): string => {
  if (score >= 80) return 'bg-red-50 border-red-200';
  if (score >= 60) return 'bg-orange-50 border-orange-200';
  if (score >= 40) return 'bg-amber-50 border-amber-200';
  if (score >= 20) return 'bg-blue-50 border-blue-200';
  return 'bg-green-50 border-green-200';
};

export const getThreatLevelColor = (level: string): string => {
  const map: Record<string, string> = {
    'CRITICAL RISK': 'text-red-700 bg-red-100 border-red-200',
    'HIGH RISK': 'text-orange-700 bg-orange-100 border-orange-200',
    'MODERATE RISK': 'text-amber-700 bg-amber-100 border-amber-200',
    'LOW RISK': 'text-blue-700 bg-blue-100 border-blue-200',
    'SAFE-LOOKING': 'text-green-700 bg-green-100 border-green-200',
  };
  return map[level] || 'text-gray-700 bg-gray-100 border-gray-200';
};

export const getSeverityColor = (severity: string): string => {
  const map: Record<string, string> = {
    critical: 'severity-critical',
    high: 'severity-high',
    medium: 'severity-medium',
    low: 'severity-low',
    info: 'severity-info',
  };
  return map[severity] || 'severity-info';
};

export const formatDate = (iso: string): string => {
  return new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
};

export const truncate = (str: string, n: number): string =>
  str.length > n ? str.slice(0, n) + '...' : str;
