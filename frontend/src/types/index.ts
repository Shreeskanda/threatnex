export type ThreatLevel = 'SAFE-LOOKING' | 'LOW RISK' | 'MODERATE RISK' | 'HIGH RISK' | 'CRITICAL RISK';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanType = 'url' | 'file' | 'image' | 'text';

export interface Finding {
  title: string;
  description: string;
  severity: Severity;
  evidence: string;
  category: string;
}

export interface ScanResult {
  scan_id: string;
  scan_type: ScanType;
  input_reference: string;
  timestamp: string;
  risk_score: number;
  threat_level: ThreatLevel;
  confidence: string;
  status: string;
  findings: Finding[];
  domain_info?: Record<string, any>;
  network_info?: Record<string, any>;
  security_headers?: Record<string, any>;
  file_metadata?: Record<string, any>;
  api_status?: Record<string, string>;
  scan_duration_ms?: number;
  screenshot?: string;
  extracted_text?: string;
  extracted_urls?: string[];
}

export interface ScanHistoryItem {
  scan_id: string;
  scan_type: ScanType;
  input_reference: string;
  timestamp: string;
  risk_score: number;
  threat_level: ThreatLevel;
  status: string;
  confidence: string;
}

export interface DashboardStats {
  total_scans: number;
  safe_count: number;
  suspicious_count: number;
  critical_count: number;
  threat_distribution: { name: string; value: number; }[];
  recent_scans: ScanHistoryItem[];
  risk_level_distribution: { level: string; count: number; }[];
  most_common_threats: { category: string; count: number; }[];
}

export interface AwarenessCategory {
  id: string;
  title: string;
  slug: string;
  icon: string;
  description: string;
  severity_level: 'critical' | 'high' | 'medium';
}

export interface AwarenessContent extends AwarenessCategory {
  how_it_works: string;
  warning_signs: string[];
  example_scenario: string;
  manipulation_tactics: string;
  how_to_identify: string;
  prevention_tips: string[];
  victim_steps: string[];
}

export interface QuizQuestion {
  id: string;
  level: 'beginner' | 'intermediate' | 'advanced';
  question: string;
  options: string[];
  correct_answer: number;
  explanation: string;
  category: string;
}
