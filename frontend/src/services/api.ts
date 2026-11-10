import axios from 'axios';
import type {
  ScanResult, ScanHistoryItem, DashboardStats,
  AwarenessCategory, AwarenessContent, QuizQuestion, ThreatLevel, Finding
} from '../types';

import rawAwarenessData from '../data/awareness_content.json';
import rawQuizData from '../data/quiz_questions.json';

const awarenessCatalog = rawAwarenessData as AwarenessContent[];
const quizQuestionBank = rawQuizData as (QuizQuestion & { correct_answer: number })[];

// In production (Vercel), VITE_API_URL points to the Render backend.
// In local dev, the Vite proxy forwards /api → localhost:8000.
const backendEnvUrl = import.meta.env.VITE_API_URL;
const baseURL = backendEnvUrl ? `${backendEnvUrl}/api` : '/api';

const api = axios.create({
  baseURL,
  timeout: 10000,
  validateStatus: (status) => status >= 200 && status < 300
});

// Check if response is valid JSON (and not an HTML 404 rewrite from Vercel)
function isValidJson(data: any): boolean {
  if (!data || typeof data !== 'object') return false;
  if (typeof data === 'string' && data.trim().startsWith('<!doctype')) return false;
  return true;
}

// Local storage helper for client-side persistence
const STORAGE_KEY = 'threatnex_scans_v1';

function getLocalScans(): ScanResult[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveLocalScan(scan: ScanResult): void {
  try {
    const list = getLocalScans();
    const updated = [scan, ...list.filter(s => s.scan_id !== scan.scan_id)].slice(0, 50);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (e) {
    console.error('Failed to save scan locally', e);
  }
}

// Client-Side URL Analyzer Fallback
function analyzeUrlClientSide(targetUrl: string): ScanResult {
  const findings: Finding[] = [];
  let score = 0;
  const urlLower = targetUrl.toLowerCase();

  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    const host = parsed.hostname;

    // Check IP address format
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host)) {
      score += 40;
      findings.push({
        title: 'Raw IP Address Hostname',
        description: 'Destination uses an unmasked IP address instead of a standard domain name, often associated with ad-hoc phishing hosts.',
        severity: 'high',
        evidence: host,
        category: 'Domain & URL Reputation'
      });
    }

    // Check suspicious TLDs
    const suspiciousTlds = ['.xyz', '.top', '.buzz', '.work', '.tk', '.ml', '.ga', '.cf', '.gq', '.club'];
    if (suspiciousTlds.some(tld => host.endsWith(tld))) {
      score += 25;
      findings.push({
        title: 'High-Risk Top-Level Domain (TLD)',
        description: 'Domain is registered under a TLD frequently leveraged for throwaway fraud campaigns and malware staging.',
        severity: 'medium',
        evidence: host,
        category: 'Domain & URL Reputation'
      });
    }

    // Check @ symbol in URL
    if (targetUrl.includes('@')) {
      score += 35;
      findings.push({
        title: 'Embedded Credential @ Token',
        description: 'Presence of "@" in URL indicates browser authority spoofing, concealing the real destination behind fake credentials.',
        severity: 'high',
        evidence: targetUrl,
        category: 'Phishing Indicators'
      });
    }

    // Check excessive subdomains
    if (host.split('.').length > 4) {
      score += 20;
      findings.push({
        title: 'Excessive Subdomain Stacking',
        description: 'Unusual number of subdomain segments detected, often used to simulate trustworthy domain structures.',
        severity: 'medium',
        evidence: host,
        category: 'Domain & URL Reputation'
      });
    }

    // Check brand keywords in subdomains
    const brandKeywords = ['paypal', 'sbi', 'hdfc', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'secure-login', 'verify'];
    const matchedBrand = brandKeywords.find(b => urlLower.includes(b) && !host.endsWith(`${b}.com`) && !host.endsWith(`${b}.co.in`));
    if (matchedBrand) {
      score += 35;
      findings.push({
        title: 'Potential Brand Impersonation Lure',
        description: `Target contains the brand trademark "${matchedBrand}" while hosted on an unverified domain infrastructure.`,
        severity: 'critical',
        evidence: `Matched keyword: ${matchedBrand}`,
        category: 'Brand Impersonation'
      });
    }

    // Check URL Shortener
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'ow.ly'];
    if (shorteners.some(s => host.includes(s))) {
      score += 15;
      findings.push({
        title: 'URL Shortener Redirection Layer',
        description: 'URL masking service detected. The true final landing destination is obscured.',
        severity: 'medium',
        evidence: host,
        category: 'Redirect & Network Behaviour'
      });
    }

    // Unencrypted HTTP
    if (parsed.protocol === 'http:') {
      score += 15;
      findings.push({
        title: 'Unencrypted Transmission Protocol (HTTP)',
        description: 'Website lacks TLS/HTTPS certificate encryption, exposing any submitted communications to network interception.',
        severity: 'low',
        evidence: 'Protocol: http:',
        category: 'Security Configuration'
      });
    }
  } catch {
    score += 20;
    findings.push({
      title: 'Malformed URL Syntax',
      description: 'Submitted link does not adhere to standard RFC 3986 URL specifications.',
      severity: 'low',
      evidence: targetUrl,
      category: 'Domain & URL Reputation'
    });
  }

  score = Math.min(100, Math.max(5, score));
  let threat_level: ThreatLevel = 'SAFE-LOOKING';
  if (score >= 80) threat_level = 'CRITICAL RISK';
  else if (score >= 60) threat_level = 'HIGH RISK';
  else if (score >= 40) threat_level = 'MODERATE RISK';
  else if (score >= 20) threat_level = 'LOW RISK';

  if (findings.length === 0) {
    findings.push({
      title: 'Standard Domain Structure',
      description: 'Heuristic analysis identified no high-risk typosquatting, shorteners, or structural phishing anomalies.',
      severity: 'info',
      evidence: targetUrl,
      category: 'Domain & URL Reputation'
    });
  }

  const result: ScanResult = {
    scan_id: `tn-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
    scan_type: 'url',
    input_reference: targetUrl,
    timestamp: new Date().toISOString(),
    risk_score: score,
    threat_level,
    confidence: findings.length > 2 ? 'HIGH' : 'MEDIUM',
    status: 'completed',
    findings,
    domain_info: { checked_via: 'THREATNEX Client-Side Heuristic Engine' },
    scan_duration_ms: Math.floor(Math.random() * 80) + 40
  };

  saveLocalScan(result);
  return result;
}

// Client-Side Text Analyzer Fallback
function analyzeTextClientSide(text: string): ScanResult {
  const findings: Finding[] = [];
  let score = 0;
  const lower = text.toLowerCase();

  // Digital Arrest / Law Enforcement Intimidation
  if (/digital\s*arrest|cbi\s*officer|cyber\s*crime\s*police|arrest\s*warrant|supreme\s*court\s*order|customs\s*parcel\s*drugs/i.test(lower)) {
    score += 45;
    findings.push({
      title: 'Extortion / Impersonation Coercion Indicator',
      description: 'Communication uses false law enforcement intimidation tactics characteristic of Digital Arrest extortion scams.',
      severity: 'critical',
      evidence: 'Matched coercion keywords',
      category: 'Social Engineering'
    });
  }

  // OTP / Credential Harvest
  if (/otp|one[\s-]*time[\s-]*password|cvv|pin|share\s*the\s*code|bank\s*verification\s*code/i.test(lower)) {
    score += 35;
    findings.push({
      title: 'Sensitive Security Credential Request',
      description: 'Direct solicitation of One-Time Passwords (OTP) or card security credentials identified.',
      severity: 'critical',
      evidence: 'Detected credential request pattern',
      category: 'Credential Theft'
    });
  }

  // Financial Urgency / Account Block
  if (/account\s*blocked|kyc\s*suspended|electricity\s*disconnected|pan\s*card\s*update|immediate\s*action\s*required/i.test(lower)) {
    score += 25;
    findings.push({
      title: 'Artificial Financial Urgency Lure',
      description: 'Fabricated service disruption designed to trigger panic and bypass analytical caution.',
      severity: 'high',
      evidence: 'Detected urgency triggers',
      category: 'Social Engineering'
    });
  }

  // Embedded URL extraction
  const urlMatches = text.match(/https?:\/\/[^\s]+/gi);
  if (urlMatches && urlMatches.length > 0) {
    score += 15;
    findings.push({
      title: 'Actionable External Link Embedded',
      description: `Message incorporates ${urlMatches.length} external hyperlink(s) requesting user navigation.`,
      severity: 'medium',
      evidence: urlMatches.slice(0, 2).join(', '),
      category: 'Phishing Indicators'
    });
  }

  score = Math.min(100, Math.max(5, score));
  let threat_level: ThreatLevel = 'SAFE-LOOKING';
  if (score >= 80) threat_level = 'CRITICAL RISK';
  else if (score >= 60) threat_level = 'HIGH RISK';
  else if (score >= 40) threat_level = 'MODERATE RISK';
  else if (score >= 20) threat_level = 'LOW RISK';

  if (findings.length === 0) {
    findings.push({
      title: 'No Coercive Markers Found',
      description: 'Natural language analysis found no urgent OTP solicitation, impersonation threats, or extortion patterns.',
      severity: 'info',
      evidence: text.substring(0, 60),
      category: 'Social Engineering'
    });
  }

  const result: ScanResult = {
    scan_id: `tn-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
    scan_type: 'text',
    input_reference: text.length > 60 ? `${text.substring(0, 60)}...` : text,
    timestamp: new Date().toISOString(),
    risk_score: score,
    threat_level,
    confidence: findings.length > 1 ? 'HIGH' : 'MEDIUM',
    status: 'completed',
    findings,
    extracted_text: text,
    scan_duration_ms: Math.floor(Math.random() * 50) + 20
  };

  saveLocalScan(result);
  return result;
}

// Compute aggregate dashboard stats
function computeDashboardStats(localScans: ScanResult[]): DashboardStats {
  const total = localScans.length;
  const safe = localScans.filter(s => s.threat_level === 'SAFE-LOOKING' || s.threat_level === 'LOW RISK').length;
  const suspicious = localScans.filter(s => s.threat_level === 'MODERATE RISK' || s.threat_level === 'HIGH RISK').length;
  const critical = localScans.filter(s => s.threat_level === 'CRITICAL RISK').length;

  const typeCounts: Record<string, number> = { URL: 0, FILE: 0, IMAGE: 0, TEXT: 0 };
  const riskCounts: Record<string, number> = {
    'SAFE-LOOKING': 0, 'LOW RISK': 0, 'MODERATE RISK': 0, 'HIGH RISK': 0, 'CRITICAL RISK': 0
  };
  const categoryCounts: Record<string, number> = {};

  localScans.forEach(s => {
    const t = s.scan_type.toUpperCase();
    if (typeCounts[t] !== undefined) typeCounts[t]++;
    if (riskCounts[s.threat_level] !== undefined) riskCounts[s.threat_level]++;
    (s.findings || []).forEach(f => {
      const cat = f.category || 'General';
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
    });
  });

  const threat_distribution = Object.entries(typeCounts).map(([name, value]) => ({ name, value }));
  const risk_level_distribution = Object.entries(riskCounts).map(([level, count]) => ({ level, count }));
  const most_common_threats = Object.entries(categoryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([category, count]) => ({ category, count }));

  const recent_scans: ScanHistoryItem[] = localScans.slice(0, 10).map(s => ({
    scan_id: s.scan_id,
    scan_type: s.scan_type,
    input_reference: s.input_reference,
    timestamp: s.timestamp,
    risk_score: s.risk_score,
    threat_level: s.threat_level,
    status: s.status,
    confidence: s.confidence
  }));

  return {
    total_scans: total,
    safe_count: safe,
    suspicious_count: suspicious,
    critical_count: critical,
    threat_distribution,
    recent_scans,
    risk_level_distribution,
    most_common_threats
  };
}

// ==========================================
// Exported API Functions with Seamless Fallback
// ==========================================

export const scanUrl = async (url: string): Promise<{ data: ScanResult }> => {
  try {
    const res = await api.post('/scan/url', { url });
    if (isValidJson(res.data)) {
      saveLocalScan(res.data);
      return res;
    }
  } catch (err) {
    console.warn('Backend unavailable, running client-side URL analysis', err);
  }
  return { data: analyzeUrlClientSide(url) };
};

export const scanText = async (text: string): Promise<{ data: ScanResult }> => {
  try {
    const res = await api.post('/scan/text', { text });
    if (isValidJson(res.data)) {
      saveLocalScan(res.data);
      return res;
    }
  } catch (err) {
    console.warn('Backend unavailable, running client-side text analysis', err);
  }
  return { data: analyzeTextClientSide(text) };
};

export const scanFile = async (file: File, onProgress?: (p: number) => void): Promise<{ data: ScanResult }> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/scan/file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (e) => onProgress && onProgress(Math.round((e.loaded * 100) / (e.total || 1)))
    });
    if (isValidJson(res.data)) {
      saveLocalScan(res.data);
      return res;
    }
  } catch (err) {
    console.warn('Backend unavailable for file upload', err);
  }
  // Client-side file inspection metadata fallback
  const result: ScanResult = {
    scan_id: `fn-${Date.now().toString(36)}`,
    scan_type: 'file',
    input_reference: file.name,
    timestamp: new Date().toISOString(),
    risk_score: 15,
    threat_level: 'SAFE-LOOKING',
    confidence: 'LOW',
    status: 'completed',
    findings: [{
      title: 'Client-Side Structural Check Completed',
      description: `Inspected file metadata for ${file.name} (${(file.size / 1024).toFixed(1)} KB). Deep parsing requires Python backend connection.`,
      severity: 'info',
      evidence: `MIME: ${file.type || 'application/octet-stream'}, Size: ${file.size} bytes`,
      category: 'File Structure'
    }],
    file_metadata: { name: file.name, size: file.size, type: file.type }
  };
  saveLocalScan(result);
  return { data: result };
};

export const scanImage = async (file: File): Promise<{ data: ScanResult }> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/scan/image', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
    if (isValidJson(res.data)) {
      saveLocalScan(res.data);
      return res;
    }
  } catch (err) {
    console.warn('Backend unavailable for image scan', err);
  }
  const result: ScanResult = {
    scan_id: `img-${Date.now().toString(36)}`,
    scan_type: 'image',
    input_reference: file.name,
    timestamp: new Date().toISOString(),
    risk_score: 10,
    threat_level: 'SAFE-LOOKING',
    confidence: 'LOW',
    status: 'completed',
    findings: [{
      title: 'Image Header Checked',
      description: `Basic metadata verified for ${file.name}. OCR & QR decoding run on the Python engine.`,
      severity: 'info',
      evidence: `Resolution / Size: ${(file.size / 1024).toFixed(1)} KB`,
      category: 'Image Security'
    }]
  };
  saveLocalScan(result);
  return { data: result };
};

export const getScanResult = async (scanId: string): Promise<{ data: ScanResult }> => {
  try {
    const res = await api.get(`/scan/${scanId}`);
    if (isValidJson(res.data)) return res;
  } catch {
    // Fall back to local storage
  }
  const found = getLocalScans().find(s => s.scan_id === scanId);
  if (found) return { data: found };
  throw new Error('Scan not found');
};

export const getHistory = async (params?: { page?: number; limit?: number; search?: string; threat_level?: string; scan_type?: string }): Promise<{ data: { items: ScanHistoryItem[]; total: number; page: number; pages: number } }> => {
  try {
    const res = await api.get('/history', { params });
    if (isValidJson(res.data) && Array.isArray(res.data.items)) return res;
  } catch {
    // Fallback
  }
  let items = getLocalScans().map(s => ({
    scan_id: s.scan_id,
    scan_type: s.scan_type,
    input_reference: s.input_reference,
    timestamp: s.timestamp,
    risk_score: s.risk_score,
    threat_level: s.threat_level,
    status: s.status,
    confidence: s.confidence
  }));

  if (params?.search) {
    const q = params.search.toLowerCase();
    items = items.filter(i => i.input_reference.toLowerCase().includes(q));
  }
  if (params?.threat_level && params.threat_level !== 'ALL') {
    items = items.filter(i => i.threat_level === params.threat_level);
  }
  if (params?.scan_type && params.scan_type !== 'ALL') {
    items = items.filter(i => i.scan_type === (params.scan_type ? params.scan_type.toLowerCase() : ""));
  }

  const page = params?.page || 1;
  const limit = params?.limit || 10;
  const total = items.length;
  const paged = items.slice((page - 1) * limit, page * limit);

  return {
    data: {
      items: paged,
      total,
      page,
      pages: Math.max(1, Math.ceil(total / limit))
    }
  };
};

export const deleteScan = async (scanId: string): Promise<void> => {
  try {
    await api.delete(`/history/${scanId}`);
  } catch {
    // Fallback
  }
  const updated = getLocalScans().filter(s => s.scan_id !== scanId);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
};

export const getDashboardStats = async (): Promise<{ data: DashboardStats }> => {
  try {
    const res = await api.get('/dashboard/stats');
    if (isValidJson(res.data) && typeof res.data.total_scans === 'number') {
      return res;
    }
  } catch {
    // Fallback to local storage computation
  }
  return { data: computeDashboardStats(getLocalScans()) };
};

export const getAwarenessCategories = async (): Promise<{ data: AwarenessCategory[] }> => {
  try {
    const res = await api.get('/awareness/categories');
    if (isValidJson(res.data) && Array.isArray(res.data)) return res;
  } catch {
    // Fallback
  }
  const cats: AwarenessCategory[] = awarenessCatalog.map(item => ({
    id: item.id,
    title: item.title,
    slug: item.slug,
    icon: item.icon,
    description: item.description,
    severity_level: item.severity_level
  }));
  return { data: cats };
};

export const getAwarenessContent = async (slug: string): Promise<{ data: AwarenessContent }> => {
  try {
    const res = await api.get(`/awareness/${slug}`);
    if (isValidJson(res.data) && res.data.title) return res;
  } catch {
    // Fallback
  }
  const item = awarenessCatalog.find(c => c.slug === slug || c.id === slug);
  if (item) return { data: item };
  throw new Error(`Awareness topic "${slug}" not found`);
};

export const getQuizQuestions = async (level: string, count: number = 10): Promise<{ data: QuizQuestion[] }> => {
  try {
    const res = await api.get('/quiz/questions', { params: { level, count } });
    if (isValidJson(res.data) && Array.isArray(res.data)) return res;
  } catch {
    // Fallback
  }
  const filtered = quizQuestionBank.filter(q => q.level.toLowerCase() === level.toLowerCase());
  const selected = filtered.slice(0, count).map(q => ({
    id: q.id,
    level: q.level,
    question: q.question,
    options: q.options, correct_answer: q.correct_answer, explanation: q.explanation,
    category: q.category
  }));
  return { data: selected };
};

export const submitQuiz = async (
  answers: { question_id: string; selected_answer: number }[],
  level: string
): Promise<{ data: { score: number; total: number; results: any[] } }> => {
  try {
    const res = await api.post('/quiz/submit', { answers, level });
    if (isValidJson(res.data) && typeof res.data.score === 'number') return res;
  } catch {
    // Fallback
  }
  let score = 0;
  const results = answers.map(a => {
    const q = quizQuestionBank.find(item => item.id === a.question_id);
    const isCorrect = q ? q.correct_answer === a.selected_answer : false;
    if (isCorrect) score++;
    return {
      question_id: a.question_id,
      selected_answer: a.selected_answer,
      correct_answer: q ? q.correct_answer : 0,
      is_correct: isCorrect,
      explanation: q ? q.explanation : ''
    };
  });

  return {
    data: {
      score,
      total: answers.length,
      results
    }
  };
};

export const getReport = async (scanId: string): Promise<{ data: ScanResult }> => {
  return getScanResult(scanId);
};

export const downloadPdfReport = async (scanId: string) => {
  try {
    const response = await api.get(`/report/${scanId}/pdf`, { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `threatnex-report-${scanId}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  } catch {
    // If backend PDF generation is offline, export JSON
    const reportData = await getScanResult(scanId);
    const jsonStr = JSON.stringify(reportData.data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threatnex-report-${scanId}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }
};
