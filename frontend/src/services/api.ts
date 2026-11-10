import axios from 'axios';
import type { ScanResult, ScanHistoryItem, DashboardStats, AwarenessCategory, AwarenessContent, QuizQuestion } from '../types';

// In production (Vercel), VITE_API_URL points to the Render backend.
// In local dev, the Vite proxy forwards /api → localhost:8000.
const baseURL = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api`
  : '/api';

const api = axios.create({ baseURL, timeout: 120000 });

export const scanUrl = (url: string): Promise<{ data: ScanResult }> =>
  api.post('/scan/url', { url });

export const scanText = (text: string): Promise<{ data: ScanResult }> =>
  api.post('/scan/text', { text });

export const scanFile = (file: File, onProgress?: (p: number) => void): Promise<{ data: ScanResult }> => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post('/scan/file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => onProgress && onProgress(Math.round((e.loaded * 100) / (e.total || 1)))
  });
};

export const scanImage = (file: File): Promise<{ data: ScanResult }> => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post('/scan/image', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
};

export const getScanResult = (scanId: string): Promise<{ data: ScanResult }> =>
  api.get(`/scan/${scanId}`);

export const getHistory = (params?: { page?: number; limit?: number; search?: string; threat_level?: string; scan_type?: string }): Promise<{ data: { items: ScanHistoryItem[]; total: number; page: number; pages: number } }> =>
  api.get('/history', { params });

export const deleteScan = (scanId: string): Promise<void> =>
  api.delete(`/history/${scanId}`);

export const getDashboardStats = (): Promise<{ data: DashboardStats }> =>
  api.get('/dashboard/stats');

export const getAwarenessCategories = (): Promise<{ data: AwarenessCategory[] }> =>
  api.get('/awareness/categories');

export const getAwarenessContent = (slug: string): Promise<{ data: AwarenessContent }> =>
  api.get(`/awareness/${slug}`);

export const getQuizQuestions = (level: string, count: number = 10): Promise<{ data: QuizQuestion[] }> =>
  api.get('/quiz/questions', { params: { level, count } });

export const submitQuiz = (answers: { question_id: string; selected_answer: number }[], level: string): Promise<{ data: { score: number; total: number; results: any[] } }> =>
  api.post('/quiz/submit', { answers, level });

export const getReport = (scanId: string): Promise<{ data: ScanResult }> =>
  api.get(`/report/${scanId}`);

export const downloadPdfReport = async (scanId: string) => {
  const response = await api.get(`/report/${scanId}/pdf`, { responseType: 'blob' });
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `cyber-sentinel-report-${scanId}.pdf`);
  document.body.appendChild(link);
  link.click();
  link.remove();
};
