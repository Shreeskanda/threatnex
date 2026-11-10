import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Globe, FileText, Image, AlignLeft, Upload, X, Loader2 } from 'lucide-react';
import { scanUrl, scanFile, scanImage, scanText } from '../services/api';
import type { ScanResult } from '../types';
import ScanProgress from '../components/ScanProgress';
import ScanResultView from '../components/ScanResultView';
import toast from 'react-hot-toast';
import clsx from 'clsx';

type Tab = 'url' | 'file' | 'image' | 'text';

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'url', label: 'URL Scanner', icon: Globe },
  { id: 'file', label: 'File Scanner', icon: FileText },
  { id: 'image', label: 'Image Scanner', icon: Image },
  { id: 'text', label: 'Text Analyzer', icon: AlignLeft },
];

function UrlTab({ onResult }: { onResult: (r: ScanResult) => void }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    try {
      const res = await scanUrl(url.trim());
      onResult(res.data);
      toast.success('URL scan complete');
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'URL scan failed');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <ScanProgress />;

  return (
    <form onSubmit={handleScan} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1.5">Website URL to scan</label>
        <div className="flex gap-3">
          <input
            type="url"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="flex-1 border border-gray-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button type="submit" disabled={!url.trim()} className="btn-primary flex items-center gap-2 whitespace-nowrap">
            <Globe className="w-4 h-4" />
            Scan URL
          </button>
        </div>
      </div>
      <p className="text-xs text-gray-500">Checks domain info, security headers, SSL, threat databases, and more.</p>
    </form>
  );
}

function FileTab({ onResult }: { onResult: (r: ScanResult) => void }) {
  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const onDrop = useCallback((accepted: File[]) => {
    setFiles(prev => [...prev, ...accepted].slice(0, 1));
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'application/vnd.ms-excel': ['.xls'],
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
      'text/plain': ['.txt'],
      'application/zip': ['.zip'],
      'application/x-zip-compressed': ['.zip'],
      'application/octet-stream': ['.exe', '.dll', '.apk'],
    },
    maxFiles: 1,
  });

  const handleScan = async () => {
    if (!files[0]) return;
    setLoading(true);
    setProgress(0);
    try {
      const res = await scanFile(files[0], setProgress);
      onResult(res.data);
      toast.success('File scan complete');
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'File scan failed');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <ScanProgress step={`Uploading... ${progress}%`} />;

  return (
    <div className="space-y-4">
      <div
        {...getRootProps()}
        className={clsx(
          'border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors',
          isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-blue-300 hover:bg-gray-50'
        )}
      >
        <input {...getInputProps()} />
        <Upload className="w-10 h-10 text-gray-300 mx-auto mb-3" />
        <p className="font-medium text-gray-700">{isDragActive ? 'Drop file here...' : 'Drag & drop a file, or click to browse'}</p>
        <p className="text-xs text-gray-400 mt-2">PDF, DOC, DOCX, XLS, XLSX, TXT, ZIP, EXE, APK</p>
      </div>

      {files.length > 0 && (
        <div className="space-y-2">
          {files.map((f, i) => (
            <div key={i} className="flex items-center gap-3 bg-blue-50 border border-blue-200 rounded-lg px-4 py-2.5">
              <FileText className="w-4 h-4 text-blue-600 flex-shrink-0" />
              <span className="text-sm font-medium text-gray-700 flex-1 min-w-0 truncate">{f.name}</span>
              <span className="text-xs text-gray-500">{(f.size / 1024).toFixed(1)} KB</span>
              <button onClick={() => setFiles([])} className="text-gray-400 hover:text-red-600">
                <X className="w-4 h-4" />
              </button>
            </div>
          ))}
          <button onClick={handleScan} className="btn-primary w-full flex items-center justify-center gap-2">
            <FileText className="w-4 h-4" />
            Analyze File
          </button>
        </div>
      )}
    </div>
  );
}

function ImageTab({ onResult }: { onResult: (r: ScanResult) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState('');
  const [loading, setLoading] = useState(false);

  const onDrop = useCallback((accepted: File[]) => {
    if (accepted[0]) {
      setFile(accepted[0]);
      setPreview(URL.createObjectURL(accepted[0]));
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'image/*': ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'] },
    maxFiles: 1,
  });

  const handleScan = async () => {
    if (!file) return;
    setLoading(true);
    try {
      const res = await scanImage(file);
      onResult(res.data);
      toast.success('Image scan complete');
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Image scan failed');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <ScanProgress step="Analyzing image content..." />;

  return (
    <div className="space-y-4">
      <div
        {...getRootProps()}
        className={clsx(
          'border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors',
          isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-blue-300 hover:bg-gray-50'
        )}
      >
        <input {...getInputProps()} />
        <Image className="w-10 h-10 text-gray-300 mx-auto mb-3" />
        <p className="font-medium text-gray-700">{isDragActive ? 'Drop image here...' : 'Drag & drop an image, or click to browse'}</p>
        <p className="text-xs text-gray-400 mt-2">JPG, PNG, GIF, WebP, BMP, TIFF</p>
      </div>

      {preview && (
        <div className="space-y-3">
          <div className="relative">
            <img src={preview} alt="Preview" className="w-full max-h-48 object-contain rounded-lg border border-gray-200 bg-gray-50" />
            <button
              onClick={() => { setFile(null); setPreview(''); }}
              className="absolute top-2 right-2 bg-white rounded-full p-1 shadow text-gray-500 hover:text-red-600"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <button onClick={handleScan} className="btn-primary w-full flex items-center justify-center gap-2">
            <Image className="w-4 h-4" />
            Analyze Image
          </button>
        </div>
      )}
    </div>
  );
}

function TextTab({ onResult }: { onResult: (r: ScanResult) => void }) {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return;
    setLoading(true);
    try {
      const res = await scanText(text.trim());
      onResult(res.data);
      toast.success('Text analysis complete');
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Text analysis failed');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <ScanProgress step="Analyzing text for threats..." />;

  return (
    <form onSubmit={handleScan} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1.5">Text to analyze</label>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Paste suspicious text, email content, SMS message, or any text to analyze..."
          rows={8}
          className="w-full border border-gray-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none font-mono"
        />
        <div className="text-xs text-gray-400 mt-1 text-right">{text.length} characters</div>
      </div>
      <button type="submit" disabled={!text.trim()} className="btn-primary flex items-center gap-2">
        <AlignLeft className="w-4 h-4" />
        Analyze Text
      </button>
    </form>
  );
}

export default function ScanCentre() {
  const [activeTab, setActiveTab] = useState<Tab>('url');
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleResult = (r: ScanResult) => {
    setResult(r);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleTabChange = (tab: Tab) => {
    setActiveTab(tab);
    setResult(null);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Scan Centre</h1>
        <p className="text-sm text-gray-500 mt-1">Analyze URLs, files, images, and text for cyber threats</p>
      </div>

      {/* Tab bar */}
      <div className="card p-0 overflow-hidden">
        <div className="flex border-b border-gray-200">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => handleTabChange(tab.id)}
              className={clsx(
                'flex-1 flex items-center justify-center gap-2 px-4 py-3.5 text-sm font-medium transition-colors border-b-2',
                activeTab === tab.id
                  ? 'border-blue-700 text-blue-700 bg-blue-50'
                  : 'border-transparent text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              )}
            >
              <tab.icon className="w-4 h-4" />
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          ))}
        </div>
        <div className="p-5">
          {activeTab === 'url' && <UrlTab onResult={handleResult} />}
          {activeTab === 'file' && <FileTab onResult={handleResult} />}
          {activeTab === 'image' && <ImageTab onResult={handleResult} />}
          {activeTab === 'text' && <TextTab onResult={handleResult} />}
        </div>
      </div>

      {/* Results */}
      {result && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-gray-900">Scan Results</h2>
            <button onClick={() => setResult(null)} className="btn-secondary text-xs flex items-center gap-1.5">
              <X className="w-3.5 h-3.5" />
              Clear
            </button>
          </div>
          <ScanResultView result={result} />
        </div>
      )}
    </div>
  );
}
