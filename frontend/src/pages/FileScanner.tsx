import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { FileUp, FileText, AlertCircle, Shield, CheckCircle2 } from 'lucide-react';
import { scanFile } from '../services/api';
import type { ScanResult } from '../types';
import ScanResultView from '../components/ScanResultView';
import ScanProgress from '../components/ScanProgress';
import toast from 'react-hot-toast';

export default function FileScanner() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setSelectedFile(acceptedFiles[0]);
      setResult(null);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    maxSize: 15 * 1024 * 1024,
    accept: {
      'application/pdf': ['.pdf'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'application/msword': ['.doc', '.docm'],
      'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
      'application/vnd.ms-powerpoint': ['.ppt', '.pptm'],
      'text/plain': ['.txt', '.log'],
      'text/csv': ['.csv'],
      'text/html': ['.html', '.htm'],
      'application/zip': ['.zip']
    }
  });

  const handleScan = async () => {
    if (!selectedFile) {
      toast.error('Please select a file to scan');
      return;
    }

    setLoading(true);
    setUploadProgress(0);

    try {
      const res = await scanFile(selectedFile, (progress) => {
        setUploadProgress(progress);
      });
      setResult(res.data);
      toast.success('File security analysis complete');
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to analyze file. Please check format.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="card border-l-4 border-l-blue-600">
        <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <FileText className="w-5 h-5 text-blue-600" />
          Multimodal Document & File Security Scanner
        </h1>
        <p className="text-sm text-gray-600 mt-1">
          Static and heuristic parsing for documents, presentations, spreadsheets and archives. Identifies
          embedded macros, malicious JavaScript actions, obfuscated URLs, CSV formula injections, and zip slips.
        </p>

        {/* Dropzone */}
        <div
          {...getRootProps()}
          className={`mt-5 border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
            isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400 bg-gray-50'
          }`}
        >
          <input {...getInputProps()} />
          <FileUp className="w-10 h-10 text-gray-400 mx-auto mb-3" />
          <p className="text-sm font-semibold text-gray-800">
            {isDragActive ? 'Drop file here to upload' : 'Drag & drop document here, or click to browse'}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Supported formats: PDF, DOCX, PPTX, TXT, CSV, HTML, ZIP (Maximum 15 MB)
          </p>
        </div>

        {/* Selected File Details */}
        {selectedFile && (
          <div className="mt-4 p-4 bg-white border border-gray-200 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <FileText className="w-6 h-6 text-blue-600 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-gray-900">{selectedFile.name}</p>
                <p className="text-xs text-gray-500">
                  {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.type || 'Generic Document'}
                </p>
              </div>
            </div>
            <button
              onClick={handleScan}
              disabled={loading}
              className="btn-primary self-start sm:self-auto"
            >
              {loading ? 'Analyzing File...' : 'Start Security Scan'}
            </button>
          </div>
        )}
      </div>

      {/* Safety Notice */}
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-3.5 flex items-start gap-3 text-xs text-amber-900">
        <Shield className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold">Safe Isolated Extraction:</span> Files are processed strictly in isolated
          in-memory / temporary sandboxes. Embedded macros and scripts are NEVER executed. Temporary copies are wiped
          immediately following structural analysis.
        </div>
      </div>

      {loading && <ScanProgress step={`Analyzing file structures, embedded objects and hashes... (${uploadProgress}%)`} />}

      {result && <ScanResultView result={result} />}
    </div>
  );
}
