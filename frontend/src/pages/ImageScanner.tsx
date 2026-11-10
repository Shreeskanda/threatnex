import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Image as ImageIcon, QrCode, FileSearch, ShieldCheck } from 'lucide-react';
import { scanImage } from '../services/api';
import type { ScanResult } from '../types';
import ScanResultView from '../components/ScanResultView';
import ScanProgress from '../components/ScanProgress';
import toast from 'react-hot-toast';

export default function ImageScanner() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      const file = acceptedFiles[0];
      setSelectedFile(file);
      setPreviewUrl(URL.createObjectURL(file));
      setResult(null);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    maxSize: 10 * 1024 * 1024,
    accept: {
      'image/*': ['.png', '.jpg', '.jpeg', '.webp', '.bmp']
    }
  });

  const handleScan = async () => {
    if (!selectedFile) {
      toast.error('Please select an image to scan');
      return;
    }

    setLoading(true);

    try {
      const res = await scanImage(selectedFile);
      setResult(res.data);
      toast.success('Image & QR analysis complete');
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to scan image.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="card border-l-4 border-l-blue-600">
        <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <ImageIcon className="w-5 h-5 text-blue-600" />
          Image, Screenshot & QR Code Scanner
        </h1>
        <p className="text-sm text-gray-600 mt-1">
          Detects Quishing (QR Phishing) payloads, decodes payment URIs, performs OCR to uncover scam text,
          fraudulent banking alerts, and fake digital arrest notices within screenshots.
        </p>

        {/* Dropzone */}
        <div
          {...getRootProps()}
          className={`mt-5 border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
            isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400 bg-gray-50'
          }`}
        >
          <input {...getInputProps()} />
          <div className="flex justify-center gap-3 mb-3">
            <ImageIcon className="w-9 h-9 text-gray-400" />
            <QrCode className="w-9 h-9 text-gray-400" />
          </div>
          <p className="text-sm font-semibold text-gray-800">
            {isDragActive ? 'Drop image here' : 'Drag & drop image or QR screenshot, or click to browse'}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Supported formats: PNG, JPG, JPEG, WEBP (Max 10 MB)
          </p>
        </div>

        {/* Preview & Controls */}
        {selectedFile && previewUrl && (
          <div className="mt-4 p-4 bg-white border border-gray-200 rounded-lg flex flex-col md:flex-row items-center gap-5">
            <div className="w-32 h-32 rounded-lg overflow-hidden border border-gray-200 bg-gray-50 flex-shrink-0">
              <img src={previewUrl} alt="Preview" className="w-full h-full object-cover" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-medium text-gray-900">{selectedFile.name}</p>
              <p className="text-xs text-gray-500 mt-0.5">
                {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.type}
              </p>
              <div className="mt-3 flex items-center gap-2">
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-blue-50 text-blue-700 font-medium">
                  <QrCode className="w-3 h-3" /> QR Decoder Active
                </span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-indigo-50 text-indigo-700 font-medium">
                  <FileSearch className="w-3 h-3" /> OCR Text Engine Active
                </span>
              </div>
            </div>
            <button
              onClick={handleScan}
              disabled={loading}
              className="btn-primary"
            >
              {loading ? 'Processing OCR & QR...' : 'Scan Image Now'}
            </button>
          </div>
        )}
      </div>

      {loading && <ScanProgress step="Decoding QR matrix, running OCR character extraction, and scoring threats..." />}

      {result && <ScanResultView result={result} />}
    </div>
  );
}
