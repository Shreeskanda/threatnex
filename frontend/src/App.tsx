import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Layout from './components/Layout';

// Pages
import Dashboard from './pages/Dashboard';
import ScanCentre from './pages/ScanCentre';
import WebsiteInspector from './pages/WebsiteInspector';
import FileScanner from './pages/FileScanner';
import ImageScanner from './pages/ImageScanner';
import ThreatIntelligence from './pages/ThreatIntelligence';
import ScanHistory from './pages/ScanHistory';
import CyberAwareness from './pages/CyberAwareness';
import AwarenessDetail from './pages/AwarenessDetail';
import DigitalArrestAwareness from './pages/DigitalArrestAwareness';
import SecurityQuiz from './pages/SecurityQuiz';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Router>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 3500,
          style: {
            background: '#1f2937',
            color: '#fff',
            fontSize: '13px',
            borderRadius: '8px',
          },
          success: {
            iconTheme: {
              primary: '#10b981',
              secondary: '#fff',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#fff',
            },
          },
        }}
      />
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<ScanCentre />} />
          <Route path="/website-inspector" element={<WebsiteInspector />} />
          <Route path="/file-scanner" element={<FileScanner />} />
          <Route path="/image-scanner" element={<ImageScanner />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/awareness" element={<CyberAwareness />} />
          <Route path="/awareness/:slug" element={<AwarenessDetail />} />
          <Route path="/digital-arrest" element={<DigitalArrestAwareness />} />
          <Route path="/quiz" element={<SecurityQuiz />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </Router>
  );
}
