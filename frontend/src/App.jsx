import React, { useState, useEffect } from 'react';
import Navigation from './components/Navigation';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import WelcomeScreen from './components/WelcomeScreen';
import { getHistory } from './services/api';
import './App.css';

function App() {
  const [showWelcome, setShowWelcome] = useState(true);
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [scannerType, setScannerType] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [viewScanId, setViewScanId] = useState(null);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const data = await getHistory();
      setHistory(data);
    } catch (error) {
      console.error('Error loading history:', error);
      setHistory([
        { 
          scan_id: '2c1947a5', 
          scan_type: 'XSS', 
          status: 'xss_complete', 
          timestamp: '2026-06-18T10:25:00',
          results: { true_positives: 6, false_positives: 0, inconclusive: 0 } 
        },
        { 
          scan_id: '18bddd75', 
          scan_type: 'SQLi', 
          status: 'sqli_complete', 
          timestamp: '2026-06-18T13:03:00',
          results: { true_positives: 0, false_positives: 0, inconclusive: 3 } 
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectScanner = (type) => {
    console.log('🔍 Selecting scanner:', type);
    setScannerType(type);
    setViewScanId(null);
    setCurrentPage('scanner');
  };

  const handleViewScan = (scanId, type) => {
    console.log('👁️ Viewing scan:', scanId, 'Type:', type);
    setScannerType(type || 'sqli');
    setViewScanId(scanId);
    setCurrentPage('scanner');
  };

  const handleScanComplete = () => {
    loadHistory();
  };

  const handleNavigate = (page) => {
    if (page === 'scanner') {
      setCurrentPage('scanner');
      return;
    }
    setCurrentPage(page);
  };

  const handleWelcomeComplete = () => {
    setShowWelcome(false);
  };

  const handleBackToDashboard = () => {
    setCurrentPage('dashboard');
    setViewScanId(null);
  };

  const handleChangeScanner = () => {
    console.log('🔄 Changing scanner - resetting type');
    setScannerType(null);
    setViewScanId(null);
    setCurrentPage('scanner');
  };

  if (showWelcome) {
    return <WelcomeScreen onComplete={handleWelcomeComplete} />;
  }

  return (
    <div className="app">
      <div className="glow-orb-1"></div>
      <div className="glow-orb-2"></div>
      <div className="glow-orb-3"></div>
      
      <div className="particle-bg">
        <div className="particle-dot"></div>
        <div className="particle-dot"></div>
        <div className="particle-dot"></div>
        <div className="particle-dot"></div>
        <div className="particle-dot"></div>
        <div className="particle-dot"></div>
        <div className="particle-dot"></div>
        <div className="particle-dot"></div>
      </div>

      <Navigation 
        currentPage={currentPage}
        onNavigate={handleNavigate}
      />
      <main className="main-content">
        {currentPage === 'dashboard' ? (
          <Dashboard 
            history={history}
            loading={loading}
            onSelectScanner={handleSelectScanner}
            onHistoryUpdate={loadHistory}
            onViewScan={handleViewScan}
          />
        ) : (
          <Scanner 
            key={scannerType || 'selection'} // Force re-render when scannerType changes
            scannerType={scannerType}
            scanId={viewScanId}
            onBack={handleBackToDashboard}
            onScanComplete={handleScanComplete}
            onSelectScanner={handleSelectScanner}
            onChangeScanner={handleChangeScanner}
          />
        )}
      </main>
    </div>
  );
}

export default App;
