import React, { useState, useRef, useEffect } from 'react';
import UploadSection from './UploadSection';
import ConfigSection from './ConfigSection';
import ProgressSection from './ProgressSection';
import ResultsSection from './ResultsSection';
import { uploadFiles, runScan, getStatus, getResults } from '../services/api';
import './Scanner.css';

function Scanner({ scannerType, scanId: initialScanId, onBack, onScanComplete, onSelectScanner, onChangeScanner }) {
  const [scanId, setScanId] = useState(initialScanId || null);
  const [xmlFile, setXmlFile] = useState(null);
  const [payloadsFile, setPayloadsFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState({ message: '', type: '' });
  const [config, setConfig] = useState({
    cookie: '',
    headers: '',
    proxy: '',
    baseUrl: '',
    payloadsPath: '',
    dbms: '',
    options: {}
  });
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState({ percentage: 0, status: '', logs: [] });
  const [results, setResults] = useState(null);
  const [loadingResults, setLoadingResults] = useState(false);
  const [isViewing, setIsViewing] = useState(false);
  const pollInterval = useRef(null);

  // If no scanner type selected, show selection screen
  if (!scannerType && !initialScanId) {
    return (
      <div className="scanner-page">
        <div className="scanner-header">
          <button className="back-button" onClick={onBack}>
            ← Back to Dashboard
          </button>
          <div className="scanner-title">
            <h1>Scanner</h1>
          </div>
        </div>
        <div className="scanner-content">
          <div className="scanner-selection-container">
            <div className="scanner-selection-header">
              <h2>Select Scanner Type</h2>
              <p>Choose which vulnerability scanner to use</p>
            </div>
            <div className="scanner-selection-grid">
              <div 
                className="scanner-selection-card sqli-card"
                onClick={() => onSelectScanner('sqli')}
              >
                <div className="scanner-selection-icon">
                  <svg width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect x="3" y="4" width="18" height="16" rx="2" stroke="#58a6ff" strokeWidth="2"/>
                    <path d="M7 8H17M7 12H14M7 16H11" stroke="#58a6ff" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                </div>
                <h3>SQL Injection Scanner</h3>
                <p>Test for SQL Injection vulnerabilities</p>
                <div className="scanner-features">
                  <span>Union-based</span>
                  <span>Error-based</span>
                  <span>Blind</span>
                  <span>Time-based</span>
                </div>
              </div>
              <div 
                className="scanner-selection-card xss-card"
                onClick={() => onSelectScanner('xss')}
              >
                <div className="scanner-selection-icon">
                  <svg width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="12" cy="12" r="9" stroke="#f85149" strokeWidth="2"/>
                    <path d="M9 9L15 15M15 9L9 15" stroke="#f85149" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                </div>
                <h3>Cross-Site Scripting Scanner</h3>
                <p>Test for XSS vulnerabilities</p>
                <div className="scanner-features">
                  <span>Reflected</span>
                  <span>Stored</span>
                  <span>DOM-based</span>
                  <span>All inputs</span>
                </div>
              </div>
            </div>
          </div>
          <div className="specification-notice scanner-notice">
            <div className="notice-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="12" cy="12" r="10" stroke="#d29922" strokeWidth="2"/>
                <path d="M12 8V12M12 16H12.01" stroke="#d29922" strokeWidth="2" strokeLinecap="round"/>
              </svg>
            </div>
            <div className="notice-content">
              <strong>Note:</strong> RuSure only performs scans from Burp Suite XML reports (not encoded/encrypted). 
              Export your Burp findings as XML and upload them for verification.
            </div>
          </div>
        </div>
      </div>
    );
  }

  const scannerTitle = scannerType === 'sqli' ? 'SQL Injection Scanner' : 'Cross-Site Scripting Scanner';
  const scannerColor = scannerType === 'sqli' ? '#1f6feb' : '#da3633';
  const scannerIcon = scannerType === 'sqli' ? 'SQLi' : 'XSS';

  useEffect(() => {
    if (initialScanId) {
      setIsViewing(true);
      setScanId(initialScanId);
      loadExistingResults(initialScanId);
    }
  }, [initialScanId]);

  const loadExistingResults = async (id) => {
    setLoadingResults(true);
    try {
      const data = await getResults(id, scannerType);
      if (data && !data.error) {
        setResults(data);
        addLog(`Loaded results for scan: ${id}`);
        addLog(`Found ${data.findings?.length || 0} findings`);
      } else {
        addLog(`No results found for scan: ${id}`);
        const otherType = scannerType === 'sqli' ? 'xss' : 'sqli';
        const otherData = await getResults(id, otherType);
        if (otherData && !otherData.error) {
          setResults(otherData);
          addLog(`Found results in ${otherType} scanner`);
        } else {
          addLog('No results found in either scanner type');
        }
      }
    } catch (error) {
      console.error('Load results error:', error);
      addLog(`Error loading results: ${error.message}`);
    } finally {
      setLoadingResults(false);
    }
  };

  const getOptionsForScanner = () => {
    if (scannerType === 'sqli') {
      return [
        { id: 'verify_ssl', label: 'Verify SSL' },
        { id: 'no_early_exit', label: 'No early exit' },
        { id: 'allow_github', label: 'Allow GitHub payloads' },
        { id: 'refresh_payloads', label: 'Refresh payloads' },
        { id: 'include_secrets', label: 'Include secrets in report' }
      ];
    } else {
      return [
        { id: 'headful', label: 'Headful browser' },
        { id: 'all_inputs', label: 'Test all inputs' },
        { id: 'dom_deep', label: 'Deep DOM analysis' },
        { id: 'strict_fp', label: 'Strict false-positive filter' },
        { id: 'screenshot_fp', label: 'Screenshot false positives' },
        { id: 'no_save_http', label: "Don't save HTTP data" },
        { id: 'verbose', label: 'Verbose logging' }
      ];
    }
  };

  const handleUpload = async () => {
    if (!xmlFile) {
      setUploadStatus({ message: 'Please select an XML file', type: 'error' });
      return;
    }

    setUploadStatus({ message: 'Uploading files...', type: 'info' });

    try {
      const data = await uploadFiles(scannerType, xmlFile, payloadsFile);
      if (data.scan_id) {
        setScanId(data.scan_id);
        setIsViewing(false);
        setResults(null);
        setUploadStatus({ 
          message: `Files uploaded successfully! Scan ID: ${data.scan_id}`, 
          type: 'success' 
        });
      } else {
        setUploadStatus({ message: 'Upload failed', type: 'error' });
      }
    } catch (error) {
      setUploadStatus({ message: `Error: ${error.message}`, type: 'error' });
    }
  };

  const handleRunScan = async () => {
    if (!scanId) {
      alert('Please upload files first');
      return;
    }

    setIsRunning(true);
    setResults(null);
    // Show initial progress immediately
    setProgress({ percentage: 10, status: 'Starting scan...', logs: ['Starting scan...'] });

    try {
      const data = await runScan(scannerType, scanId, config);
      if (data.status === 'started') {
        addLog('Scan started successfully');
        addLog(`Command: ${data.cmd}`);
        startPolling();
      } else {
        addLog('Failed to start scan: ' + JSON.stringify(data));
        setIsRunning(false);
      }
    } catch (error) {
      addLog('Error: ' + error.message);
      setIsRunning(false);
    }
  };

  const startPolling = () => {
    let progressValue = 10; // Start at 10%
    let lastStatus = 'Running...';
    
    if (pollInterval.current) {
      clearInterval(pollInterval.current);
    }

    pollInterval.current = setInterval(async () => {
      try {
        const data = await getStatus(scanId, scannerType);
        
        // Update progress more aggressively
        if (data.status === 'running') {
          // Gradually increase progress
          progressValue += 15;
          if (progressValue > 90) progressValue = 90;
          
          // Update status if changed
          if (data.status !== lastStatus) {
            lastStatus = data.status;
          }
          
          setProgress(prev => ({
            ...prev,
            percentage: progressValue,
            status: 'Scanning...'
          }));
        }

        if (data.status === 'done' || data.status === 'complete') {
          clearInterval(pollInterval.current);
          setProgress(prev => ({
            ...prev,
            percentage: 100,
            status: 'Complete!'
          }));
          addLog('Scan completed successfully!');
          setIsRunning(false);
          
          // Wait a moment before loading results
          setTimeout(() => {
            loadResults();
            onScanComplete();
          }, 500);
        } else if (data.status === 'error' || data.status === 'failed') {
          clearInterval(pollInterval.current);
          setProgress(prev => ({
            ...prev,
            percentage: 100,
            status: 'Failed'
          }));
          addLog('Scan failed: ' + (data.stderr || data.error || 'Unknown error'));
          setIsRunning(false);
        } else if (data.stdout) {
          const lines = data.stdout.split('\n').filter(l => l.trim());
          if (lines.length > 0) {
            const lastLine = lines[lines.length - 1];
            // Only add if it's a new message
            setProgress(prev => {
              if (!prev.logs.includes(lastLine)) {
                return {
                  ...prev,
                  logs: [...prev.logs, `[${new Date().toLocaleTimeString()}] ${lastLine}`]
                };
              }
              return prev;
            });
          }
        }
      } catch (error) {
        console.error('Poll error:', error);
      }
    }, 1000); // Poll every 1 second (faster)
  };

  const addLog = (message) => {
    setProgress(prev => ({
      ...prev,
      logs: [...prev.logs, `[${new Date().toLocaleTimeString()}] ${message}`]
    }));
  };

  const loadResults = async () => {
    setLoadingResults(true);
    try {
      const data = await getResults(scanId, scannerType);
      if (data && !data.error) {
        setResults(data);
        addLog(`Results loaded successfully`);
        addLog(`Found ${data.findings?.length || 0} findings`);
      } else {
        addLog('Error loading results: ' + (data?.error || 'Unknown error'));
      }
    } catch (error) {
      console.error('Load results error:', error);
    } finally {
      setLoadingResults(false);
    }
  };

  const handleChangeScanner = () => {
    if (onChangeScanner) {
      onChangeScanner();
    } else {
      onSelectScanner(null);
    }
  };

  useEffect(() => {
    return () => {
      if (pollInterval.current) {
        clearInterval(pollInterval.current);
      }
    };
  }, []);

  return (
    <div className="scanner-page">
      <div className="scanner-header">
        <button className="back-button" onClick={onBack}>
          ← Back to Dashboard
        </button>
        <div className="scanner-title">
          <span className="scanner-icon">{scannerIcon}</span>
          <h1>{scannerTitle}</h1>
          <span className="scanner-badge" style={{ background: scannerColor }}>
            {scannerType.toUpperCase()}
          </span>
          <button className="change-scanner-btn" onClick={handleChangeScanner}>
            Change
          </button>
          {isViewing && scanId && (
            <span className="viewing-badge" style={{ 
              background: '#d29922', 
              color: 'white', 
              padding: '4px 12px', 
              borderRadius: '12px', 
              fontSize: '0.8rem',
              marginLeft: '10px'
            }}>
              Viewing: {scanId}
            </span>
          )}
        </div>
      </div>

      <div className="scanner-content">
        {!isViewing && (
          <UploadSection
            xmlFile={xmlFile}
            payloadsFile={payloadsFile}
            onXmlChange={setXmlFile}
            onPayloadsChange={setPayloadsFile}
            onUpload={handleUpload}
            uploadStatus={uploadStatus}
            disabled={isRunning}
          />
        )}

        {scanId && !isViewing && !isRunning && (
          <ConfigSection
            scannerType={scannerType}
            config={config}
            onConfigChange={setConfig}
            options={getOptionsForScanner()}
            disabled={isRunning}
          />
        )}

        {scanId && !isRunning && !isViewing && (
          <button 
            className="btn btn-run"
            onClick={handleRunScan}
            style={{ 
              background: scannerColor,
              color: 'white',
              border: 'none',
              padding: '14px 32px',
              fontSize: '1.1rem',
              borderRadius: '8px',
              cursor: 'pointer',
              fontWeight: '600',
              width: '100%',
              marginTop: '10px'
            }}
          >
            Run Scan
          </button>
        )}

        {isRunning && (
          <ProgressSection progress={progress} />
        )}

        {results && (
          <ResultsSection
            results={results}
            scannerType={scannerType}
            scanId={scanId}
            loading={loadingResults}
          />
        )}

        {loadingResults && (
          <div style={{ 
            textAlign: 'center', 
            padding: '40px',
            color: '#8b949e'
          }}>
            <div className="spinner"></div>
            <p>Loading results...</p>
          </div>
        )}

        {isViewing && !results && !loadingResults && (
          <div style={{ 
            textAlign: 'center', 
            padding: '60px',
            background: '#161b22',
            borderRadius: '12px',
            border: '1px dashed #1c2333'
          }}>
            <p style={{ fontSize: '1.2rem', color: '#8b949e' }}>No results found for this scan</p>
            <p style={{ color: '#8b949e', fontSize: '0.9rem' }}>The scan may not have completed or results were not saved.</p>
          </div>
        )}

        {/* Specification Notice on Scanner page */}
        <div className="specification-notice scanner-notice">
          <div className="notice-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="12" cy="12" r="10" stroke="#d29922" strokeWidth="2"/>
              <path d="M12 8V12M12 16H12.01" stroke="#d29922" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </div>
          <div className="notice-content">
            <strong>Note:</strong> RuSure only performs scans from Burp Suite XML reports (not encoded/encrypted). 
            Export your Burp findings as XML and upload them for verification.
          </div>
        </div>
      </div>
    </div>
  );
}

export default Scanner;
