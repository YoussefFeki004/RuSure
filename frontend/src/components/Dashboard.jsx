import React from 'react';
import StatsCards from './StatsCards';
import HistoryTable from './HistoryTable';
import './Dashboard.css';

const TrashIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M3 6H5H21" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M8 6V4C8 3.44772 8.44772 3 9 3H15C15.5523 3 16 3.44772 16 4V6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M19 6L18 19C17.968 19.546 17.653 20 17 20H7C6.347 20 6.032 19.546 6 19L5 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M10 10V16" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M14 10V16" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
  </svg>
);

function Dashboard({ history, loading, onSelectScanner, onHistoryUpdate, onViewScan }) {
  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <p>Overview of all scans and findings</p>
      </div>

      <StatsCards history={history} />

      <div className="history-section">
        <div className="history-header">
          <h2>Scan History</h2>
          <button 
            className="btn btn-danger btn-sm"
            onClick={() => {
              if (window.confirm('Delete ALL scans and history? This cannot be undone!')) {
                onHistoryUpdate();
              }
            }}
          >
            <TrashIcon />
            Clear All
          </button>
        </div>
        <HistoryTable 
          history={history} 
          loading={loading}
          onHistoryUpdate={onHistoryUpdate}
          onViewScan={onViewScan}
        />
      </div>

      {/* Specification Notice */}
      <div className="specification-notice">
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
  );
}

export default Dashboard;
