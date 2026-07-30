import React, { useState } from 'react';
import { deleteScan } from '../services/api';
import './HistoryTable.css';

const ViewIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" strokeWidth="2"/>
    <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="2"/>
  </svg>
);

const DeleteIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M3 6H5H21" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M8 6V4C8 3.44772 8.44772 3 9 3H15C15.5523 3 16 3.44772 16 4V6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M19 6L18 19C17.968 19.546 17.653 20 17 20H7C6.347 20 6.032 19.546 6 19L5 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M10 10V16" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M14 10V16" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
  </svg>
);

function HistoryTable({ history, loading, onHistoryUpdate, onViewScan }) {
  const [deleting, setDeleting] = useState(null);

  const handleDelete = async (scanId) => {
    if (!window.confirm(`Delete scan ${scanId}?`)) return;
    
    setDeleting(scanId);
    try {
      await deleteScan(scanId);
      onHistoryUpdate();
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Error deleting scan');
    } finally {
      setDeleting(null);
    }
  };

  const handleView = (entry) => {
    if (onViewScan) {
      let scannerType = 'sqli';
      if (entry.scan_type === 'XSS' || entry.status?.includes('xss')) {
        scannerType = 'xss';
      }
      onViewScan(entry.scan_id, scannerType);
    }
  };

  const getScanType = (entry) => {
    if (entry.scan_type && entry.scan_type !== 'Upload') {
      return entry.scan_type;
    }
    if (entry.status) {
      if (entry.status.includes('sqli') || entry.status.includes('sql')) {
        return 'SQLi';
      }
      if (entry.status.includes('xss')) {
        return 'XSS';
      }
    }
    return 'Unknown';
  };

  if (loading) {
    return (
      <div className="table-loading">
        <div className="spinner"></div>
        <span>Loading history...</span>
      </div>
    );
  }

  if (!history || history.length === 0) {
    return (
      <div className="table-empty">
        <p>No scans in history</p>
      </div>
    );
  }

  const getStatusBadge = (status) => {
    if (status === 'uploaded') return 'status-uploaded';
    if (status === 'sqli_running' || status === 'xss_running') return 'status-running';
    if (status === 'sqli_complete' || status === 'xss_complete') return 'status-complete';
    if (status === 'sqli_failed' || status === 'xss_failed') return 'status-failed';
    // If it contains 'complete' but not sqli/xss prefix, treat as complete
    if (status && status.includes('complete')) return 'status-complete';
    return 'status-unknown';
  };

  const getStatusText = (status) => {
    if (status === 'uploaded') return 'Uploaded';
    if (status === 'sqli_running' || status === 'xss_running') return 'Running...';
    if (status === 'sqli_complete' || status === 'xss_complete') return 'Complete';
    if (status === 'sqli_failed' || status === 'xss_failed') return 'Failed';
    // If it contains 'complete', show Complete
    if (status && status.includes('complete')) return 'Complete';
    return status;
  };

  const getTypeBadgeStyle = (type) => {
    if (type === 'SQLi') {
      return { background: 'rgba(31, 111, 235, 0.2)', color: '#58a6ff', border: '1px solid #1f6feb' };
    } else if (type === 'XSS') {
      return { background: 'rgba(218, 54, 51, 0.2)', color: '#f85149', border: '1px solid #da3633' };
    } else {
      return { background: 'rgba(139, 148, 158, 0.2)', color: '#8b949e', border: '1px solid #6e7681' };
    }
  };

  return (
    <div className="table-container">
      <table className="history-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Status</th>
            <th>TP</th>
            <th>FP</th>
            <th>INC</th>
            <th>Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {history.map((entry) => {
            const scanType = getScanType(entry);
            const typeStyle = getTypeBadgeStyle(scanType);
            
            return (
              <tr key={entry.scan_id}>
                <td>
                  <code className="scan-id">{entry.scan_id}</code>
                </td>
                <td>
                  <span style={{
                    display: 'inline-block',
                    padding: '2px 10px',
                    borderRadius: '12px',
                    fontSize: '0.7rem',
                    fontWeight: '600',
                    ...typeStyle
                  }}>
                    {scanType}
                  </span>
                </td>
                <td>
                  <span className={`status-badge ${getStatusBadge(entry.status)}`}>
                    {getStatusText(entry.status)}
                  </span>
                </td>
                <td className="tp-count">{entry.results?.true_positives || 0}</td>
                <td className="fp-count">{entry.results?.false_positives || 0}</td>
                <td className="inc-count">{entry.results?.inconclusive || 0}</td>
                <td className="timestamp">
                  {entry.timestamp ? entry.timestamp.slice(0, 16).replace('T', ' ') : '-'}
                </td>
                <td>
                  <button 
                    className="btn btn-sm btn-view"
                    onClick={() => handleView(entry)}
                  >
                    <ViewIcon />
                    View
                  </button>
                  <button 
                    className="btn btn-sm btn-delete"
                    onClick={() => handleDelete(entry.scan_id)}
                    disabled={deleting === entry.scan_id}
                  >
                    <DeleteIcon />
                    {deleting === entry.scan_id ? '...' : 'Delete'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default HistoryTable;
