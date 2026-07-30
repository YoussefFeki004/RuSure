import React from 'react';
import './StatsCards.css';

const TotalIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect x="3" y="3" width="7" height="7" rx="1" stroke="#58a6ff" strokeWidth="2"/>
    <rect x="14" y="3" width="7" height="7" rx="1" stroke="#58a6ff" strokeWidth="2"/>
    <rect x="3" y="14" width="7" height="7" rx="1" stroke="#58a6ff" strokeWidth="2"/>
    <rect x="14" y="14" width="7" height="7" rx="1" stroke="#58a6ff" strokeWidth="2"/>
  </svg>
);

const TPIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M20 6L9 17L4 12" stroke="#3fb950" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

const FPIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M18 6L6 18M6 6L18 18" stroke="#f85149" strokeWidth="2" strokeLinecap="round"/>
  </svg>
);

const INCIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="#d29922" strokeWidth="2"/>
    <path d="M12 8V12" stroke="#d29922" strokeWidth="2" strokeLinecap="round"/>
    <path d="M12 16H12.01" stroke="#d29922" strokeWidth="2" strokeLinecap="round"/>
  </svg>
);

function StatsCards({ history }) {
  const calculateStats = () => {
    let totalTP = 0, totalFP = 0, totalINC = 0;
    history.forEach(entry => {
      if (entry.results) {
        totalTP += entry.results.true_positives || 0;
        totalFP += entry.results.false_positives || 0;
        totalINC += entry.results.inconclusive || 0;
      }
    });
    return {
      totalScans: history.length,
      totalTP,
      totalFP,
      totalINC
    };
  };

  const stats = calculateStats();

  return (
    <div className="stats-grid">
      <div className="stat-card">
        <div className="stat-icon"><TotalIcon /></div>
        <div className="stat-content">
          <div className="stat-number">{stats.totalScans}</div>
          <div className="stat-label">Total Scans</div>
        </div>
      </div>
      <div className="stat-card stat-tp">
        <div className="stat-icon"><TPIcon /></div>
        <div className="stat-content">
          <div className="stat-number">{stats.totalTP}</div>
          <div className="stat-label">True Positives</div>
        </div>
      </div>
      <div className="stat-card stat-fp">
        <div className="stat-icon"><FPIcon /></div>
        <div className="stat-content">
          <div className="stat-number">{stats.totalFP}</div>
          <div className="stat-label">False Positives</div>
        </div>
      </div>
      <div className="stat-card stat-inc">
        <div className="stat-icon"><INCIcon /></div>
        <div className="stat-content">
          <div className="stat-number">{stats.totalINC}</div>
          <div className="stat-label">Inconclusive</div>
        </div>
      </div>
    </div>
  );
}

export default StatsCards;
