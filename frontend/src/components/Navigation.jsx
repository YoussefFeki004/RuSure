import React from 'react';
import './Navigation.css';

const ShieldIcon = () => (
  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke="#58a6ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    <path d="M12 8V12M12 16H12.01" stroke="#58a6ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

const DashboardIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect x="3" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="2"/>
    <rect x="14" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="2"/>
    <rect x="3" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="2"/>
    <rect x="14" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="2"/>
  </svg>
);

const ScanIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="2"/>
    <path d="M21 3L16 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M3 21L8 16" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    <path d="M12 8V12L14 14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
  </svg>
);

function Navigation({ currentPage, onNavigate }) {
  return (
    <nav className="navbar">
      <div className="nav-brand">
        <ShieldIcon />
        <span className="brand-text">RuSure</span>
      </div>
      <div className="nav-links">
        <button
          className={`nav-link ${currentPage === 'dashboard' ? 'active' : ''}`}
          onClick={() => onNavigate('dashboard')}
        >
          <DashboardIcon />
          Dashboard
        </button>
        <button
          className={`nav-link ${currentPage === 'scanner' ? 'active' : ''}`}
          onClick={() => onNavigate('scanner')}
        >
          <ScanIcon />
          Scanner
        </button>
      </div>
    </nav>
  );
}

export default Navigation;
