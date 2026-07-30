import React from 'react';
import './ConfigSection.css';

function ConfigSection({ scannerType, config, onConfigChange, options, disabled }) {
  const handleChange = (field, value) => {
    onConfigChange(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleOptionChange = (optionId, checked) => {
    onConfigChange(prev => ({
      ...prev,
      options: {
        ...prev.options,
        [optionId]: checked
      }
    }));
  };

  // Only show DBMS selector for SQLi scanner
  const showDbmsSelector = scannerType === 'sqli';

  return (
    <div className="config-section">
      <h3>Configuration</h3>
      
      <div className="config-grid">
        <div className="config-group">
          <label htmlFor="cookie">Cookie</label>
          <textarea
            id="cookie"
            rows="2"
            placeholder="PHPSESSID=abc123; security=low"
            value={config.cookie || ''}
            onChange={(e) => handleChange('cookie', e.target.value)}
            disabled={disabled}
          />
        </div>
        <div className="config-group">
          <label htmlFor="headers">Headers (one per line)</label>
          <textarea
            id="headers"
            rows="2"
            placeholder="Authorization: Bearer token"
            value={config.headers || ''}
            onChange={(e) => handleChange('headers', e.target.value)}
            disabled={disabled}
          />
        </div>
        <div className="config-group">
          <label htmlFor="proxy">Proxy</label>
          <input
            type="text"
            id="proxy"
            placeholder="http://127.0.0.1:8080"
            value={config.proxy || ''}
            onChange={(e) => handleChange('proxy', e.target.value)}
            disabled={disabled}
          />
        </div>
        <div className="config-group">
          <label htmlFor="baseUrl">Base URL Override</label>
          <input
            type="text"
            id="baseUrl"
            placeholder="http://127.0.0.1:8080"
            value={config.baseUrl || ''}
            onChange={(e) => handleChange('baseUrl', e.target.value)}
            disabled={disabled}
          />
        </div>
        <div className="config-group config-full">
          <label htmlFor="payloadsPath">Custom Payloads Path</label>
          <input
            type="text"
            id="payloadsPath"
            placeholder="path/to/payloads.txt"
            value={config.payloadsPath || ''}
            onChange={(e) => handleChange('payloadsPath', e.target.value)}
            disabled={disabled}
          />
        </div>
        
        {/* DBMS Selector - Only for SQLi */}
        {showDbmsSelector && (
          <div className="config-group">
            <label htmlFor="dbms">DBMS Type</label>
            <select
              id="dbms"
              value={config.dbms || ''}
              onChange={(e) => handleChange('dbms', e.target.value)}
              disabled={disabled}
              style={{
                padding: '10px 12px',
                background: '#0a0e17',
                border: '1px solid #1c2333',
                borderRadius: '6px',
                color: '#e6edf3',
                fontFamily: 'inherit',
                fontSize: '0.9rem',
                width: '100%',
                cursor: disabled ? 'not-allowed' : 'pointer'
              }}
            >
              <option value="">Auto-detect</option>
              <option value="mysql">MySQL</option>
              <option value="postgresql">PostgreSQL</option>
              <option value="mssql">MSSQL</option>
              <option value="oracle">Oracle</option>
              <option value="sqlite">SQLite</option>
              <option value="generic">Generic</option>
            </select>
          </div>
        )}
      </div>

      <div className="options-group">
        <h4>Options</h4>
        <div className="options-grid">
          {options.map((option) => (
            <label key={option.id} className="option-checkbox">
              <input
                type="checkbox"
                checked={config.options[option.id] || false}
                onChange={(e) => handleOptionChange(option.id, e.target.checked)}
                disabled={disabled}
              />
              <span>{option.label}</span>
            </label>
          ))}
          {/* Add Verbose option for SQLi */}
          {scannerType === 'sqli' && (
            <label className="option-checkbox">
              <input
                type="checkbox"
                checked={config.options.verbose || false}
                onChange={(e) => handleOptionChange('verbose', e.target.checked)}
                disabled={disabled}
              />
              <span>Verbose Logging</span>
            </label>
          )}
        </div>
      </div>
    </div>
  );
}

export default ConfigSection;
