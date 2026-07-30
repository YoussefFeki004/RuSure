import React, { useRef, useEffect } from 'react';
import './ProgressSection.css';

function ProgressSection({ progress }) {
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress.logs]);

  return (
    <div className="progress-section">
      <h3>Scan Progress</h3>
      <div className="progress-bar-container">
        <div 
          className="progress-bar" 
          style={{ width: `${progress.percentage}%` }}
        ></div>
      </div>
      <div className="progress-text">
        <span>{progress.status}</span>
        <span>{progress.percentage}%</span>
      </div>
      <div className="progress-log" ref={logRef}>
        {progress.logs.map((log, index) => (
          <div key={index} className="log-entry">
            {log}
          </div>
        ))}
      </div>
    </div>
  );
}

export default ProgressSection;
