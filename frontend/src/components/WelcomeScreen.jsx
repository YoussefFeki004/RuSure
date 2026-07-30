import React, { useState, useEffect } from 'react';
import './WelcomeScreen.css';

function WelcomeScreen({ onComplete }) {
  const [fadeOut, setFadeOut] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + 1;
      });
    }, 20);

    const timer = setTimeout(() => {
      setFadeOut(true);
      setTimeout(() => {
        onComplete();
      }, 800);
    }, 2500);

    return () => {
      clearInterval(interval);
      clearTimeout(timer);
    };
  }, [onComplete]);

  return (
    <div className={`welcome-screen ${fadeOut ? 'fade-out' : ''}`}>
      <div className="welcome-content">
        <div className="logo-container">
          <svg className="shield-logo" width="120" height="120" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke="#58a6ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <animate attributeName="stroke-dasharray" from="0 100" to="100 100" dur="1.5s" fill="freeze"/>
            </path>
            <path d="M12 8V12M12 16H12.01" stroke="#58a6ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <animate attributeName="opacity" from="0" to="1" dur="1s" begin="0.8s" fill="freeze"/>
            </path>
            <circle cx="12" cy="12" r="2" fill="#58a6ff">
              <animate attributeName="r" from="0" to="2" dur="0.5s" begin="1s" fill="freeze"/>
              <animate attributeName="opacity" from="0" to="1" dur="0.5s" begin="1s" fill="freeze"/>
            </circle>
          </svg>
          <div className="pulse-ring"></div>
        </div>

        <h1 className="welcome-title">
          <span className="title-char">R</span>
          <span className="title-char">u</span>
          <span className="title-char">S</span>
          <span className="title-char">u</span>
          <span className="title-char">r</span>
          <span className="title-char">e</span>
        </h1>
        <p className="welcome-subtitle">Vulnerability Verification Tool</p>

        <div className="progress-container">
          <div className="progress-bar" style={{ width: `${progress}%` }}>
            <div className="progress-shimmer"></div>
          </div>
        </div>
        <p className="loading-text">Loading...</p>

        <div className="particles">
          {[...Array(20)].map((_, i) => (
            <div
              key={i}
              className="particle"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 2}s`,
                animationDuration: `${2 + Math.random() * 3}s`,
                width: `${2 + Math.random() * 4}px`,
                height: `${2 + Math.random() * 4}px`,
              }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

export default WelcomeScreen;
