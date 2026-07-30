import React, { useState } from 'react';
import FindingCard from './FindingCard';
import './ResultsSection.css';

function ResultsSection({ results, scannerType, scanId, loading }) {
  const [expandedFindings, setExpandedFindings] = useState({});
  const [expandedPayloads, setExpandedPayloads] = useState({});

  if (loading) {
    return (
      <div className="results-section">
        <div className="results-loading">
          <div className="spinner"></div>
          <span>Loading results...</span>
        </div>
      </div>
    );
  }

  if (!results || !results.findings || results.findings.length === 0) {
    return (
      <div className="results-section">
        <h3>Results</h3>
        <p className="no-findings">No findings in results</p>
      </div>
    );
  }

  const summary = results.summary || {};
  const findings = results.findings;

  const toggleFinding = (index) => {
    setExpandedFindings(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  const togglePayload = (findingIdx, payloadIdx) => {
    const key = `${findingIdx}-${payloadIdx}`;
    setExpandedPayloads(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const getBadgeClass = (classification) => {
    if (classification === 'TRUE_POSITIVE' || classification === 'CONFIRMED') {
      return 'badge-tp';
    } else if (classification === 'FALSE_POSITIVE') {
      return 'badge-fp';
    }
    return 'badge-inc';
  };

  const getBadgeText = (classification) => {
    if (classification === 'TRUE_POSITIVE' || classification === 'CONFIRMED') {
      return 'TP';
    } else if (classification === 'FALSE_POSITIVE') {
      return 'FP';
    }
    return 'INC';
  };

  // Calculate statistics
  const totalFindings = findings.length;
  const truePositives = findings.filter(f => f.classification === 'TRUE_POSITIVE').length;
  const falsePositives = findings.filter(f => f.classification === 'FALSE_POSITIVE').length;
  const inconclusive = findings.filter(f => f.classification === 'INCONCLUSIVE' || f.classification === 'UNREACHABLE').length;

  return (
    <div className="results-section">
      <h3>Results</h3>
      
      <div className="results-summary">
        <div className="result-stat total">
          <div className="number">{summary.totalFindings || totalFindings || 0}</div>
          <div className="label">Total Findings</div>
        </div>
        <div className="result-stat tp">
          <div className="number">{summary.truePositives || truePositives || 0}</div>
          <div className="label">True Positives</div>
        </div>
        <div className="result-stat fp">
          <div className="number">{summary.falsePositives || falsePositives || 0}</div>
          <div className="label">False Positives</div>
        </div>
        <div className="result-stat inc">
          <div className="number">{summary.inconclusive || inconclusive || 0}</div>
          <div className="label">Inconclusive</div>
        </div>
      </div>

      <div className="findings-container">
        {findings.map((finding, index) => (
          <FindingCard
            key={index}
            finding={finding}
            index={index}
            scannerType={scannerType}
            scanId={scanId}
            isExpanded={expandedFindings[index] || false}
            onToggle={() => toggleFinding(index)}
            badgeClass={getBadgeClass(finding.classification)}
            badgeText={getBadgeText(finding.classification)}
            onPayloadToggle={togglePayload}
            expandedPayloads={expandedPayloads}
          />
        ))}
      </div>
    </div>
  );
}

export default ResultsSection;
