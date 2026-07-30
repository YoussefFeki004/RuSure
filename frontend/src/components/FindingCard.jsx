import React, { useState } from 'react';
import RequestResponseModal from './RequestResponseModal';
import './FindingCard.css';

function FindingCard({ 
  finding, 
  index, 
  scannerType, 
  scanId, 
  isExpanded, 
  onToggle,
  badgeClass,
  badgeText,
  onPayloadToggle,
  expandedPayloads
}) {
  const [modalOpen, setModalOpen] = useState(false);
  const [modalContent, setModalContent] = useState(null);

  const openModal = (content) => {
    setModalContent(content);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setModalContent(null);
  };

  const showFullRequest = (request) => {
    openModal({
      type: 'request',
      title: 'Full Request',
      data: { fullRequest: request }
    });
  };

  const showRequestResponse = (type, data, payload = null) => {
    const enrichedData = { ...data };
    if (payload) {
      enrichedData.payload = payload;
    }
    openModal({
      type: type,
      title: type === 'request' ? 'Request' : 'Response',
      data: enrichedData
    });
  };

  const showInjectionDetail = (payloadData) => {
    openModal({
      type: 'injection_detail',
      title: 'Injection Detail',
      data: payloadData
    });
  };

  const showInputInjections = (injections) => {
    openModal({
      type: 'injections',
      title: `Input Injections (${injections.length})`,
      data: injections
    });
  };

  const isPayloadExpanded = (payloadIdx) => {
    const key = `${index}-${payloadIdx}`;
    return expandedPayloads && expandedPayloads[key];
  };

  // Handle finding card click to toggle expansion
  const handleFindingClick = (e) => {
    // Don't toggle if clicking on a button or link
    if (e.target.closest('button') || e.target.closest('a')) {
      return;
    }
    onToggle();
  };

  if (scannerType === 'sqli') {
    return (
      <>
        {renderSqliFinding(
          finding, index, badgeClass, badgeText, 
          isExpanded, handleFindingClick, showFullRequest, showRequestResponse, 
          showInjectionDetail, isPayloadExpanded, onPayloadToggle
        )}
        <RequestResponseModal 
          isOpen={modalOpen}
          onClose={closeModal}
          content={modalContent}
        />
      </>
    );
  } else {
    return (
      <>
        {renderXssFinding(
          finding, index, badgeClass, badgeText,
          isExpanded, handleFindingClick, scanId, showRequestResponse, showInputInjections
        )}
        <RequestResponseModal 
          isOpen={modalOpen}
          onClose={closeModal}
          content={modalContent}
        />
      </>
    );
  }
}

function renderSqliFinding(finding, index, badgeClass, badgeText, isExpanded, handleFindingClick, showFullRequest, showRequestResponse, showInjectionDetail, isPayloadExpanded, onPayloadToggle) {
  return (
    <div className={`finding-card ${isExpanded ? 'expanded' : ''}`}>
      <div className="finding-header" onClick={handleFindingClick}>
        <div className="finding-title">
          #{index + 1} {finding.method} {finding.url}
        </div>
        <div className="finding-meta">
          <span className={`badge ${badgeClass}`}>{badgeText}</span>
          <span className="finding-count">{finding.payloads ? finding.payloads.length : 0} payloads</span>
          <span className="expand-icon">{isExpanded ? '▾' : '▸'}</span>
        </div>
      </div>
      
      <div className={`finding-body ${isExpanded ? 'expanded' : ''}`}>
        {isExpanded && (
          <>
            <div className="finding-info">
              <span><strong>Parameter:</strong> {finding.parameter}</span>
              <span><strong>DBMS:</strong> {finding.fingerprint?.dbms || 'unknown'} ({finding.fingerprint?.confidence || 'unknown'})</span>
              <span><strong>Evidence Score:</strong> {finding.scoring?.evidenceScore || 0}</span>
              <span><strong>Reliability:</strong> {finding.scoring?.reliabilityScore || 0}</span>
              <span><strong>Classification:</strong> {finding.classification}</span>
            </div>

            {finding.verdict && (
              <div className="verdict-box" style={{
                padding: '12px 16px',
                background: '#0d1117',
                borderLeft: `4px solid ${finding.classification === 'TRUE_POSITIVE' ? '#3fb950' : finding.classification === 'FALSE_POSITIVE' ? '#f85149' : '#d29922'}`,
                borderRadius: '4px',
                marginBottom: '16px'
              }}>
                <strong>Verdict:</strong> {finding.verdict}
              </div>
            )}

            {finding.full_requests && finding.full_requests.length > 0 && (
              <div className="action-buttons">
                <button 
                  className="btn btn-sm btn-success"
                  onClick={() => showFullRequest(finding.full_requests[0])}
                >
                  View Original Request
                </button>
              </div>
            )}

            <div className="payloads-table-wrapper">
              <table className="payloads-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Category</th>
                    <th>Payload</th>
                    <th>Status</th>
                    <th>Time</th>
                    <th>Evidence</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {(finding.payloads || []).map((p, i) => {
                    const isExpanded = isPayloadExpanded(i);
                    const hasEvidence = p.evidence && p.evidence.length > 0;
                    const isWorking = p.statusCode && p.statusCode < 400 && hasEvidence;
                    
                    return (
                      <React.Fragment key={i}>
                        <tr 
                          style={{ 
                            cursor: 'pointer',
                            background: isWorking ? 'rgba(63, 185, 80, 0.05)' : 'transparent'
                          }}
                          onClick={() => onPayloadToggle(index, i)}
                        >
                          <td>{i + 1}</td>
                          <td className="category">{p.category}</td>
                          <td className="payload" title={p.payload}>
                            {p.payload}
                          </td>
                          <td>
                            <span style={{ 
                              color: p.statusCode && p.statusCode < 400 ? '#3fb950' : '#f85149',
                              fontWeight: 'bold'
                            }}>
                              {p.statusCode || 'ERR'}
                            </span>
                          </td>
                          <td>{p.responseTimeSeconds}s</td>
                          <td>
                            {hasEvidence ? (
                              <span style={{ color: '#3fb950' }}>✓ {p.evidence.length}</span>
                            ) : (
                              <span style={{ color: '#8b949e' }}>−</span>
                            )}
                          </td>
                          <td>
                            <button 
                              className="btn btn-sm btn-secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                if (p.fullRequestSent) {
                                  const requestData = {
                                    fullRequest: p.fullRequestSent,
                                    payload: p.payload,
                                    evidence: p.evidence || [],
                                    responseSnippet: p.responseSnippet,
                                    fullResponse: p.responseBody || p.responseSnippet,
                                    statusCode: p.statusCode,
                                    responseTime: p.responseTimeSeconds,
                                    responseSize: p.responseSize
                                  };
                                  showRequestResponse('request', requestData, p.payload);
                                }
                              }}
                            >
                              View
                            </button>
                            {hasEvidence && (
                              <button 
                                className="btn btn-sm btn-success"
                                style={{ marginLeft: '4px' }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  showInjectionDetail({
                                    payload: p.payload,
                                    category: p.category,
                                    statusCode: p.statusCode,
                                    responseTime: p.responseTimeSeconds,
                                    responseSize: p.responseSize,
                                    evidence: p.evidence,
                                    fullRequest: p.fullRequestSent,
                                    responseSnippet: p.responseSnippet,
                                    fullResponse: p.responseBody || p.responseSnippet,
                                    working: isWorking
                                  });
                                }}
                              >
                                Detail
                              </button>
                            )}
                          </td>
                        </tr>
                        {isExpanded && hasEvidence && (
                          <tr>
                            <td colSpan="7" style={{ padding: '0' }}>
                              <div style={{ 
                                padding: '16px', 
                                background: '#0d1117',
                                borderTop: '1px solid #1c2333'
                              }}>
                                <div style={{ marginBottom: '12px' }}>
                                  <strong style={{ color: '#3fb950' }}>This payload worked!</strong>
                                </div>
                                <div style={{ 
                                  display: 'grid', 
                                  gridTemplateColumns: '1fr 1fr', 
                                  gap: '16px',
                                  marginBottom: '12px'
                                }}>
                                  <div>
                                    <strong style={{ color: '#8b949e', fontSize: '0.8rem' }}>Evidence:</strong>
                                    <ul style={{ 
                                      margin: '8px 0 0 0', 
                                      paddingLeft: '20px',
                                      color: '#d29922'
                                    }}>
                                      {p.evidence.map((ev, ei) => (
                                        <li key={ei} style={{ fontSize: '0.85rem' }}>{ev}</li>
                                      ))}
                                    </ul>
                                  </div>
                                  <div>
                                    <strong style={{ color: '#8b949e', fontSize: '0.8rem' }}>Response Info:</strong>
                                    <div style={{ fontSize: '0.85rem', color: '#e6edf3', marginTop: '8px' }}>
                                      <div>Status: <span style={{ color: p.statusCode && p.statusCode < 400 ? '#3fb950' : '#f85149' }}>{p.statusCode}</span></div>
                                      <div>Time: {p.responseTimeSeconds}s</div>
                                      <div>Size: {p.responseSize} bytes</div>
                                    </div>
                                  </div>
                                </div>
                                <div>
                                  <strong style={{ color: '#8b949e', fontSize: '0.8rem' }}>Payload Injected:</strong>
                                  <pre style={{
                                    background: '#0a0e17',
                                    padding: '12px',
                                    borderRadius: '4px',
                                    border: '1px solid #1c2333',
                                    color: '#f0883e',
                                    fontSize: '0.8rem',
                                    marginTop: '8px',
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-all'
                                  }}>
                                    {p.payload}
                                  </pre>
                                </div>
                                {p.fullRequestSent && (
                                  <div style={{ marginTop: '12px' }}>
                                    <button 
                                      className="btn btn-sm btn-success"
                                      onClick={() => showRequestResponse('request', { 
                                        fullRequest: p.fullRequestSent,
                                        fullResponse: p.responseBody || p.responseSnippet,
                                        payload: p.payload,
                                        evidence: p.evidence
                                      }, p.payload)}
                                    >
                                      View Full Request and Response
                                    </button>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function renderXssFinding(finding, index, badgeClass, badgeText, isExpanded, handleFindingClick, scanId, showRequestResponse, showInputInjections) {
  return (
    <div className={`finding-card ${isExpanded ? 'expanded' : ''}`}>
      <div className="finding-header" onClick={handleFindingClick}>
        <div className="finding-title">
          #{finding.id} [{finding.xssType}] {finding.method} {finding.url}
        </div>
        <div className="finding-meta">
          <span className={`badge ${badgeClass}`}>{badgeText}</span>
          <span className="finding-count">{finding.attempts ? finding.attempts.length : 0} attempts</span>
          <span className="expand-icon">{isExpanded ? '▾' : '▸'}</span>
        </div>
      </div>

      <div className={`finding-body ${isExpanded ? 'expanded' : ''}`}>
        {isExpanded && (
          <>
            <div className="finding-info">
              <span><strong>Parameter:</strong> {finding.parameter}</span>
              <span><strong>Marker:</strong> {finding.marker}</span>
              <span><strong>Severity:</strong> {finding.severity}</span>
              <span><strong>Confidence:</strong> {finding.confidence}</span>
            </div>

            {(finding.attempts || []).map((attempt, i) => {
              const payload = attempt.payload || attempt.payloadInjected || null;
              
              return (
                <div key={i} className="attempt-card">
                  <div className="attempt-header">
                    <span>
                      Attempt #{attempt.index} - 
                      <span className={`badge ${attempt.status === 'CONFIRMED' ? 'badge-tp' : attempt.status === 'FALSE_POSITIVE' ? 'badge-fp' : 'badge-inc'}`}>
                        {attempt.status}
                      </span>
                    </span>
                    <div className="attempt-actions">
                      {attempt.allInputsTested && (
                        <span className="attempt-badge">All Inputs</span>
                      )}
                      {attempt.screenshot && (
                        <a 
                          href={`/api/screenshots/${scanId}/${attempt.screenshot.split('/').pop()}`} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="screenshot-link"
                        >
                          Screenshot
                        </a>
                      )}
                    </div>
                  </div>

                  <div className="attempt-body">
                    <div className="attempt-buttons">
                      {attempt.request && (
                        <button 
                          className="btn btn-sm btn-secondary"
                          onClick={() => {
                            let rawRequest = '';
                            const method = attempt.request?.method || finding.method || 'GET';
                            const url = attempt.request?.url || finding.url;
                            
                            let path = '/';
                            try {
                              const urlObj = new URL(url);
                              path = urlObj.pathname + urlObj.search;
                            } catch (e) {}
                            
                            rawRequest = `${method} ${path} HTTP/1.1\n`;
                            
                            try {
                              const urlObj = new URL(url);
                              rawRequest += `Host: ${urlObj.host}\n`;
                            } catch (e) {}
                            
                            if (attempt.request?.headers) {
                              let headers = attempt.request.headers;
                              if (typeof headers === 'string') {
                                try {
                                  headers = JSON.parse(headers);
                                } catch (e) {}
                              }
                              if (typeof headers === 'object') {
                                const excludeKeys = ['method', 'url', 'body', 'fullRequest', 'fullResponse', 'raw'];
                                for (const [key, value] of Object.entries(headers)) {
                                  if (!excludeKeys.includes(key.toLowerCase())) {
                                    rawRequest += `${key}: ${value}\n`;
                                  }
                                }
                              }
                            }
                            
                            if (attempt.request?.body && typeof attempt.request.body === 'string') {
                              rawRequest += '\n' + attempt.request.body;
                            }
                            
                            const requestData = {
                              fullRequest: rawRequest || 'No request data available',
                              payload: payload,
                              fullResponse: attempt.response?.body || attempt.response?.fullResponse
                            };
                            showRequestResponse('request', requestData, payload);
                          }}
                        >
                          Request
                        </button>
                      )}
                      {attempt.response && (
                        <button 
                          className="btn btn-sm btn-secondary"
                          onClick={() => {
                            let rawResponse = '';
                            
                            if (attempt.response) {
                              if (typeof attempt.response === 'string') {
                                rawResponse = attempt.response;
                              } else if (typeof attempt.response === 'object') {
                                if (attempt.response.fullResponse) {
                                  rawResponse = attempt.response.fullResponse;
                                } else if (attempt.response.raw) {
                                  rawResponse = attempt.response.raw;
                                } else {
                                  const statusCode = attempt.response.statusCode || '200';
                                  rawResponse = `HTTP/1.1 ${statusCode} OK\n`;
                                  
                                  if (attempt.response.headers) {
                                    let headers = attempt.response.headers;
                                    if (typeof headers === 'string') {
                                      try {
                                        headers = JSON.parse(headers);
                                      } catch (e) {}
                                    }
                                    if (typeof headers === 'object') {
                                      for (const [key, value] of Object.entries(headers)) {
                                        if (key !== 'statusCode' && key !== 'body') {
                                          rawResponse += `${key}: ${value}\n`;
                                        }
                                      }
                                    }
                                  }
                                  
                                  if (attempt.response.body && typeof attempt.response.body === 'string') {
                                    rawResponse += '\n' + attempt.response.body;
                                  }
                                }
                              }
                            }
                            
                            const responseData = {
                              fullResponse: rawResponse || 'No response data available',
                              statusCode: attempt.response?.statusCode,
                              payload: payload
                            };
                            showRequestResponse('response', responseData, payload);
                          }}
                        >
                          Response
                        </button>
                      )}
                      {attempt.inputInjections && attempt.inputInjections.length > 0 && (
                        <button 
                          className="btn btn-sm btn-secondary"
                          onClick={() => showInputInjections(attempt.inputInjections)}
                        >
                          Inputs ({attempt.inputInjections.length})
                        </button>
                      )}
                    </div>

                    {attempt.contextAnalysis && (
                      <div className="context-info">
                        <span>Found: {attempt.contextAnalysis.found ? 'Yes' : 'No'}</span>
                        <span>Encoded: {attempt.contextAnalysis.encoded ? 'Yes' : 'No'}</span>
                        <span>Exploitable: {attempt.contextAnalysis.exploitable ? 'Yes' : 'No'}</span>
                        <span className="context-reason">{attempt.contextAnalysis.reason}</span>
                      </div>
                    )}

                    {payload && (
                      <div className="payload-injected">
                        <strong>Payload Injected:</strong>
                        <pre>{payload}</pre>
                        <div style={{ 
                          marginTop: '4px', 
                          fontSize: '0.75rem', 
                          color: '#8b949e'
                        }}>
                          This payload was injected into the {finding.parameter} parameter
                        </div>
                      </div>
                    )}

                    {attempt.screenshot && (
                      <div className="screenshot-preview">
                        <img 
                          src={`/api/screenshots/${scanId}/${attempt.screenshot.split('/').pop()}`} 
                          alt="Screenshot"
                        />
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </>
        )}
      </div>
    </div>
  );
}

export default FindingCard;
