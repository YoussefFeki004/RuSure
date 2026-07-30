import React from 'react';
import './RequestResponseModal.css';

function RequestResponseModal({ isOpen, onClose, content }) {
  if (!isOpen || !content) return null;

  const renderContent = () => {
    const data = content.data;

    if (content.type === 'injection_detail') {
      return (
        <div className="modal-data">
          <div style={{ marginBottom: '16px' }}>
            <div style={{ 
              padding: '12px 16px',
              background: data.working ? 'rgba(63, 185, 80, 0.1)' : 'rgba(248, 81, 73, 0.1)',
              borderLeft: `4px solid ${data.working ? '#3fb950' : '#f85149'}`,
              borderRadius: '4px',
              marginBottom: '16px'
            }}>
              <strong style={{ color: data.working ? '#3fb950' : '#f85149' }}>
                {data.working ? 'This injection was successful!' : 'This injection did not work'}
              </strong>
            </div>
          </div>

          <div className="modal-field">
            <strong>Category:</strong>
            <span style={{ color: '#58a6ff' }}>{data.category}</span>
          </div>

          <div className="modal-field">
            <strong>Payload Injected:</strong>
            <pre className="modal-pre payload-highlight">{data.payload}</pre>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px', marginBottom: '16px' }}>
            <div className="modal-field">
              <strong>Status Code:</strong>
              <span style={{ color: data.statusCode && data.statusCode < 400 ? '#3fb950' : '#f85149' }}>
                {data.statusCode || 'N/A'}
              </span>
            </div>
            <div className="modal-field">
              <strong>Response Time:</strong>
              <span>{data.responseTime || 'N/A'}s</span>
            </div>
            <div className="modal-field">
              <strong>Response Size:</strong>
              <span>{data.responseSize || 'N/A'} bytes</span>
            </div>
          </div>

          {data.evidence && data.evidence.length > 0 && (
            <div className="modal-field">
              <strong>Evidence:</strong>
              <ul className="evidence-list">
                {data.evidence.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          {data.fullRequest && (
            <div className="modal-field">
              <strong>Full Request:</strong>
              <pre className="modal-pre http-message">{data.fullRequest}</pre>
            </div>
          )}

          {data.fullResponse && (
            <div className="modal-field">
              <strong>Full Response:</strong>
              <pre className="modal-pre http-message" style={{ maxHeight: '400px' }}>{data.fullResponse}</pre>
            </div>
          )}

          {data.responseSnippet && !data.fullResponse && (
            <div className="modal-field">
              <strong>Response Snippet:</strong>
              <pre className="modal-pre">{data.responseSnippet}</pre>
            </div>
          )}
        </div>
      );
    }

    if (content.type === 'request' || content.type === 'response') {
      if (data.fullRequest) {
        return (
          <div className="modal-data">
            {data.payload && (
              <div className="modal-field payload-field">
                <strong>Payload Injected:</strong>
                <pre className="modal-pre payload-highlight">{data.payload}</pre>
                {data.injected && (
                  <div style={{ 
                    marginTop: '4px', 
                    fontSize: '0.75rem', 
                    color: '#3fb950'
                  }}>
                    This payload was injected into the parameter
                  </div>
                )}
              </div>
            )}
            <div className="modal-field">
              <strong>Request:</strong>
              <pre className="modal-pre http-message">{data.fullRequest}</pre>
            </div>
            {data.fullResponse && (
              <div className="modal-field">
                <strong>Full Response:</strong>
                <pre className="modal-pre http-message" style={{ maxHeight: '400px' }}>{data.fullResponse}</pre>
              </div>
            )}
            {data.responseSnippet && !data.fullResponse && (
              <div className="modal-field">
                <strong>Response Snippet:</strong>
                <pre className="modal-pre">{data.responseSnippet}</pre>
              </div>
            )}
          </div>
        );
      }

      if (data.fullResponse) {
        return (
          <div className="modal-data">
            {data.payload && (
              <div className="modal-field payload-field">
                <strong>Payload Injected:</strong>
                <pre className="modal-pre payload-highlight">{data.payload}</pre>
                {data.injected && (
                  <div style={{ 
                    marginTop: '4px', 
                    fontSize: '0.75rem', 
                    color: '#3fb950'
                  }}>
                    This payload was injected into the parameter
                  </div>
                )}
              </div>
            )}
            <div className="modal-field">
              <strong>Response:</strong>
              <pre className="modal-pre http-message" style={{ maxHeight: '400px' }}>{data.fullResponse}</pre>
            </div>
          </div>
        );
      }
    }

    if (content.type === 'injections') {
      const injections = data;
      return (
        <div className="injections-table-wrapper">
          <h4 style={{ color: '#e6edf3', marginBottom: '12px' }}>Input Injections ({injections.length})</h4>
          <table className="injections-table">
            <thead>
              <tr>
                <th>Selector</th>
                <th>Name</th>
                <th>Type</th>
                <th>Success</th>
                <th>Restrictions</th>
              </tr>
            </thead>
            <tbody>
              {injections.map((inj, i) => (
                <tr key={i}>
                  <td className="inj-selector">{inj.selector || '-'}</td>
                  <td>{inj.name || '-'}</td>
                  <td>{inj.inputType || inj.tagName || '-'}</td>
                  <td className={inj.success === 'true' ? 'inj-success' : 'inj-fail'}>
                    {inj.success === 'true' ? 'Yes' : 'No'}
                  </td>
                  <td className="inj-restrictions">
                    {inj.restrictions ? 
                      Object.entries(inj.restrictions)
                        .filter(([k, v]) => v && v !== 'null' && v !== '')
                        .map(([k]) => k)
                        .join(', ') || 'None' : 
                      'None'
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }

    if (typeof data === 'string') {
      return <pre className="modal-pre">{data}</pre>;
    }
    
    return <pre className="modal-pre">{JSON.stringify(data, null, 2)}</pre>;
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{content.title || 'Details'}</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <div className="modal-body">
          {renderContent()}
        </div>
      </div>
    </div>
  );
}

export default RequestResponseModal;
