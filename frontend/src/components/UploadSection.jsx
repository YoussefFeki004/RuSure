import React from 'react';
import './UploadSection.css';

function UploadSection({ 
  xmlFile, 
  payloadsFile, 
  onXmlChange, 
  onPayloadsChange, 
  onUpload,
  uploadStatus,
  disabled 
}) {
  const handleXmlChange = (e) => {
    if (e.target.files[0]) {
      onXmlChange(e.target.files[0]);
    }
  };

  const handlePayloadsChange = (e) => {
    if (e.target.files[0]) {
      onPayloadsChange(e.target.files[0]);
    }
  };

  return (
    <div className="upload-section">
      <h3>Upload Files</h3>
      <div className="upload-grid">
        <div className="upload-box">
          <label htmlFor="xml-file">Burp XML Report</label>
          <input 
            type="file" 
            id="xml-file" 
            accept=".xml" 
            onChange={handleXmlChange}
            disabled={disabled}
          />
          <span className="file-name">
            {xmlFile ? xmlFile.name : 'No file selected'}
          </span>
        </div>
        <div className="upload-box">
          <label htmlFor="payloads-file">Payloads File</label>
          <input 
            type="file" 
            id="payloads-file" 
            accept=".txt" 
            onChange={handlePayloadsChange}
            disabled={disabled}
          />
          <span className="file-name">
            {payloadsFile ? payloadsFile.name : 'No file selected (will use defaults)'}
          </span>
        </div>
      </div>
      <button 
        className="btn btn-primary" 
        onClick={onUpload}
        disabled={disabled}
      >
        Upload Files
      </button>
      {uploadStatus.message && (
        <div className={`status-message ${uploadStatus.type}`}>
          {uploadStatus.message}
        </div>
      )}
    </div>
  );
}

export default UploadSection;
