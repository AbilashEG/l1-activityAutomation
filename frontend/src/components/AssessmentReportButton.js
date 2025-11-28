import React, { useState, useEffect } from 'react';
import { generateAssessmentReport } from '../Services/api';

// ✅ COMPONENT: Assessment Report Generation Button
const AssessmentReportButton = ({ accountId, region }) => {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const [templateFile, setTemplateFile] = useState(null);
  const [architectureFile, setArchitectureFile] = useState(null);
  const [filesUploaded, setFilesUploaded] = useState(false);
  const [showPopup, setShowPopup] = useState(false);

  // EFFECT: Enable button when both files are ready
  useEffect(() => {
    if (templateFile && architectureFile) {
      setFilesUploaded(true);
      setMessage('✅ Both files ready! Click "Generate Report" to start.');
      setMessageType('info');
    } else {
      setFilesUploaded(false);
    }
  }, [templateFile, architectureFile]);

  // HANDLER: Template File Upload
  const handleTemplateUpload = (e) => {
    const file = e.target.files[0];
    if (file && file.name.endsWith('.docx')) {
      setTemplateFile(file);
      setMessage(`✅ Template uploaded: ${file.name}`);
      setMessageType('success');
    } else {
      setMessage('❌ Please upload a valid .docx template file');
      setMessageType('error');
      setTemplateFile(null);
    }
  };

  // HANDLER: Architecture Image Upload
  const handleArchitectureUpload = (e) => {
    const file = e.target.files[0];
    if (file && (file.type.startsWith('image/') || file.name.endsWith('.png'))) {
      setArchitectureFile(file);
      setMessage(`✅ Architecture image uploaded: ${file.name}`);
      setMessageType('success');
    } else {
      setMessage('❌ Please upload a valid image file (PNG, JPG, etc.)');
      setMessageType('error');
      setArchitectureFile(null);
    }
  };

  // UTILITY: Download Report File
  const downloadReport = (base64String, filename) => {
    try {
      const byteArray = new Uint8Array(
        atob(base64String)
          .split('')
          .map((char) => char.charCodeAt(0)),
      );
      const blob = new Blob([byteArray], {
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    } catch (error) {
      setMessage(`❌ Download failed: ${error.message}`);
      setMessageType('error');
    }
  };

  // MAIN: Generate Assessment Report
  const handleGenerateAssessmentReport = async () => {
    if (!accountId || !region) {
      setMessage('❌ Account ID and Region are required');
      setMessageType('error');
      return;
    }
    if (!templateFile || !architectureFile) {
      setMessage('❌ Please upload both files first');
      setMessageType('error');
      return;
    }

    setLoading(true);
    setMessage('⏳ Generating report...');
    setMessageType('info');

    try {
      const result = await generateAssessmentReport({
        accountId,
        region,
        templateFile,
        imageFile: architectureFile,
      });

      // generateAssessmentReport returns:
      // { success: true/false, message, data: { reportBase64, filename, ... } }
      if (result && result.success && result.data && result.data.reportBase64) {
        setShowPopup(true);
        setTimeout(() => setShowPopup(false), 3000);

        const filename =
          result.data.filename ||
          `AWS_Assessment_${accountId}_${region || 'report'}.docx`;

        setMessage(result.message || '✅ Report generated! Downloading...');
        setMessageType('success');

        downloadReport(result.data.reportBase64, filename);

        setTimeout(() => {
          setMessage(`✅ Report downloaded: ${filename}`);
        }, 1000);
      } else if (result && !result.success) {
        setMessage(`❌ Error: ${result.message || 'Unknown error occurred'}`);
        setMessageType('error');
      } else {
        setMessage('❌ Error: No report content returned from server');
        setMessageType('error');
      }
    } catch (error) {
      setMessage(`❌ Failed: ${error.message}`);
      setMessageType('error');
    } finally {
      setLoading(false);
    }
  };

  // RENDER: UI LAYOUT
  return (
    <div className="assessment-report-container">
      {showPopup && (
        <div
          style={{
            position: 'fixed',
            top: '20px',
            right: '20px',
            backgroundColor: '#4CAF50',
            color: 'white',
            padding: '15px 20px',
            borderRadius: '5px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.2)',
            zIndex: 9999,
            fontSize: '14px',
            fontWeight: 'bold',
          }}
        >
          ✅ Report Generated Successfully!
        </div>
      )}

      <div className="report-header">
        <h3>📊 Generate Assessment Report</h3>
        <p>Account: {accountId}</p>
      </div>

      <div className="file-upload-section">
        <div className="upload-box">
          <label>📄 Upload Template (DOCX)</label>
          <input
            type="file"
            accept=".docx"
            onChange={handleTemplateUpload}
            disabled={loading}
          />
          {templateFile && (
            <span className="file-name">
              ✅ {templateFile.name} ({(templateFile.size / 1024).toFixed(2)} KB)
            </span>
          )}
        </div>
        <div className="upload-box">
          <label>🖼️ Upload Architecture Image</label>
          <input
            type="file"
            accept="image/*"
            onChange={handleArchitectureUpload}
            disabled={loading}
          />
          {architectureFile && (
            <span className="file-name">
              ✅ {architectureFile.name} ({(architectureFile.size / 1024).toFixed(2)} KB)
            </span>
          )}
        </div>
      </div>

      <div className="button-section">
        <button
          onClick={handleGenerateAssessmentReport}
          disabled={loading || !filesUploaded}
          className={`generate-btn ${loading ? 'loading' : ''} ${
            !filesUploaded ? 'disabled' : ''
          }`}
        >
          {loading ? '⏳ Generating...' : '📊 Generate Report'}
        </button>
      </div>

      {message && <div className={`message ${messageType}`}>{message}</div>}

      {loading && (
        <div className="status-info">
          <p>⏳ Generating report from uploaded files...</p>
          <ul>
            <li>✅ Files uploaded to cache</li>
            <li>✅ Architecture analysis with Bedrock Nova Pro</li>
            <li>✅ AWS resources discovery</li>
            <li>✅ Security validation</li>
            <li>✅ Cost optimization analysis</li>
            <li>✅ Performance review</li>
            <li>✅ Well-Architected Framework assessment</li>
            <li>✅ Cache cleanup & report download</li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default AssessmentReportButton;
