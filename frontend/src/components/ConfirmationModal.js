// components/ConfirmationModal.js
import React from 'react';

const ConfirmationModal = ({ 
  show, 
  instanceId, 
  region, 
  onConfirm, 
  onCancel 
}) => {
  if (!show) return null;

  return (
    <div className="confirmation-modal-overlay" onClick={onCancel}>
      <div className="confirmation-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>⚠️ Confirm CloudWatch Agent Deployment</h3>
        </div>
        
        <div className="modal-body">
          <div className="instance-info">
            <p><strong>Instance ID:</strong> <code>{instanceId}</code></p>
            <p><strong>Region:</strong> <code>{region}</code></p>
          </div>
          
          <div className="warning-section">
            <p>This action will:</p>
            <ul>
              <li>Install/configure CloudWatch agent on this instance</li>
              <li>Take approximately <strong>10 minutes</strong> to complete</li>
              <li>Require SSM access to the instance</li>
            </ul>
          </div>
          
          <div className="confirmation-question">
            <strong>Do you want to proceed with the deployment?</strong>
          </div>
        </div>
        
        <div className="modal-footer">
          <button 
            className="modal-btn cancel-btn" 
            onClick={onCancel}
          >
            Cancel
          </button>
          <button 
            className="modal-btn confirm-btn" 
            onClick={onConfirm}
          >
            Yes, Deploy Agent
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmationModal;
