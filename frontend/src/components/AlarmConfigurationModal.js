import React, { useState } from 'react';
import '../styles/combined.css';

const AlarmConfigurationModal = ({ 
  show, 
  instance, 
  onConfirm, 
  onCancel 
}) => {
  const [alarmConfig, setAlarmConfig] = useState({
    cpu_threshold: 85,
    cpu_condition: 'above',
    memory_threshold: 85,
    memory_condition: 'above',
    disk_threshold: 90,
    disk_condition: 'above',
    overall_threshold: 80,
    overall_condition: 'above'
  });

  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleInputChange = (field, value) => {
    // ✅ Add validation for numeric inputs
    if (field.includes('threshold')) {
      const numValue = parseInt(value);
      if (isNaN(numValue)) return;
      if (numValue < 1) value = 1;
      if (numValue > 100) value = 100;
    }
    
    setAlarmConfig(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleConfirm = async () => {
    setIsSubmitting(true);
    try {
      await onConfirm(alarmConfig);
      // Reset form after successful submission
      setAlarmConfig({
        cpu_threshold: 85,
        cpu_condition: 'above',
        memory_threshold: 85,
        memory_condition: 'above',
        disk_threshold: 90,
        disk_condition: 'above',
        overall_threshold: 80,
        overall_condition: 'above'
      });
    } catch (error) {
      console.error('Error configuring alarms:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    if (!isSubmitting) {
      onCancel();
      // Reset form on cancel
      setAlarmConfig({
        cpu_threshold: 85,
        cpu_condition: 'above',
        memory_threshold: 85,
        memory_condition: 'above',
        disk_threshold: 90,
        disk_condition: 'above',
        overall_threshold: 80,
        overall_condition: 'above'
      });
    }
  };

  if (!show || !instance) return null;

  const isWindows = instance.Platform && instance.Platform.toLowerCase().includes('windows');
  const platform = isWindows ? 'Windows' : 'Linux';

  return (
    <div className="modal-overlay" style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.6)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 1000,
      backdropFilter: 'blur(4px)'
    }}>
      <div className="modal-content alarm-config-modal" style={{
        maxWidth: '650px',
        width: '90%',
        maxHeight: '90vh',
        overflowY: 'auto',
        background: 'white',
        borderRadius: '16px',
        boxShadow: '0 20px 60px rgba(129, 79, 255, 0.2)',
        border: '2px solid #E5E7EB'
      }}>
        
        {/* ✅ Header with bot-style purple theme */}
        <div className="modal-header" style={{
          background: 'linear-gradient(135deg, #8B5CF6, #A855F7)',
          color: 'white',
          padding: '24px 28px',
          borderRadius: '14px 14px 0 0',
          boxShadow: '0 4px 12px rgba(139, 92, 246, 0.2)'
        }}>
          <h3 style={{ 
            margin: 0, 
            fontSize: '1.6rem', 
            fontWeight: '600',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            ⚠️ Configure CloudWatch Alarms
          </h3>
          <p style={{ 
            margin: '10px 0 0 0', 
            opacity: 0.9, 
            fontSize: '1rem' 
          }}>
            Instance: <strong>{instance.InstanceName || instance.InstanceId}</strong> ({platform})
          </p>
        </div>
        
        {/* ✅ Modal Body */}
        <div className="modal-body" style={{ 
          padding: '28px',
          background: '#FAFBFC'
        }}>
          
          {/* ✅ CPU Configuration */}
          <div className="config-row" style={{ 
            display: 'flex', 
            alignItems: 'center', 
            marginBottom: '20px',
            padding: '20px',
            backgroundColor: '#FFFFFF',
            borderRadius: '12px',
            border: '2px solid #E2E8F0',
            transition: 'all 0.3s ease',
            boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)'
          }}>
            <div style={{ flex: 1 }}>
              <label style={{ 
                fontWeight: '600', 
                color: '#374151',
                marginBottom: '8px',
                display: 'block',
                fontSize: '1rem'
              }}>🖥️ CPU Utilization:</label>
              <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={alarmConfig.cpu_threshold}
                  onChange={(e) => handleInputChange('cpu_threshold', parseInt(e.target.value))}
                  disabled={isSubmitting}
                  style={{
                    padding: '12px 16px',
                    border: '2px solid #D1D5DB',
                    borderRadius: '8px',
                    width: '90px',
                    fontSize: '16px',
                    fontWeight: '500',
                    transition: 'border-color 0.2s ease',
                    background: 'white'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#8B5CF6'}
                  onBlur={(e) => e.target.style.borderColor = '#D1D5DB'}
                />
                <span style={{ color: '#6B7280', fontWeight: '500' }}>%</span>
                <select
                  value={alarmConfig.cpu_condition}
                  onChange={(e) => handleInputChange('cpu_condition', e.target.value)}
                  disabled={isSubmitting}
                  style={{
                    padding: '12px 16px',
                    border: '2px solid #D1D5DB',
                    borderRadius: '8px',
                    fontSize: '16px',
                    fontWeight: '500',
                    backgroundColor: 'white',
                    cursor: 'pointer',
                    transition: 'border-color 0.2s ease',
                    minWidth: '100px'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#8B5CF6'}
                  onBlur={(e) => e.target.style.borderColor = '#D1D5DB'}
                >
                  <option value="above">Above</option>
                  <option value="below">Below</option>
                </select>
              </div>
            </div>
          </div>

          {/* ✅ Memory Configuration */}
          <div className="config-row" style={{ 
            display: 'flex', 
            alignItems: 'center', 
            marginBottom: '20px',
            padding: '20px',
            backgroundColor: '#FFFFFF',
            borderRadius: '12px',
            border: '2px solid #E2E8F0',
            transition: 'all 0.3s ease',
            boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)'
          }}>
            <div style={{ flex: 1 }}>
              <label style={{ 
                fontWeight: '600', 
                color: '#374151',
                marginBottom: '8px',
                display: 'block',
                fontSize: '1rem'
              }}>💾 Memory Utilization:</label>
              <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={alarmConfig.memory_threshold}
                  onChange={(e) => handleInputChange('memory_threshold', parseInt(e.target.value))}
                  disabled={isSubmitting}
                  style={{
                    padding: '12px 16px',
                    border: '2px solid #D1D5DB',
                    borderRadius: '8px',
                    width: '90px',
                    fontSize: '16px',
                    fontWeight: '500',
                    transition: 'border-color 0.2s ease',
                    background: 'white'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#8B5CF6'}
                  onBlur={(e) => e.target.style.borderColor = '#D1D5DB'}
                />
                <span style={{ color: '#6B7280', fontWeight: '500' }}>%</span>
                <select
                  value={alarmConfig.memory_condition}
                  onChange={(e) => handleInputChange('memory_condition', e.target.value)}
                  disabled={isSubmitting}
                  style={{
                    padding: '12px 16px',
                    border: '2px solid #D1D5DB',
                    borderRadius: '8px',
                    fontSize: '16px',
                    fontWeight: '500',
                    backgroundColor: 'white',
                    cursor: 'pointer',
                    transition: 'border-color 0.2s ease',
                    minWidth: '100px'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#8B5CF6'}
                  onBlur={(e) => e.target.style.borderColor = '#D1D5DB'}
                >
                  <option value="above">Above</option>
                  <option value="below">Below</option>
                </select>
              </div>
            </div>
          </div>

          {/* ✅ Platform Specific - Linux: Disk, Windows: Overall */}
          <div className="config-row" style={{ 
            display: 'flex', 
            alignItems: 'center', 
            marginBottom: '20px',
            padding: '20px',
            backgroundColor: '#FFFFFF',
            borderRadius: '12px',
            border: '2px solid #E2E8F0',
            transition: 'all 0.3s ease',
            boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)'
          }}>
            <div style={{ flex: 1 }}>
              <label style={{ 
                fontWeight: '600', 
                color: '#374151',
                marginBottom: '8px',
                display: 'block',
                fontSize: '1rem'
              }}>
                {isWindows ? '📊 Overall Utilization:' : '💿 Disk Utilization:'}
              </label>
              <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={isWindows ? alarmConfig.overall_threshold : alarmConfig.disk_threshold}
                  onChange={(e) => handleInputChange(
                    isWindows ? 'overall_threshold' : 'disk_threshold', 
                    parseInt(e.target.value)
                  )}
                  disabled={isSubmitting}
                  style={{
                    padding: '12px 16px',
                    border: '2px solid #D1D5DB',
                    borderRadius: '8px',
                    width: '90px',
                    fontSize: '16px',
                    fontWeight: '500',
                    transition: 'border-color 0.2s ease',
                    background: 'white'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#8B5CF6'}
                  onBlur={(e) => e.target.style.borderColor = '#D1D5DB'}
                />
                <span style={{ color: '#6B7280', fontWeight: '500' }}>%</span>
                <select
                  value={isWindows ? alarmConfig.overall_condition : alarmConfig.disk_condition}
                  onChange={(e) => handleInputChange(
                    isWindows ? 'overall_condition' : 'disk_condition', 
                    e.target.value
                  )}
                  disabled={isSubmitting}
                  style={{
                    padding: '12px 16px',
                    border: '2px solid #D1D5DB',
                    borderRadius: '8px',
                    fontSize: '16px',
                    fontWeight: '500',
                    backgroundColor: 'white',
                    cursor: 'pointer',
                    transition: 'border-color 0.2s ease',
                    minWidth: '100px'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#8B5CF6'}
                  onBlur={(e) => e.target.style.borderColor = '#D1D5DB'}
                >
                  <option value="above">Above</option>
                  <option value="below">Below</option>
                </select>
              </div>
            </div>
          </div>

          {/* ✅ Status Check - Always Enabled */}
          <div className="config-row status-check" style={{ 
            padding: '20px',
            backgroundColor: '#F0FDF4',
            borderRadius: '12px',
            border: '2px solid #BBF7D0',
            marginBottom: '24px',
            boxShadow: '0 4px 12px rgba(16, 185, 129, 0.15)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <span style={{ 
                fontSize: '24px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: '40px',
                height: '40px',
                backgroundColor: '#DCFCE7',
                borderRadius: '50%'
              }}>✅</span>
              <div>
                <div style={{ 
                  fontWeight: '600', 
                  color: '#15803D', 
                  fontSize: '1.1rem',
                  marginBottom: '4px'
                }}>
                  Status Check Failed - System
                </div>
                <div style={{ 
                  fontSize: '14px', 
                  color: '#16A34A',
                  lineHeight: 1.4
                }}>
                  Always enabled for system health monitoring (1 out of 1 in 5 minutes)
                </div>
              </div>
            </div>
          </div>

          {/* ✅ Alarm Preview */}
          <div className="alarm-preview" style={{
            background: 'linear-gradient(135deg, #FEF3C7, #FDE68A)',
            border: '2px solid #F59E0B',
            borderRadius: '12px',
            padding: '20px',
            marginBottom: '24px',
            boxShadow: '0 4px 12px rgba(245, 158, 11, 0.15)'
          }}>
            <h4 style={{ 
              margin: '0 0 16px 0', 
              color: '#92400E', 
              fontSize: '1.2rem',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>⚡ Alarms to be created:</h4>
            <ul style={{ 
              margin: 0, 
              paddingLeft: '24px', 
              color: '#78350F',
              lineHeight: 1.6
            }}>
              <li style={{ marginBottom: '6px', fontWeight: '500' }}>
                CPU Utilization ({alarmConfig.cpu_condition} {alarmConfig.cpu_threshold}%) - 1 out of 1 in 5 minutes
              </li>
              <li style={{ marginBottom: '6px', fontWeight: '500' }}>
                Memory Utilization ({alarmConfig.memory_condition} {alarmConfig.memory_threshold}%) - 1 out of 1 in 5 minutes
              </li>
              {isWindows ? (
                <li style={{ marginBottom: '6px', fontWeight: '500' }}>
                  Overall Utilization ({alarmConfig.overall_condition} {alarmConfig.overall_threshold}%) - 1 out of 1 in 5 minutes
                </li>
              ) : (
                <li style={{ marginBottom: '6px', fontWeight: '500' }}>
                  Disk Utilization ({alarmConfig.disk_condition} {alarmConfig.disk_threshold}%) - 1 out of 1 in 5 minutes
                </li>
              )}
              <li style={{ fontWeight: '500' }}>
                Status Check Failed - System - 1 out of 1 in 5 minutes
              </li>
            </ul>
          </div>
        </div>
        
        {/* ✅ Footer Buttons */}
        <div className="modal-footer" style={{
          padding: '24px 28px',
          borderTop: '2px solid #E5E7EB',
          display: 'flex',
          gap: '16px',
          justifyContent: 'flex-end',
          background: '#FAFBFC'
        }}>
          <button 
            className="btn btn-secondary" 
            onClick={handleCancel}
            disabled={isSubmitting}
            style={{
              padding: '14px 28px',
              border: '2px solid #D1D5DB',
              borderRadius: '8px',
              backgroundColor: '#F3F4F6',
              color: '#374151',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              fontSize: '16px',
              fontWeight: '600',
              minWidth: '120px',
              transition: 'all 0.2s ease',
              opacity: isSubmitting ? 0.6 : 1
            }}
            onMouseOver={(e) => {
              if (!isSubmitting) {
                e.target.style.backgroundColor = '#E5E7EB';
                e.target.style.transform = 'translateY(-1px)';
                e.target.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
              }
            }}
            onMouseOut={(e) => {
              e.target.style.backgroundColor = '#F3F4F6';
              e.target.style.transform = 'translateY(0)';
              e.target.style.boxShadow = 'none';
            }}
          >
            Cancel
          </button>
          <button 
            className="btn btn-primary" 
            onClick={handleConfirm}
            disabled={isSubmitting}
            style={{
              padding: '14px 28px',
              border: 'none',
              borderRadius: '8px',
              background: isSubmitting 
                ? 'linear-gradient(135deg, #9CA3AF, #6B7280)' 
                : 'linear-gradient(135deg, #8B5CF6, #A855F7)',
              color: 'white',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              fontSize: '16px',
              fontWeight: '600',
              minWidth: '180px',
              transition: 'all 0.2s ease',
              opacity: isSubmitting ? 0.7 : 1
            }}
            onMouseOver={(e) => {
              if (!isSubmitting) {
                e.target.style.background = 'linear-gradient(135deg, #7C3AED, #9333EA)';
                e.target.style.transform = 'translateY(-1px)';
                e.target.style.boxShadow = '0 4px 16px rgba(139, 92, 246, 0.4)';
              }
            }}
            onMouseOut={(e) => {
              if (!isSubmitting) {
                e.target.style.background = 'linear-gradient(135deg, #8B5CF6, #A855F7)';
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = 'none';
              }
            }}
          >
            {isSubmitting ? '⏳ Creating Alarms...' : '🚀 Create Alarms'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AlarmConfigurationModal;
