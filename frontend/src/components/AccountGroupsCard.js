// components/AccountGroupsCard.js
import React, { useState } from 'react';

const AccountGroupsCard = ({ accountGroups, onAccountSelect }) => {
  const [expandedGroups, setExpandedGroups] = useState({});

  // Group accounts by GroupName
  const groupAccountsByGroupName = (accounts) => {
    const grouped = {};
    accounts.forEach(account => {
      const groupName = account.GroupName;
      if (!grouped[groupName]) {
        grouped[groupName] = {
          groupName: groupName,
          accounts: []
        };
      }
      grouped[groupName].accounts.push(account);
    });
    return Object.values(grouped);
  };

  const groupedAccounts = groupAccountsByGroupName(accountGroups);

  const toggleGroup = (groupName) => {
    setExpandedGroups(prev => ({
      ...prev,
      [groupName]: !prev[groupName]
    }));
  };

  return (
    <div className="account-groups-card">
      <h3>Available Account Groups</h3>
      <div className="account-cards-container">
        {groupedAccounts.map(group => (
          <div key={group.groupName} className="group-container">
            {/* Group Header */}
            <div 
              className="group-header" 
              onClick={() => toggleGroup(group.groupName)}
              style={{ 
                cursor: 'pointer', 
                padding: '10px', 
                background: '#f5f5f5', 
                border: '1px solid #ddd',
                borderRadius: '5px',
                marginBottom: '5px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}
            >
              <strong>{group.groupName} ({group.accounts.length} accounts)</strong>
              <span style={{ fontSize: '18px' }}>
                {expandedGroups[group.groupName] ? '▼' : '▶'}
              </span>
            </div>

            {/* Expanded Accounts */}
            {expandedGroups[group.groupName] && (
              <div className="accounts-list" style={{ marginLeft: '20px', marginBottom: '10px' }}>
                {group.accounts.map(account => (
                  <div 
                    key={account.AccountID} 
                    className="account-card" 
                    onClick={() => onAccountSelect(account.AccountID)}
                    style={{ 
                      cursor: 'pointer',
                      padding: '8px 12px',
                      background: '#fff',
                      border: '1px solid #ccc',
                      borderRadius: '3px',
                      marginBottom: '5px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      transition: 'background-color 0.2s'
                    }}
                    onMouseEnter={(e) => e.target.style.backgroundColor = '#f0f0f0'}
                    onMouseLeave={(e) => e.target.style.backgroundColor = '#fff'}
                  >
                    <div className="account-info">
                      <div><strong>Account:</strong> {account.AccountID}</div>
                      <div style={{ fontSize: '12px', color: '#666' }}>
                        {account.AccountName} - {account.Environment}
                      </div>
                    </div>
                    <div className="expand-arrow">→</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default AccountGroupsCard;
