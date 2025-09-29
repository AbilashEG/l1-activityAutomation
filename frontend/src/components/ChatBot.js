// components/ChatBot.js
import React, { useState, useRef, useEffect } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { sendMessage, discoverAccounts, discoverInstances, deployCloudWatchAgent, configureAlarms } from '../Services/api';
import AccountGroupsCard from './AccountGroupsCard';
import InstanceDetailsTable from './InstanceDetailsTable';
import ConfirmationModal from './ConfirmationModal';
import '../styles/combined.css';

export default function ChatBot() {
  const [sessionId] = useState(uuidv4());
  const [messages, setMessages] = useState([
    {
      from: 'bot',
      text: "Hi! Welcome to the L1 Activity Bot. I'm your virtual assistant. I can help you discover instances across your AWS accounts and configure CloudWatch agents.",
      type: 'text'
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [conversationState, setConversationState] = useState('welcome');
  const [accountGroups, setAccountGroups] = useState([]);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [instances, setInstances] = useState([]);
  const messageEndRef = useRef(null);

  // Modal state
  const [confirmationModal, setConfirmationModal] = useState({
    show: false,
    instanceId: '',
    region: ''
  });

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  // ✅ NEW: Add message to chat function
  const addMessage = (text, sender = 'user') => {
    const newMessage = {
      from: sender === 'user' ? 'user' : 'bot',
      text: text,
      type: 'text'
    };
    
    setMessages(prev => [...prev, newMessage]);
    console.log(`💬 Chat message added: ${text.substring(0, 50)}... from ${sender}`);
  };

  // ✅ NEW: Handle refresh instances function
  const handleRefreshInstances = async () => {
    if (!selectedAccount) return;
    
    try {
      console.log(`🔄 Refreshing instances for account: ${selectedAccount}`);
      const result = await discoverInstances(selectedAccount);
      
      if (result.status === 'success' && result.data.instances) {
        console.log(`✅ Refresh successful: ${result.data.instances.length} instances`);
        setInstances(result.data.instances);
        
        // ✅ Update the table message data for real-time display
        setMessages(prev => prev.map(msg => {
          if (msg.type === 'instances-table' && msg.data?.accountId === selectedAccount) {
            return {
              ...msg,
              data: {
                ...msg.data,
                instances: result.data.instances
              }
            };
          }
          return msg;
        }));
        
        return result.data.instances;
      } else {
        throw new Error('Failed to fetch instance data');
      }
    } catch (error) {
      console.error('❌ Refresh error:', error);
      throw error;
    }
  };

  // Enhanced intent detection
  const checkCloudWatchIntent = (userInput) => {
    const keywords = ['cloudwatch', 'configure', 'agent', 'install', 'setup', 'monitor', 'start', 'deploy'];
    return keywords.some(keyword => userInput.toLowerCase().includes(keyword));
  };

  const checkAlarmIntent = (userInput) => {
    const keywords = ['alarm', 'alert', 'threshold', 'notification', 'warning', 'metric'];
    return keywords.some(keyword => userInput.toLowerCase().includes(keyword));
  };

  // Fetch account groups using API
  const fetchAccountGroups = async () => {
    console.log('=== FETCH ACCOUNT GROUPS CALLED ===');
    try {
      console.log('About to call discoverAccounts...');
      const result = await discoverAccounts();
      console.log('discoverAccounts result:', result);
      
      if (result.status === 'success') {
        setAccountGroups(result.data.accountGroups || []);
        
        setMessages(prev => [...prev, {
          from: 'bot',
          text: 'Here are your AWS accounts with CloudWatch agent status:',
          type: 'account-groups',
          data: result.data.accountGroups || []
        }]);
        
        setConversationState('account-selection');
      } else {
        throw new Error(result.message);
      }
    } catch (error) {
      console.error('Error fetching accounts:', error);
      setMessages(prev => [...prev, {
        from: 'bot',
        text: 'Sorry, I encountered an error while fetching your accounts. Please try again.',
        type: 'text'
      }]);
    }
  };

  // ✅ UPDATED: Handle account selection with alarm counting
  const handleAccountSelect = async (accountId) => {
    setSelectedAccount(accountId);
    
    setMessages(prev => [...prev, {
      from: 'user',
      text: `Selected account: ${accountId}`,
      type: 'text'
    }]);
    
    setMessages(prev => [...prev, {
      from: 'bot',
      text: `Scanning account ${accountId} for EC2 instances and checking CloudWatch agent status...`,
      type: 'text'
    }]);
    
    setLoading(true);
    
    try {
      const result = await discoverInstances(accountId);
      
      if (result.status === 'success') {
        // ✅ Update instances state for real-time updates
        const instancesWithAlarms = result.data.instances || [];
        setInstances(instancesWithAlarms);
        
        // ✅ Enhanced counting with alarm status
        const unconfiguredCount = instancesWithAlarms.filter(i => i.ActionNeeded && i.State === 'running').length;
        const configuredCount = instancesWithAlarms.filter(i => i.CloudWatchConfigured && i.State === 'running').length;
        const alarmsConfiguredCount = instancesWithAlarms.filter(i => i.AlarmsConfigured && i.State === 'running').length;

        // ✅ Enhanced message with alarm information
        let message = `Found ${result.data.instances.length} instances in total:
        
🔧 ${unconfiguredCount} instances need CloudWatch agent installation
✅ ${configuredCount} instances have CloudWatch agent configured
🎯 ${alarmsConfiguredCount} instances have alarms configured

Use the action buttons in the table below to manage your instances:`;

        setMessages(prev => [...prev, {
          from: 'bot',
          text: message,
          type: 'instances-table',
          data: { instances: instancesWithAlarms, accountId }
        }]);
        
        setConversationState('instance-management');
      } else {
        throw new Error(result.message);
      }
    } catch (error) {
      console.error('Error fetching instances:', error);
      setMessages(prev => [...prev, {
        from: 'bot',
        text: 'Sorry, I encountered an error while scanning instances. Please try again.',
        type: 'text'
      }]);
    } finally {
      setLoading(false);
    }
  };

  // Show confirmation modal for CloudWatch agent deployment
  const handleInstanceSelect = async (instanceId, region) => {
    setConfirmationModal({
      show: true,
      instanceId: instanceId,
      region: region
    });
  };

  // Handle modal confirmation
  const handleConfirmDeployment = () => {
    const { instanceId, region } = confirmationModal;
    setConfirmationModal({ show: false, instanceId: '', region: '' });
    proceedWithDeployment(instanceId, region);
  };

  // Handle modal cancellation
  const handleCancelDeployment = () => {
    setConfirmationModal({ show: false, instanceId: '', region: '' });
  };

  // Proceed with actual CloudWatch agent deployment
  const proceedWithDeployment = async (instanceId, region) => {
    // Add user selection message
    setMessages(prev => [...prev, {
      from: 'user',
      text: `Configure CloudWatch agent on: ${instanceId}`,
      type: 'text'
    }]);
    
    // Add bot configuration message
    setMessages(prev => [...prev, {
      from: 'bot',
      text: `Configuring CloudWatch agent on instance ${instanceId} in region ${region}...`,
      type: 'text'
    }]);
    
    setLoading(true);
    
    try {
      const result = await deployCloudWatchAgent({
        instanceId,
        accountId: selectedAccount,
        region: region
      });
      
      if (result.status === 'success') {
        setMessages(prev => [...prev, {
          from: 'bot',
          text: `✅ CloudWatch agent installation initiated successfully on ${instanceId}!

Command ID: ${result.data.commandId}
Estimated completion time: ~10 minutes

You can monitor the installation progress in AWS Systems Manager console.

💡 Once the agent is installed, you can configure CloudWatch alarms for this instance!`,
          type: 'text'
        }]);
      } else {
        throw new Error(result.message);
      }
      
    } catch (error) {
      console.error('Error deploying agent:', error);
      setMessages(prev => [...prev, {
        from: 'bot',
        text: `❌ Failed to configure CloudWatch agent on ${instanceId}.

Error: ${error.message}

Please check the instance permissions and try again.`,
        type: 'text'
      }]);
    } finally {
      setLoading(false);
    }
  };

  // Enhanced message handling with alarm intent
  const handleSend = async () => {
    const value = input.trim();
    if (!value) return;
    
    setMessages(prev => [...prev, { from: 'user', text: value, type: 'text' }]);
    setInput('');
    setLoading(true);
    
    try {
      console.log('=== HANDLE SEND CALLED ===', value);
      
      // Check for CloudWatch intent
      if (checkCloudWatchIntent(value)) {
        console.log('=== CLOUDWATCH INTENT DETECTED ===');
        
        setMessages(prev => [...prev, {
          from: 'bot',
          text: "I'll scan your accounts and show current CloudWatch agent status...",
          type: 'text'
        }]);
        
        await fetchAccountGroups();
      } 
      // Check for alarm intent
      else if (checkAlarmIntent(value)) {
        console.log('=== ALARM INTENT DETECTED ===');
        
        setMessages(prev => [...prev, {
          from: 'bot',
          text: "I'll help you configure CloudWatch alarms! First, let me show you your instances so you can select which ones need alarm configuration...",
          type: 'text'
        }]);
        
        await fetchAccountGroups();
      }
      // Regular chat
      else {
        console.log('=== REGULAR CHAT ===');
        
        const result = await sendMessage({ sessionId: sessionId, message: value });
        
        if (result.status === 'success') {
          let botReply = result.data?.message || "Sorry, I didn't understand that.";
          
          // Handle backend intent responses
          if (result.intent === 'cloudwatch_configuration') {
            botReply = result.message;
            setTimeout(() => fetchAccountGroups(), 1000);
          } else if (result.intent === 'alarm_configuration') {
            botReply = result.message;
            setTimeout(() => fetchAccountGroups(), 1000);
          } else {
            // Add helpful suggestions
            botReply += "\n\n💡 Try saying:\n• 'configure cloudwatch agent'\n• 'set up alarms'\n• 'show my instances'";
          }
          
          setMessages(prev => [...prev, { from: 'bot', text: botReply, type: 'text' }]);
        } else {
          throw new Error(result.message);
        }
      }
    } catch (error) {
      console.error('Error in handleSend:', error);
      setMessages(prev => [...prev, { 
        from: 'bot', 
        text: 'Error communicating with backend. Please try again.',
        type: 'text'
      }]);
    } finally {
      setLoading(false);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="mojobot-widget-container">
      <div className="mojobot-header">
        <img src={require('../assets/bot-avatar.png')} alt="Bot" className="mojobot-avatar" />
        <div style={{ flex: 1 }}>
          <div className="mojobot-title">Chat with L1 Activity Bot</div>
          <div className="mojobot-status">
            <span className="mojobot-dot" /> Ready to help you!
          </div>
        </div>
        <div className="mojobot-menu">⋮</div>
      </div>
      
      <div className="mojobot-messages">
        {messages.map((msg, idx) => (
          <div key={idx}>
            {msg.type === 'text' && (
              <div
                className={msg.from === 'user' ? 'mojobot-bubble mojobot-user' : 'mojobot-bubble mojobot-bot'}
                dangerouslySetInnerHTML={{ __html: msg.text.replace(/\n/g, "<br />") }}
              />
            )}
            
            {msg.type === 'account-groups' && msg.from === 'bot' && (
              <div className="mojobot-bubble mojobot-bot">
                <div dangerouslySetInnerHTML={{ __html: msg.text.replace(/\n/g, "<br />") }} />
                <AccountGroupsCard 
                  accountGroups={msg.data}
                  onAccountSelect={handleAccountSelect}
                />
              </div>
            )}
            
            {msg.type === 'instances-table' && msg.from === 'bot' && (
              <div className="mojobot-bubble mojobot-bot">
                <div dangerouslySetInnerHTML={{ __html: msg.text.replace(/\n/g, "<br />") }} />
                {/* ✅ FIXED: Updated InstanceDetailsTable with all required props */}
                <InstanceDetailsTable 
                  instances={instances}                    // ✅ Use state instances for real-time updates
                  setInstances={setInstances}              // ✅ CRITICAL: For local state updates
                  accountId={msg.data.accountId}
                  onInstanceSelect={(instanceId) => {
                    const instance = instances.find(i => i.InstanceId === instanceId);
                    handleInstanceSelect(instanceId, instance.Region);
                  }}
                  onAddMessage={addMessage}                // ✅ CRITICAL: For chat integration
                  onRefresh={handleRefreshInstances}       // ✅ CRITICAL: For refresh functionality
                />
              </div>
            )}
          </div>
        ))}
        
        {loading && <div className="mojobot-bubble mojobot-bot">Thinking…</div>}
        <div ref={messageEndRef} />
      </div>
      
      <div className="mojobot-inputbar">
        <input
          className="mojobot-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Enter your message..."
          disabled={loading}
        />
        <button
          className="mojobot-send"
          onClick={handleSend}
          disabled={loading || !input.trim()}
          aria-label="Send"
        >
          <svg width="28" height="28" fill="white" viewBox="0 0 24 24">
            <path d="M3 20v-5l15-3-15-3V4l19 8-19 8z" />
          </svg>
        </button>
      </div>

      {/* Confirmation modal for CloudWatch agent deployment */}
      <ConfirmationModal
        show={confirmationModal.show}
        instanceId={confirmationModal.instanceId}
        region={confirmationModal.region}
        onConfirm={handleConfirmDeployment}
        onCancel={handleCancelDeployment}
      />
    </div>
  );
}
