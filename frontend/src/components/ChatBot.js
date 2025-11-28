// components/ChatBot.js
import React, { useState, useRef, useEffect } from 'react';
import { v4 as uuidv4 } from 'uuid';
import {
  sendMessage,
  discoverAccounts,
  discoverInstances,
  deployCloudWatchAgent,
  configureAlarms,
} from '../Services/api';
import AccountGroupsCard from './AccountGroupsCard';
import InstanceDetailsTable from './InstanceDetailsTable';
import ConfirmationModal from './ConfirmationModal';
import AssessmentReportButton from './AssessmentReportButton';
import '../styles/combined.css';

export default function ChatBot() {
  const [sessionId] = useState(uuidv4());
  const [messages, setMessages] = useState([
    {
      from: 'bot',
      text: "Hi! Welcome to the L1 Activity Bot. I'm your virtual assistant. I can help you discover instances across your AWS accounts, configure CloudWatch agents, set up monitoring alarms, change instance types, convert GP2 volumes to GP3 for cost savings, and generate assessment reports!",
      type: 'text',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [accountGroups, setAccountGroups] = useState([]);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [instances, setInstances] = useState([]);
  const messageEndRef = useRef(null);

  const [confirmationModal, setConfirmationModal] = useState({
    show: false,
    instanceId: '',
    region: '',
  });

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  // Add message to chat
  const addMessage = (text, sender = 'user') => {
    setMessages((prev) => [
      ...prev,
      {
        from: sender === 'user' ? 'user' : 'bot',
        text,
        type: 'text',
      },
    ]);
  };

  // Refresh instances for selected account
  const handleRefreshInstances = async () => {
    if (!selectedAccount) return;
    try {
      const result = await discoverInstances(selectedAccount);
      if (result.status === 'success' && result.data.instances) {
        setInstances(result.data.instances);
        setMessages((prev) =>
          prev.map((msg) =>
            msg.type === 'instances-table' && msg.data?.accountId === selectedAccount
              ? {
                  ...msg,
                  data: {
                    ...msg.data,
                    instances: result.data.instances,
                  },
                }
              : msg
          )
        );
        return result.data.instances;
      } else {
        throw new Error('Failed to fetch instance data');
      }
    } catch (error) {
      throw error;
    }
  };

  // Intent detection helpers
  const checkCloudWatchIntent = (userInput) =>
    ['cloudwatch', 'configure', 'agent', 'install', 'setup', 'monitor', 'start', 'deploy'].some((k) =>
      userInput.toLowerCase().includes(k)
    );

  const checkAlarmIntent = (userInput) =>
    ['alarm', 'alert', 'threshold', 'notification', 'warning', 'metric'].some((k) =>
      userInput.toLowerCase().includes(k)
    );

  const checkInstanceTypeChangeIntent = (userInput) =>
    ['change', 'resize', 'upgrade', 'instance type', 'scale', 'modify instance'].some((k) =>
      userInput.toLowerCase().includes(k)
    );

  const checkVolumeConversionIntent = (userInput) =>
    ['volume', 'gp2', 'gp3', 'storage', 'convert', 'migrate', 'cost saving', 'optimize storage'].some((k) =>
      userInput.toLowerCase().includes(k)
    );

  const checkAssessmentReportIntent = (userInput) =>
    ['report', 'assessment', 'generate', 'architecture', 'analysis', 'review'].some((k) =>
      userInput.toLowerCase().includes(k)
    );

  // Fetch account groups
  const fetchAccountGroups = async () => {
    try {
      const result = await discoverAccounts();
      if (result.status === 'success') {
        setAccountGroups(result.data.accountGroups || []);
        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text: 'Here are your AWS accounts:',
            type: 'account-groups',
            data: result.data.accountGroups || [],
          },
        ]);
      } else {
        throw new Error(result.message);
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          from: 'bot',
          text: 'Sorry, I encountered an error while fetching your accounts. Please try again.',
          type: 'text',
        },
      ]);
    }
  };

  // Account selection
  const handleAccountSelect = async (accountId) => {
    setSelectedAccount(accountId);
    setMessages((prev) => [
      ...prev,
      { from: 'user', text: `Selected account: ${accountId}`, type: 'text' },
      { from: 'bot', text: `Scanning account ${accountId}...`, type: 'text' },
    ]);
    setLoading(true);
    try {
      const result = await discoverInstances(accountId);
      if (result.status === 'success') {
        const instancesWithAlarms = result.data.instances || [];
        setInstances(instancesWithAlarms);

        const unconfiguredCount = instancesWithAlarms.filter(
          (i) => i.ActionNeeded && i.State === 'running'
        ).length;
        const configuredCount = instancesWithAlarms.filter(
          (i) => i.CloudWatchConfigured && i.State === 'running'
        ).length;
        const alarmsConfiguredCount = instancesWithAlarms.filter(
          (i) => i.AlarmsConfigured && i.State === 'running'
        ).length;

        let message = `Found ${result.data.instances.length} instances in total:<br>
🔧 ${unconfiguredCount} instances need CloudWatch agent installation<br>
✅ ${configuredCount} instances have CloudWatch agent configured<br>
🎯 ${alarmsConfiguredCount} instances have alarms configured<br><br>
💡 <strong>Available Actions:</strong><br>
• <strong>CloudWatch Agent:</strong> Install monitoring on unconfigured instances<br>
• <strong>Volume Conversion:</strong> Convert GP2 volumes to GP3 for cost savings (up to 20%)<br>
• <strong>Instance Type Change:</strong> Resize instances for better performance<br>
• <strong>Alarm Configuration:</strong> Set up monitoring thresholds<br>
• <strong>Assessment Report:</strong> Generate comprehensive AWS assessment report<br>
<br>Use the action buttons in the table below to manage your instances:`;

        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text: message,
            type: 'instances-table',
            data: { instances: instancesWithAlarms, accountId },
          },
        ]);
      } else {
        throw new Error(result.message);
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          from: 'bot',
          text: 'Sorry, I encountered an error while scanning instances. Please try again.',
          type: 'text',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Confirmation modal for CW agent deployment
  const handleInstanceSelect = async (instanceId, region) => {
    setConfirmationModal({
      show: true,
      instanceId,
      region,
    });
  };

  const handleConfirmDeployment = () => {
    const { instanceId, region } = confirmationModal;
    setConfirmationModal({ show: false, instanceId: '', region: '' });
    proceedWithDeployment(instanceId, region);
  };

  const handleCancelDeployment = () => {
    setConfirmationModal({ show: false, instanceId: '', region: '' });
  };

  // Proceed with deployment
  const proceedWithDeployment = async (instanceId, region) => {
    setMessages((prev) => [
      ...prev,
      { from: 'user', text: `Configure CloudWatch agent on: ${instanceId}`, type: 'text' },
      { from: 'bot', text: `Configuring CloudWatch agent on instance ${instanceId} in region ${region}...`, type: 'text' },
    ]);
    setLoading(true);

    try {
      const result = await deployCloudWatchAgent({
        instanceId,
        accountId: selectedAccount,
        region: region,
      });
      if (result.status === 'success') {
        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text:
              `✅ CloudWatch agent installation initiated successfully on ${instanceId}!<br><br>` +
              `Command ID: ${result.data.commandId}<br>` +
              `Estimated completion time: ~10 minutes<br><br>` +
              `You can monitor the installation progress in AWS Systems Manager console.<br><br>` +
              `💡 Once the agent is installed, you can configure CloudWatch alarms for this instance!`,
            type: 'text',
          },
        ]);
      } else {
        throw new Error(result.message);
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          from: 'bot',
          text:
            `❌ Failed to configure CloudWatch agent on ${instanceId}.<br><br>` +
            `Error: ${error.message}<br><br>` +
            `Please check the instance permissions and try again.`,
          type: 'text',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Main message handler
  const handleSend = async () => {
    const value = input.trim();
    if (!value) return;
    setMessages((prev) => [...prev, { from: 'user', text: value, type: 'text' }]);
    setInput('');
    setLoading(true);

    try {
      // Assessment Report intent
      if (checkAssessmentReportIntent(value)) {
        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text:
              `📊 <strong>Great! I'll help you generate a comprehensive AWS assessment report.</strong><br><br>` +
              `This report includes:<br>` +
              `✅ Architecture analysis with Bedrock Nova Pro<br>` +
              `✅ Multi-region AWS resource discovery<br>` +
              `✅ Cost optimization analysis<br>` +
              `✅ Security validation (17+ checks)<br>` +
              `✅ Performance efficiency review<br>` +
              `✅ Well-Architected Framework assessment<br><br>` +
              `Let me show you your accounts so you can select one to analyze:`,
            type: 'text',
          },
        ]);
        await fetchAccountGroups();
      }
      // Volume Conversion intent
      else if (checkVolumeConversionIntent(value)) {
        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text:
              `🎯 <strong>Great choice! GP2 to GP3 volume conversion can save you up to 20% on storage costs while improving performance.</strong><br><br>` +
              `I'll help you convert your GP2 volumes to GP3! This optimization offers:<br><br>` +
              `🔧 <strong>Process:</strong><br>` +
              `• No downtime required - conversion happens live<br>` +
              `• Takes 5-15 minutes per volume<br>` +
              `• Automatic performance optimization<br><br>` +
              `Let me show you your instances so you can select volumes for conversion:`,
            type: 'text',
          },
        ]);
        await fetchAccountGroups();
      }
      // Instance Type Change intent
      else if (checkInstanceTypeChangeIntent(value)) {
        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text:
              `🔧 <strong>I'll help you change instance types safely!</strong><br><br>` +
              `⚠️ <strong>Important Notes:</strong><br>` +
              `• Instance type changes require a stop/start cycle<br>` +
              `• Expect 2-5 minutes of downtime during the change<br>` +
              `• All data on instance store volumes will be lost<br>` +
              `• EBS volumes and network settings are preserved<br><br>` +
              `🎯 <strong>Benefits:</strong><br>` +
              `• Optimize performance for your workload<br>` +
              `• Right-size instances for cost efficiency<br>` +
              `• Upgrade to newer generation instances<br><br>` +
              `Let me show you your instances so you can select which ones need type changes:`,
            type: 'text',
          },
        ]);
        await fetchAccountGroups();
      }
      // CloudWatch intent
      else if (checkCloudWatchIntent(value)) {
        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text: "I'll scan your accounts ...",
            type: 'text',
          },
        ]);
        await fetchAccountGroups();
      }
      // Alarm intent
      else if (checkAlarmIntent(value)) {
        setMessages((prev) => [
          ...prev,
          {
            from: 'bot',
            text:
              "I'll help you configure CloudWatch alarms! First, let me show you your instances so you can select which ones need alarm configuration...",
            type: 'text',
          },
        ]);
        await fetchAccountGroups();
      }
      // Regular chat
      else {
        const result = await sendMessage({ sessionId, message: value });
        if (result.status === 'success') {
          let botReply = result.data?.message || "Sorry, I didn't understand that.";
          botReply += `<br><br>💡 <strong>Try saying:</strong><br>• 'generate assessment report'<br>• 'configure cloudwatch agent'<br>• 'set up alarms'<br>• 'change instance type'<br>• 'convert volumes to GP3'<br>• 'show my instances'`;
          setMessages((prev) => [...prev, { from: 'bot', text: botReply, type: 'text' }]);
        } else {
          throw new Error(result.message);
        }
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          from: 'bot',
          text:
            `Error communicating with backend. Please try again.<br><br>` +
            `💡 <strong>Available commands:</strong><br>` +
            `• 'generate report'<br>` +
            `• 'configure cloudwatch'<br>` +
            `• 'set up alarms'<br>` +
            `• 'change instance type'<br>` +
            `• 'convert volumes to GP3'`,
          type: 'text',
        },
      ]);
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
            <span className="mojobot-dot" /> Ready to help you! 💿 GP2→GP3 • 🔧 Instance Types • ⚠️ Alarms • 📊 Reports
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
                <AccountGroupsCard accountGroups={msg.data} onAccountSelect={handleAccountSelect} />
              </div>
            )}

            {msg.type === 'instances-table' && msg.from === 'bot' && (
              <div className="mojobot-bubble mojobot-bot">
                <div dangerouslySetInnerHTML={{ __html: msg.text.replace(/\n/g, "<br />") }} />
                <InstanceDetailsTable
                  instances={instances}
                  setInstances={setInstances}
                  accountId={msg.data.accountId}
                  onInstanceSelect={(instanceId) => {
                    const instance = instances.find((i) => i.InstanceId === instanceId);
                    handleInstanceSelect(instanceId, instance.Region);
                  }}
                  onAddMessage={addMessage}
                  onRefresh={handleRefreshInstances}
                />
                {/* Assessment Report Button */}
                {selectedAccount && (
                  <div style={{ marginTop: '20px' }}>
                    <AssessmentReportButton accountId={selectedAccount} region="us-east-1" />
                  </div>
                )}
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
          placeholder="Try: 'generate report', 'convert volumes to GP3', 'change instance type'..."
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
 
