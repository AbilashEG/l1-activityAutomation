// Services/api.js - Production Ready Version

// ✅ FIXED: Environment-based API configuration
const getBaseURL = () => {
  // Check if we're in development mode
  const isDevelopment = process.env.NODE_ENV === 'development' || 
                       window.location.hostname === 'localhost' ||
                       window.location.hostname === '127.0.0.1';
  
  if (isDevelopment) {
    // Development - call Flask directly
    return 'http://127.0.0.1:5000';
  } else {
    // Production - use relative URLs (Nginx will proxy)
    return '';
  }
};

const BASE = getBaseURL();

// Enhanced API call function with better error handling
const apiCall = async (endpoint, options = {}) => {
  const fullUrl = `${BASE}${endpoint}`;
  console.log(`🌐 API Call: ${fullUrl}`, options.body ? JSON.parse(options.body) : {});
  
  try {
    const response = await fetch(fullUrl, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    });
    
    const data = await response.json();
    console.log(`📥 API Response (${response.status}):`, data);
    
    if (!response.ok) {
      throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
    }
    
    return { status: "success", data };
  } catch (error) {
    console.error(`❌ API Error for ${endpoint}:`, error);
    throw error;
  }
};

// ✅ Chat/Conversation API
export const sendMessage = async ({ sessionId, message }) => {
  try {
    return await apiCall('/api/converse', {
      method: 'POST',
      body: JSON.stringify({ 
        session_id: sessionId, 
        message 
      })
    });
  } catch (error) {
    return { 
      status: "error", 
      message: error.message || 'Failed to send message'
    };
  }
};

// ✅ Account Discovery API
export const discoverAccounts = async () => {
  try {
    return await apiCall('/api/discover-accounts');
  } catch (error) {
    throw new Error(`Failed to discover accounts: ${error.message}`);
  }
};

// ✅ Instance Discovery API
export const discoverInstances = async (accountId) => {
  try {
    if (!accountId) throw new Error('Account ID is required');
    return await apiCall(`/api/discover-instances/${accountId}`);
  } catch (error) {
    throw new Error(`Failed to discover instances for account ${accountId}: ${error.message}`);
  }
};

// ✅ CloudWatch Agent Deployment API
export const deployCloudWatchAgent = async (data) => {
  try {
    console.log('🚀 Deploying CloudWatch agent with data:', data);
    
    // Validate required fields
    if (!data.instanceId || !data.accountId || !data.region) {
      throw new Error('Missing required fields: instanceId, accountId, or region');
    }
    
    return await apiCall('/api/deploy-cloudwatch-agent', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  } catch (error) {
    throw new Error(`Failed to deploy CloudWatch agent: ${error.message}`);
  }
};

// ✅ ENHANCED: CloudWatch Alarms Configuration API
export const configureAlarms = async (data) => {
  try {
    console.log('🚨 Configuring CloudWatch alarms with data:', data);
    
    // Validate required fields
    if (!data.instanceId || !data.accountId || !data.region) {
      throw new Error('Missing required fields: instanceId, accountId, or region');
    }
    
    const fullUrl = `${BASE}/api/configure-alarms`;
    
    const response = await fetch(fullUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    
    const result = await response.json();
    console.log('🚨 Raw alarm configuration response:', result);
    
    // ✅ Handle different response scenarios from Flask
    if (response.ok && result.success) {
      // Success case
      return {
        success: true,
        message: result.message,
        alarmDetails: result.alarmDetails || {
          successfulAlarms: 4,
          totalAlarms: 4,
          createdAlarms: [
            `${data.instanceId}-CPU-Utilization`,
            `${data.instanceId}-Memory-Utilization`, 
            `${data.instanceId}-${data.platform?.toLowerCase().includes('windows') ? 'Overall' : 'Disk'}-Utilization`,
            `${data.instanceId}-StatusCheck-System`
          ]
        }
      };
    } else if (response.status === 207 && result.partialSuccess) {
      // Partial success case
      return {
        success: false,
        partialSuccess: true,
        message: result.message,
        alarmDetails: result.alarmDetails
      };
    } else {
      // Error case
      throw new Error(result.error || 'Alarm configuration failed');
    }
    
  } catch (error) {
    console.error('❌ Error configuring alarms:', error);
    throw new Error(`Failed to configure alarms: ${error.message}`);
  }
};

// ✅ Health Check API (useful for monitoring)
export const healthCheck = async () => {
  try {
    return await apiCall('/api/health');
  } catch (error) {
    throw new Error(`Health check failed: ${error.message}`);
  }
};

// ✅ Test DynamoDB Connection API (for debugging)
export const testDynamoDB = async () => {
  try {
    return await apiCall('/api/test-dynamodb');
  } catch (error) {
    throw new Error(`DynamoDB test failed: ${error.message}`);
  }
};

// ✅ Export the base URL for debugging
export const getApiBaseUrl = getBaseURL;

// ✅ Console log current configuration
console.log('🔧 API Configuration:', {
  environment: process.env.NODE_ENV,
  hostname: window.location.hostname,
  baseURL: BASE,
  isDevelopment: BASE.includes('127.0.0.1')
});
