// utils/api.js - API Client
class APIClient {
    constructor() {
      this.baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      this.authToken = null;
    }
  
    setAuthToken(token) {
      this.authToken = token;
    }
  
    async request(endpoint, options = {}) {
      const url = `${this.baseURL}${endpoint}`;
      
      const defaultHeaders = {
        'Content-Type': 'application/json',
      };
  
      if (this.authToken) {
        defaultHeaders.Authorization = `Bearer ${this.authToken}`;
      }
  
      const config = {
        headers: {
          ...defaultHeaders,
          ...options.headers,
        },
        ...options,
      };
  
      if (config.body && typeof config.body === 'object') {
        config.body = JSON.stringify(config.body);
      }
  
      try {
        const response = await fetch(url, config);
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw {
            response: {
              status: response.status,
              data: errorData
            }
          };
        }
  
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          return await response.json();
        }
        
        return await response.text();
      } catch (error) {
        console.error('API request failed:', error);
        throw error;
      }
    }
  
    async get(endpoint, params = {}) {
      const queryString = new URLSearchParams(params).toString();
      const url = queryString ? `${endpoint}?${queryString}` : endpoint;
      return this.request(url);
    }
  
    async post(endpoint, data = {}) {
      return this.request(endpoint, {
        method: 'POST',
        body: data,
      });
    }
  
    async put(endpoint, data = {}) {
      return this.request(endpoint, {
        method: 'PUT',
        body: data,
      });
    }
  
    async delete(endpoint) {
      return this.request(endpoint, {
        method: 'DELETE',
      });
    }
  
    // Website Analysis
    async analyzeWebsite(url, priority = 'normal') {
      return this.post('/analyze', { url, priority });
    }
  
    async getAnalyses(filters = {}) {
      return this.get('/analyses', filters);
    }
  
    async getAnalysisDetail(id) {
      return this.get(`/analysis/${id}`);
    }
  
    // Outreach
    async getLeads(filters = {}) {
      return this.post('/outreach/leads', filters);
    }
  
    async sendOutreach(email, template_type = 'opportunity', custom_message = null) {
      return this.post('/outreach/send', {
        to_email: email,
        template_type,
        custom_message
      });
    }
  
    // Analytics
    async getDashboardAnalytics(days = 30) {
      return this.get('/analytics/dashboard', { days });
    }
  
    async getTrendAnalytics(metric = 'score', days = 30) {
      return this.get('/analytics/trends', { metric, days });
    }
  
    // Campaigns (Admin)
    async createCampaign(campaignData) {
      return this.post('/campaigns', campaignData);
    }
  
    async getCampaigns() {
      return this.get('/campaigns');
    }
  }
  
  export const apiClient = new APIClient();
  