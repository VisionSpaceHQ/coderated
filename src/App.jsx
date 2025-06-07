import React, { useState, useEffect } from 'react';
import { Search, BarChart3, Users, Mail, Star, ChevronRight, Globe, TrendingUp, Eye, Settings, LogOut, Download, Filter, ExternalLink, Clock, CheckCircle, AlertCircle, XCircle } from 'lucide-react';

// Mock API client (replace with real API calls)
const apiClient = {
  async analyzeWebsite(url, priority = 'normal') {
    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Mock analysis result
    return {
      url,
      domain: new URL(url.startsWith('http') ? url : `https://${url}`).hostname,
      title: `Analysis for ${url}`,
      score: Math.floor(Math.random() * 40) + 60,
      scores: {
        ux_design: Math.floor(Math.random() * 30) + 70,
        seo_fundamentals: Math.floor(Math.random() * 25) + 65,
        speed_optimization: Math.floor(Math.random() * 35) + 60,
        visual_identity: Math.floor(Math.random() * 25) + 75,
        strategic_copy: Math.floor(Math.random() * 30) + 68
      },
      industry: ['Technology', 'E-commerce', 'Local Business', 'Professional Services'][Math.floor(Math.random() * 4)],
      contact_info: {
        email: `contact@${new URL(url.startsWith('http') ? url : `https://${url}`).hostname}`,
        company_name: `${new URL(url.startsWith('http') ? url : `https://${url}`).hostname.split('.')[0]} Inc.`
      },
      analysis_summary: {
        working: "Strong visual design and clear navigation structure with good brand consistency throughout the site.",
        improvements: "Page loading speeds could be optimized, and mobile responsiveness needs enhancement for better user experience.",
        invitation: "We'd love to share specific recommendations to help boost your online presence and conversion rates!"
      },
      timestamp: new Date().toISOString()
    };
  },

  async getAnalyses(filters = {}) {
    // Mock analyses data
    const mockAnalyses = Array.from({ length: 12 }, (_, i) => ({
      id: i + 1,
      url: `https://example-site-${i + 1}.com`,
      domain: `example-site-${i + 1}.com`,
      title: `Example Business ${i + 1}`,
      score: Math.floor(Math.random() * 40) + 60,
      industry: ['Technology', 'E-commerce', 'Local Business', 'Professional Services', 'Healthcare'][Math.floor(Math.random() * 5)],
      contact_email: `contact@example-site-${i + 1}.com`,
      company_name: `Example Company ${i + 1}`,
      created_at: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString()
    }));
    
    return mockAnalyses;
  },

  async getDashboardAnalytics() {
    return {
      summary: {
        total_analyses: 1247,
        avg_score: 73.2,
        with_contact: 892
      },
      score_distribution: {
        excellent: 124,
        good: 286,
        fair: 451,
        poor: 312,
        critical: 74
      },
      top_industries: [
        { industry: 'Local Business', count: 387 },
        { industry: 'E-commerce', count: 254 },
        { industry: 'Professional Services', count: 196 },
        { industry: 'Technology', count: 143 },
        { industry: 'Healthcare', count: 127 }
      ],
      outreach_stats: {
        emails_sent: 234,
        emails_opened: 156,
        emails_replied: 42
      }
    };
  }
};

// Utility functions
const getScoreColor = (score) => {
  if (score >= 90) return 'text-green-400';
  if (score >= 80) return 'text-green-300';
  if (score >= 70) return 'text-yellow-400';
  if (score >= 60) return 'text-orange-400';
  return 'text-red-400';
};

const getScoreGrade = (score) => {
  if (score >= 90) return 'Excellent';
  if (score >= 80) return 'Good';
  if (score >= 70) return 'Fair';
  if (score >= 60) return 'Poor';
  return 'Critical';
};

// Analysis Result Component
const AnalysisResult = ({ result }) => (
  <div className="mt-8 p-6 bg-slate-700/30 rounded-2xl border border-slate-600/50">
    <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
      <div>
        <h3 className="text-2xl font-bold text-white mb-2">{result.contact_info.company_name}</h3>
        <p className="text-gray-300 flex items-center">
          <ExternalLink className="w-4 h-4 mr-2" />
          <a href={result.url} target="_blank" rel="noopener noreferrer" className="hover:text-blue-400 transition-colors">
            {result.domain}
          </a>
        </p>
        <p className="text-sm text-gray-400 mt-1">{result.industry}</p>
      </div>
      <div className="mt-4 md:mt-0 text-center">
        <div className={`text-4xl font-bold ${getScoreColor(result.score)} mb-1`}>
          {result.score}
        </div>
        <div className="text-sm text-gray-400">Overall Score</div>
        <div className={`text-xs px-2 py-1 rounded-full mt-1 ${
          result.score >= 80 ? 'bg-green-500/20 text-green-300' :
          result.score >= 60 ? 'bg-yellow-500/20 text-yellow-300' :
          'bg-red-500/20 text-red-300'
        }`}>
          {getScoreGrade(result.score)}
        </div>
      </div>
    </div>

    {/* Score Breakdown */}
    <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
      {Object.entries(result.scores).map(([key, value]) => (
        <div key={key} className="text-center p-3 bg-slate-600/30 rounded-lg">
          <div className={`text-xl font-bold ${getScoreColor(value)} mb-1`}>{value}</div>
          <div className="text-xs text-gray-400 capitalize">
            {key.replace('_', ' ')}
          </div>
        </div>
      ))}
    </div>

    {/* AI Summary */}
    <div className="space-y-4">
      <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
        <h4 className="text-green-300 font-semibold mb-2 flex items-center">
          <CheckCircle className="w-4 h-4 mr-2" />
          What's Working Well
        </h4>
        <p className="text-gray-300 text-sm">{result.analysis_summary.working}</p>
      </div>
      
      <div className="p-4 bg-orange-500/10 border border-orange-500/20 rounded-lg">
        <h4 className="text-orange-300 font-semibold mb-2 flex items-center">
          <AlertCircle className="w-4 h-4 mr-2" />
          Improvement Opportunities
        </h4>
        <p className="text-gray-300 text-sm">{result.analysis_summary.improvements}</p>
      </div>
      
      <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
        <h4 className="text-blue-300 font-semibold mb-2 flex items-center">
          <Star className="w-4 h-4 mr-2" />
          Our Recommendation
        </h4>
        <p className="text-gray-300 text-sm">{result.analysis_summary.invitation}</p>
      </div>
    </div>

    {/* Contact Info */}
    {result.contact_info.email && (
      <div className="mt-6 p-4 bg-slate-600/30 rounded-lg">
        <h4 className="text-white font-semibold mb-2">Contact Information</h4>
        <div className="text-sm text-gray-300">
          <p>📧 {result.contact_info.email}</p>
          <p>🏢 {result.contact_info.company_name}</p>
        </div>
      </div>
    )}
  </div>
);

// Stat Card Component
const StatCard = ({ number, label, icon, gradient }) => (
  <div className="bg-slate-800/50 backdrop-blur-xl rounded-2xl p-6 border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200">
    <div className="flex items-center justify-between mb-4">
      <div className={`p-3 rounded-xl bg-gradient-to-r ${gradient} bg-opacity-20`}>
        <div className="text-white">{icon}</div>
      </div>
    </div>
    <div className="text-3xl font-bold text-white mb-2">{number}</div>
    <div className="text-gray-400 text-sm">{label}</div>
  </div>
);

// Main App Component
const CodeRatedApp = () => {
  const [currentView, setCurrentView] = useState('home');
  const [user] = useState({
    name: 'Alex Chen',
    email: 'alex@company.com',
    tier: 'business',
    avatar: '👨‍💼'
  });
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [searchUrl, setSearchUrl] = useState('');
  const [analyses, setAnalyses] = useState([]);
  const [analytics, setAnalytics] = useState(null);

  useEffect(() => {
    // Load initial data
    loadAnalyses();
    loadAnalytics();
  }, []);

  const loadAnalyses = async () => {
    try {
      const data = await apiClient.getAnalyses();
      setAnalyses(data);
    } catch (error) {
      console.error('Failed to load analyses:', error);
    }
  };

  const loadAnalytics = async () => {
    try {
      const data = await apiClient.getDashboardAnalytics();
      setAnalytics(data);
    } catch (error) {
      console.error('Failed to load analytics:', error);
    }
  };

  const handleAnalyze = async () => {
    if (!searchUrl.trim()) return;
    
    setIsAnalyzing(true);
    setAnalysisResult(null);
    
    try {
      const result = await apiClient.analyzeWebsite(searchUrl);
      setAnalysisResult(result);
      await loadAnalyses(); // Refresh analyses list
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Navigation Component
  const Navigation = () => (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-900/95 backdrop-blur-xl border-b border-slate-700/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center space-x-8">
            <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setCurrentView('home')}>
              <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-600 rounded-xl flex items-center justify-center">
                <span className="text-white font-bold text-lg">R</span>
              </div>
              <span className="text-xl font-bold text-white">CodeRated</span>
            </div>
            
            <div className="hidden md:flex space-x-6">
              <button
                onClick={() => setCurrentView('home')}
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  currentView === 'home' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-300 hover:text-white hover:bg-slate-700/50'
                }`}
              >
                <Search className="w-4 h-4 inline mr-2" />
                Analyze
              </button>
              <button
                onClick={() => setCurrentView('dashboard')}
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  currentView === 'dashboard' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-300 hover:text-white hover:bg-slate-700/50'
                }`}
              >
                <BarChart3 className="w-4 h-4 inline mr-2" />
                Dashboard
              </button>
              <button
                onClick={() => setCurrentView('analyses')}
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  currentView === 'analyses' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-300 hover:text-white hover:bg-slate-700/50'
                }`}
              >
                <Globe className="w-4 h-4 inline mr-2" />
                Analyses
              </button>
            </div>
          </div>

          {user && (
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-300">
                <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded-full uppercase tracking-wide">
                  {user.tier}
                </span>
              </div>
              <div className="flex items-center space-x-3">
                <span className="text-2xl">{user.avatar}</span>
                <div className="hidden md:block text-sm">
                  <div className="text-white font-medium">{user.name}</div>
                  <div className="text-gray-400 text-xs">{user.email}</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </nav>
  );

  // Home/Analysis View
  const HomeView = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Background Effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl"></div>
        <div className="absolute top-1/2 -left-40 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl"></div>
        <div className="absolute -bottom-40 right-1/3 w-80 h-80 bg-pink-500/10 rounded-full blur-3xl"></div>
      </div>

      <div className="relative pt-24 pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          {/* Hero Section */}
          <div className="text-center mb-16">
            <h1 className="text-6xl md:text-7xl font-bold bg-gradient-to-r from-white via-blue-100 to-purple-200 bg-clip-text text-transparent mb-6">
              AI Website Intelligence
            </h1>
            <p className="text-xl text-gray-300 mb-4 max-w-3xl mx-auto">
              Discover, analyze, and improve websites with advanced AI-powered insights
            </p>
            <p className="text-lg text-gray-400 max-w-2xl mx-auto">
              Get comprehensive scores for UX design, SEO, speed optimization, visual identity, and strategic copy
            </p>
          </div>

          {/* Analysis Section */}
          <div className="max-w-4xl mx-auto mb-16">
            <div className="bg-slate-800/50 backdrop-blur-xl rounded-3xl p-8 border border-slate-700/50 shadow-2xl">
              <div className="flex flex-col md:flex-row gap-4 mb-6">
                <div className="flex-1">
                  <input
                    type="text"
                    value={searchUrl}
                    onChange={(e) => setSearchUrl(e.target.value)}
                    placeholder="Enter website URL (e.g., example.com)"
                    className="w-full px-6 py-4 bg-slate-700/50 border border-slate-600/50 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 text-lg"
                    onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
                  />
                </div>
                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing || !searchUrl.trim()}
                  className="px-8 py-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-xl font-semibold hover:from-blue-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg hover:shadow-xl whitespace-nowrap"
                >
                  {isAnalyzing ? (
                    <div className="flex items-center space-x-2">
                      <div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                      <span>Analyzing...</span>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <Search className="w-5 h-5" />
                      <span>Analyze Website</span>
                    </div>
                  )}
                </button>
              </div>

              {/* Analysis Result */}
              {analysisResult && (
                <AnalysisResult result={analysisResult} />
              )}
            </div>
          </div>

          {/* Stats Grid */}
          {analytics && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-16">
              <StatCard
                number={analytics.summary.total_analyses.toLocaleString()}
                label="Websites Analyzed"
                icon={<Globe className="w-6 h-6" />}
                gradient="from-blue-500 to-cyan-500"
              />
              <StatCard
                number={`${analytics.summary.avg_score.toFixed(1)}/100`}
                label="Average Score"
                icon={<Star className="w-6 h-6" />}
                gradient="from-purple-500 to-pink-500"
              />
              <StatCard
                number={analytics.summary.with_contact.toLocaleString()}
                label="Contact Info Found"
                icon={<Mail className="w-6 h-6" />}
                gradient="from-green-500 to-emerald-500"
              />
              <StatCard
                number={analytics.outreach_stats.emails_sent.toLocaleString()}
                label="Outreach Emails Sent"
                icon={<TrendingUp className="w-6 h-6" />}
                gradient="from-orange-500 to-red-500"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // Dashboard View
  const DashboardView = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="pt-24 pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex justify-between items-center mb-8">
            <h1 className="text-4xl font-bold text-white">Analytics Dashboard</h1>
            <button className="flex items-center space-x-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors">
              <Download className="w-4 h-4" />
              <span>Export Report</span>
            </button>
          </div>

          {analytics && (
            <>
              {/* Summary Stats */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
                <StatCard
                  number={analytics.summary.total_analyses.toLocaleString()}
                  label="Total Analyses"
                  icon={<BarChart3 className="w-6 h-6" />}
                  gradient="from-blue-500 to-cyan-500"
                />
                <StatCard
                  number={`${analytics.summary.avg_score.toFixed(1)}/100`}
                  label="Average Score"
                  icon={<Star className="w-6 h-6" />}
                  gradient="from-purple-500 to-pink-500"
                />
                <StatCard
                  number={`${((analytics.summary.with_contact / analytics.summary.total_analyses) * 100).toFixed(1)}%`}
                  label="Contact Rate"
                  icon={<Users className="w-6 h-6" />}
                  gradient="from-green-500 to-emerald-500"
                />
                <StatCard
                  number={`${((analytics.outreach_stats.emails_replied / analytics.outreach_stats.emails_sent) * 100).toFixed(1)}%`}
                  label="Reply Rate"
                  icon={<Mail className="w-6 h-6" />}
                  gradient="from-orange-500 to-red-500"
                />
              </div>

              {/* Score Distribution */}
              <div className="bg-slate-800/50 backdrop-blur-xl rounded-2xl p-8 border border-slate-700/50 mb-8">
                <h2 className="text-2xl font-bold text-white mb-6">Score Distribution</h2>
                <div className="grid grid-cols-5 gap-4">
                  {Object.entries(analytics.score_distribution).map(([grade, count]) => (
                    <div key={grade} className="text-center">
                      <div className={`text-3xl font-bold mb-2 ${
                        grade === 'excellent' ? 'text-green-400' :
                        grade === 'good' ? 'text-green-300' :
                        grade === 'fair' ? 'text-yellow-400' :
                        grade === 'poor' ? 'text-orange-400' :
                        'text-red-400'
                      }`}>
                        {count}
                      </div>
                      <div className="text-gray-400 text-sm capitalize">{grade}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Industries */}
              <div className="bg-slate-800/50 backdrop-blur-xl rounded-2xl p-8 border border-slate-700/50">
                <h2 className="text-2xl font-bold text-white mb-6">Top Industries</h2>
                <div className="space-y-4">
                  {analytics.top_industries.map((industry, index) => (
                    <div key={industry.industry} className="flex items-center justify-between p-4 bg-slate-700/30 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg flex items-center justify-center text-white font-bold text-sm">
                          {index + 1}
                        </div>
                        <span className="text-white font-medium">{industry.industry}</span>
                      </div>
                      <div className="text-gray-300">{industry.count} sites</div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );

  // Analyses List View
  const AnalysesView = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="pt-24 pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex justify-between items-center mb-8">
            <h1 className="text-4xl font-bold text-white">Website Analyses</h1>
            <div className="flex items-center space-x-4">
              <button className="flex items-center space-x-2 px-4 py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600 transition-colors">
                <Filter className="w-4 h-4" />
                <span>Filter</span>
              </button>
              <button className="flex items-center space-x-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors">
                <Download className="w-4 h-4" />
                <span>Export</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {analyses.map((analysis) => (
              <div key={analysis.id} className="bg-slate-800/50 backdrop-blur-xl rounded-2xl p-6 border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-white mb-1">{analysis.company_name}</h3>
                    <p className="text-gray-400 text-sm mb-1">{analysis.domain}</p>
                    <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-300 rounded-full">{analysis.industry}</span>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold ${getScoreColor(analysis.score)} mb-1`}>
                      {analysis.score}
                    </div>
                    <div className="text-xs text-gray-400">Score</div>
                  </div>
                </div>

                <div className="flex items-center justify-between text-sm text-gray-400 mb-4">
                  <div className="flex items-center space-x-1">
                    <Clock className="w-4 h-4" />
                    <span>{new Date(analysis.created_at).toLocaleDateString()}</span>
                  </div>
                  {analysis.contact_email && (
                    <div className="flex items-center space-x-1 text-green-400">
                      <CheckCircle className="w-4 h-4" />
                      <span>Contact</span>
                    </div>
                  )}
                </div>

                <div className="flex space-x-2">
                  <button className="flex-1 px-3 py-2 bg-blue-500/20 text-blue-300 rounded-lg hover:bg-blue-500/30 transition-colors text-sm">
                    <Eye className="w-4 h-4 inline mr-1" />
                    View Details
                  </button>
                  {analysis.contact_email && (
                    <button className="px-3 py-2 bg-green-500/20 text-green-300 rounded-lg hover:bg-green-500/30 transition-colors text-sm">
                      <Mail className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  
  // Render appropriate view
  const renderCurrentView = () => {
    switch (currentView) {
      case 'dashboard':
        return <DashboardView />;
      case 'analyses':
        return <AnalysesView />;
      default:
        return <HomeView />;
    }
  };

  return (
    <div className="min-h-screen">
      <Navigation />
      {renderCurrentView()}
    </div>
  );
};

export default CodeRatedApp;