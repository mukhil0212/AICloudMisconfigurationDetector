"use client";
import { useState, useEffect } from "react";
import ReactMarkdown from 'react-markdown';

interface Misconfiguration {
  type: string;
  resource_id: string;
  details: string;
  ai_suggestion?: string;
  confidence?: string;
  confidence_score?: number;
  can_remediate?: boolean;
  scanned_by?: string;
}

interface AWSCredentials {
  access_key_id: string;
  secret_access_key: string;
  region: string;
}

interface User {
  username: string;
  role: string;
  email?: string;
}

interface ScanResponse {
  findings: Misconfiguration[];
  scan_metadata: {
    total_findings: number;
    scanned_by: string;
    scan_type: string;
    timestamp?: string;
  };
}

const getSeverityColor = (type: string) => {
  if (type.includes("Public S3") || type.includes("Unrestricted")) return "bg-red-100 text-red-800 border-red-200";
  if (type.includes("IAM") || type.includes("Permissive")) return "bg-orange-100 text-orange-800 border-orange-200";
  return "bg-yellow-100 text-yellow-800 border-yellow-200";
};

const getTypeIcon = (type: string) => {
  if (type.includes("S3")) return "🪣";
  if (type.includes("IAM")) return "👤";
  if (type.includes("Security Group")) return "🛡️";
  return "⚠️";
};

export default function Dashboard() {
  const [scanResponse, setScanResponse] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showCredentials, setShowCredentials] = useState(false);
  const [credentials, setCredentials] = useState<AWSCredentials>({
    access_key_id: "",
    secret_access_key: "",
    region: "us-east-1"
  });
  const [useAI, setUseAI] = useState(true);
  const [expandedSuggestion, setExpandedSuggestion] = useState<number | null>(null);
  const [isClient, setIsClient] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(true);
  const [loginCredentials, setLoginCredentials] = useState({ username: "", password: "" });
  const [confidenceThreshold, setConfidenceThreshold] = useState(0.7);
  const [strictnessLevel, setStrictnessLevel] = useState("balanced");

  // Ensure component only renders on client side to avoid hydration mismatch
  useEffect(() => {
    setIsClient(true);
    // Check for existing token
    const savedToken = localStorage.getItem('auth_token');
    const savedUser = localStorage.getItem('user_data');
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
      setShowLogin(false);
    }
  }, []);

  if (!isClient) {
    return null; // Return nothing during SSR
  }

  const login = async () => {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginCredentials)
      });

      if (!res.ok) throw new Error("Invalid credentials");
      
      const data = await res.json();
      setToken(data.access_token);
      setUser(data.user);
      setShowLogin(false);
      
      // Save to localStorage
      localStorage.setItem('auth_token', data.access_token);
      localStorage.setItem('user_data', JSON.stringify(data.user));
    } catch (err: any) {
      setError(err.message || "Login failed");
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    setShowLogin(true);
    setScanResponse(null);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_data');
  };

  const scanCloud = async () => {
    if (!token) {
      setError("Please login first");
      return;
    }

    setLoading(true);
    setError("");
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      
      const endpoint = useAI ? "/scan-with-suggestions" : "/scan";
      const hasCredentials = showCredentials && credentials.access_key_id && credentials.secret_access_key;
      const method = (hasCredentials || useAI) ? "POST" : "GET";
      
      let requestBody = undefined;
      if (method === "POST") {
        requestBody = {
          credentials: hasCredentials ? credentials : null,
          ai_confidence_threshold: confidenceThreshold,
          strictness_level: strictnessLevel
        };
      }

      const res = await fetch(`${apiUrl}${endpoint}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: requestBody ? JSON.stringify(requestBody) : undefined
      });

      if (!res.ok) {
        if (res.status === 401) {
          logout();
          throw new Error("Session expired. Please login again.");
        }
        const errorText = await res.text();
        throw new Error(`HTTP ${res.status}: ${res.statusText}. ${errorText}`);
      }
      
      const data = await res.json();
      
      // Handle both old format (array) and new format (object with findings)
      if (Array.isArray(data)) {
        setScanResponse({
          findings: data,
          scan_metadata: {
            total_findings: data.length,
            scanned_by: user?.username || "unknown",
            scan_type: "basic"
          }
        });
      } else {
        setScanResponse(data);
      }
    } catch (err: any) {
      console.error("Request error:", err);
      if (err.name === 'TypeError' && err.message.includes('fetch')) {
        setError("Cannot connect to backend. Make sure the backend server is running.");
      } else {
        setError(err.message || "Unknown error occurred");
      }
    }
    setLoading(false);
  };

  // Login screen
  if (showLogin) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 rounded-full mb-4">
              <span className="text-2xl text-white">🔐</span>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Cloud Security Platform</h1>
            <p className="text-gray-600">Enterprise Security Management</p>
          </div>
          
          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-red-700 text-sm">
              {error}
            </div>
          )}
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
              <input
                type="text"
                value={loginCredentials.username}
                onChange={(e) => setLoginCredentials({...loginCredentials, username: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="admin or viewer"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input
                type="password"
                value={loginCredentials.password}
                onChange={(e) => setLoginCredentials({...loginCredentials, password: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="••••••••"
              />
            </div>
            <button
              onClick={login}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition-colors"
            >
              Login
            </button>
          </div>
          
          <div className="mt-6 text-xs text-gray-500 bg-gray-50 p-3 rounded">
            <strong>Demo Accounts:</strong><br/>
            • admin / admin123 (Full access)<br/>
            • viewer / viewer123 (Read-only)
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-between items-center mb-6">
            <div className="flex items-center">
              <div className="inline-flex items-center justify-center w-12 h-12 bg-blue-600 rounded-full mr-3">
                <span className="text-xl text-white">🔐</span>
              </div>
              <div className="text-left">
                <h1 className="text-2xl font-bold text-gray-900">Cloud Security Dashboard</h1>
                <p className="text-gray-600 text-sm">Enterprise Security Management</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-sm font-medium text-gray-900">{user?.username}</div>
                <div className="text-xs text-gray-500 capitalize">{user?.role} Account</div>
              </div>
              <button
                onClick={logout}
                className="bg-gray-500 text-white px-4 py-2 rounded-md hover:bg-gray-600 transition-colors text-sm"
              >
                Logout
              </button>
            </div>
          </div>
        </div>

        {/* Configuration Panel */}
        <div className="max-w-4xl mx-auto mb-8">
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan Configuration</h3>
            
            {/* AI Toggle */}
            <div className="flex items-center justify-between mb-4 p-3 bg-blue-50 rounded-lg">
              <div className="flex items-center">
                <span className="text-2xl mr-3">🤖</span>
                <div>
                  <div className="font-medium text-gray-900">AI-Powered Remediation</div>
                  <div className="text-sm text-gray-600">Get AI-generated fix suggestions for detected issues</div>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={useAI}
                  onChange={(e) => setUseAI(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
              </label>
            </div>

            {/* AI Confidence Tuning */}
            {useAI && (
              <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center mb-3">
                  <span className="text-xl mr-2">🎯</span>
                  <div className="font-medium text-gray-900">AI Confidence Tuning</div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Confidence Threshold: {confidenceThreshold}
                    </label>
                    <input
                      type="range"
                      min="0"
                      max="1"
                      step="0.1"
                      value={confidenceThreshold}
                      onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
                      className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
                    />
                    <div className="flex justify-between text-xs text-gray-500 mt-1">
                      <span>Show All</span>
                      <span>High Confidence Only</span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Detection Strictness
                    </label>
                    <select
                      value={strictnessLevel}
                      onChange={(e) => setStrictnessLevel(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="lenient">Lenient (fewer alerts)</option>
                      <option value="balanced">Balanced (recommended)</option>
                      <option value="strict">Strict (more alerts)</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            {/* AWS Credentials Toggle */}
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center">
                <span className="text-2xl mr-3">🔑</span>
                <div>
                  <div className="font-medium text-gray-900">Custom AWS Credentials</div>
                  <div className="text-sm text-gray-600">Use your own AWS credentials for real-time scanning</div>
                </div>
              </div>
              <button
                onClick={() => setShowCredentials(!showCredentials)}
                className="bg-gray-100 hover:bg-gray-200 text-gray-800 px-4 py-2 rounded-lg transition-colors"
              >
                {showCredentials ? "Hide" : "Configure"}
              </button>
            </div>

            {/* Credentials Form */}
            {showCredentials && (
              <div className="border-t pt-4 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Access Key ID
                    </label>
                    <input
                      type="text"
                      value={credentials.access_key_id}
                      onChange={(e) => setCredentials({...credentials, access_key_id: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="AKIA..."
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Secret Access Key
                    </label>
                    <input
                      type="password"
                      value={credentials.secret_access_key}
                      onChange={(e) => setCredentials({...credentials, secret_access_key: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="••••••••••••••••"
                    />
                  </div>
                </div>
                <div className="w-full md:w-1/3">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Region
                  </label>
                  <select
                    value={credentials.region}
                    onChange={(e) => setCredentials({...credentials, region: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="us-east-1">US East (N. Virginia)</option>
                    <option value="us-west-2">US West (Oregon)</option>
                    <option value="eu-west-1">Europe (Ireland)</option>
                    <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                  </select>
                </div>
                <div className="text-sm text-yellow-600 bg-yellow-50 p-3 rounded-lg">
                  <strong>Note:</strong> Your credentials are only used for this scan and are not stored.
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Scan Controls */}
        <div className="flex flex-col items-center mb-8">
          <button
            onClick={scanCloud}
            className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-semibold px-8 py-3 rounded-lg shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:transform-none disabled:hover:shadow-lg"
            disabled={loading}
          >
            {loading ? (
              <div className="flex items-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Scanning...
              </div>
            ) : (
              <div className="flex items-center">
                <span className="mr-2">🔍</span>
                {useAI ? "Start AI-Powered Scan" : "Start Security Scan"}
              </div>
            )}
          </button>
        </div>

        {/* Error Message */}
        {error && (
          <div className="max-w-4xl mx-auto mb-6">
            <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded-r-lg">
              <div className="flex">
                <div className="flex-shrink-0">
                  <span className="text-red-400 text-xl">❌</span>
                </div>
                <div className="ml-3">
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Stats Summary */}
        {scanResponse && scanResponse.findings.length > 0 && (
          <div className="max-w-6xl mx-auto mb-8">
            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Overview</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="text-3xl font-bold text-blue-600">{scanResponse.scan_metadata.total_findings}</div>
                  <div className="text-sm text-gray-600">Total Issues Found</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-orange-600">
                    {scanResponse.findings.filter(f => f.type.includes("Public") || f.type.includes("Unrestricted")).length}
                  </div>
                  <div className="text-sm text-gray-600">High Risk Issues</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-green-600">
                    {scanResponse.findings.filter(f => f.ai_suggestion).length}
                  </div>
                  <div className="text-sm text-gray-600">AI Suggestions</div>
                </div>
              </div>
            </div>

            {/* Scan Metadata */}
            <div className="bg-white rounded-lg shadow-md p-4 mt-4">
              <div className="flex justify-between items-center text-sm text-gray-600">
                <span>Scanned by: <strong>{scanResponse.scan_metadata.scanned_by}</strong></span>
                <span>Scan type: <strong className="capitalize">{scanResponse.scan_metadata.scan_type}</strong></span>
                <span>Confidence threshold: <strong>{confidenceThreshold}</strong></span>
                <span>Strictness: <strong className="capitalize">{strictnessLevel}</strong></span>
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        <div className="max-w-6xl mx-auto">
          {scanResponse && scanResponse.findings.length > 0 ? (
            <div className="bg-white rounded-lg shadow-lg overflow-hidden">
              <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
                <h2 className="text-xl font-semibold text-gray-900">Security Issues Detected</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Issue Type
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Resource ID
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Details
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Confidence
                      </th>
                      {useAI && (
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          AI Remediation
                        </th>
                      )}
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {scanResponse.findings.map((item, idx) => (
                      <tr key={idx} className="hover:bg-gray-50 transition-colors duration-150">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <span className="text-2xl mr-3">{getTypeIcon(item.type)}</span>
                            <div className="text-sm font-medium text-gray-900">{item.type}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900 font-mono bg-gray-100 px-2 py-1 rounded">
                            {item.resource_id}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm text-gray-700">{item.details}</div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex flex-col space-y-1">
                            <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                              item.confidence === "high" ? "bg-green-100 text-green-800" :
                              item.confidence === "medium" ? "bg-yellow-100 text-yellow-800" :
                              "bg-gray-100 text-gray-800"
                            }`}>
                              {item.confidence?.toUpperCase()} 
                            </span>
                            {item.confidence_score && (
                              <span className="text-xs text-gray-500">
                                Score: {item.confidence_score}
                              </span>
                            )}
                          </div>
                        </td>
                        {useAI && (
                          <td className="px-6 py-4">
                            {item.ai_suggestion ? (
                              <div>
                                <button
                                  onClick={() => setExpandedSuggestion(expandedSuggestion === idx ? null : idx)}
                                  className="flex items-center text-blue-600 hover:text-blue-800 font-medium text-sm"
                                >
                                  <span className="mr-2">🤖</span>
                                  {expandedSuggestion === idx ? "Hide Fix" : "View AI Fix"}
                                  <span className="ml-1">{expandedSuggestion === idx ? "▲" : "▼"}</span>
                                </button>
                                {expandedSuggestion === idx && (
                                  <div className="mt-3 p-4 bg-blue-50 rounded-lg border border-blue-200">
                                    <div className="flex items-center justify-between mb-3">
                                      <div className="flex items-center space-x-2">
                                        <span className={`px-2 py-1 text-xs rounded-full font-medium ${
                                          item.confidence === "high" ? "bg-green-100 text-green-800" :
                                          item.confidence === "medium" ? "bg-yellow-100 text-yellow-800" :
                                          "bg-gray-100 text-gray-800"
                                        }`}>
                                          {item.confidence?.toUpperCase()} CONFIDENCE
                                        </span>
                                        {item.can_remediate && user?.role === "admin" && (
                                          <span className="px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-full">
                                            ADMIN REMEDIATION AVAILABLE
                                          </span>
                                        )}
                                      </div>
                                      <span className="text-xs text-gray-500">AI-Generated Remediation</span>
                                    </div>
                                    <div className="prose prose-sm max-w-none">
                                      <div 
                                        className="bg-white p-4 rounded border overflow-auto"
                                        style={{ maxHeight: '500px' }}
                                      >
                                        <ReactMarkdown 
                                          components={{
                                            h1: ({children, ...props}) => <h1 {...props} className="text-lg font-bold text-gray-900 mb-2">{children}</h1>,
                                            h2: ({children, ...props}) => <h2 {...props} className="text-md font-semibold text-gray-800 mb-2 mt-4">{children}</h2>,
                                            h3: ({children, ...props}) => <h3 {...props} className="text-sm font-medium text-gray-700 mb-1 mt-3">{children}</h3>,
                                            p: ({children, ...props}) => <p {...props} className="mb-2 text-gray-700">{children}</p>,
                                            ul: ({children, ...props}) => <ul {...props} className="list-disc list-inside mb-2 space-y-1">{children}</ul>,
                                            ol: ({children, ...props}) => <ol {...props} className="list-decimal list-inside mb-2 space-y-1">{children}</ol>,
                                            li: ({children, ...props}) => <li {...props} className="text-gray-700">{children}</li>,
                                            code: ({children, className, ...props}) => {
                                              const isBlock = className?.includes('language-');
                                              if (isBlock) {
                                                return (
                                                  <pre className="bg-gray-100 p-3 rounded text-xs font-mono overflow-x-auto mb-2">
                                                    <code {...props} className="text-gray-800">{children}</code>
                                                  </pre>
                                                );
                                              }
                                              return <code {...props} className="bg-gray-100 px-1 py-0.5 rounded text-xs font-mono text-gray-800">{children}</code>;
                                            },
                                            strong: ({children, ...props}) => <strong {...props} className="font-semibold text-gray-900">{children}</strong>,
                                            em: ({children, ...props}) => <em {...props} className="italic text-gray-700">{children}</em>,
                                            blockquote: ({children, ...props}) => <blockquote {...props} className="border-l-4 border-blue-300 pl-4 italic text-gray-600 mb-2">{children}</blockquote>
                                          }}
                                        >
                                          {item.ai_suggestion}
                                        </ReactMarkdown>
                                      </div>
                                    </div>
                                    <div className="mt-3 flex justify-between items-center text-xs border-t pt-3">
                                      <span className="text-gray-500">
                                        💡 <strong>Tip:</strong> Always test changes in a non-production environment first
                                      </span>
                                      {user?.role === "admin" && (
                                        <button className="bg-green-600 text-white px-3 py-1 rounded text-xs hover:bg-green-700">
                                          Mark as Remediated
                                        </button>
                                      )}
                                    </div>
                                  </div>
                                )}
                              </div>
                            ) : (
                              <span className="text-gray-400 text-sm">Generating...</span>
                            )}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow-md p-12 text-center">
              <div className="text-6xl mb-4">🛡️</div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">No Security Issues Detected</h3>
              <p className="text-gray-600 mb-6">
                {loading ? "Scanning your cloud infrastructure..." : "Click 'Start Security Scan' to check for misconfigurations"}
              </p>
              {!loading && (!scanResponse || scanResponse.findings.length === 0) && (
                <div className="text-sm text-gray-500">
                  Last scan: Never
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
