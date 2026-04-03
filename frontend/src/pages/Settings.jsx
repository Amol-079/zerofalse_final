import React, { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, 
  User, 
  Building2, 
  Bell, 
  Shield,
  CreditCard,
  Mail,
  Check,
  AlertCircle,
  ChevronRight,
  ExternalLink,
  Loader2
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import client from '../api/client';

const Settings = () => {
  const { user, org, refreshUser } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [isLoading, setIsLoading] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState('');
  
  const [profileData, setProfileData] = useState({
    full_name: '',
    email: ''
  });

  const [orgData, setOrgData] = useState({
    name: '',
    slug: ''
  });

  const [notificationSettings, setNotificationSettings] = useState({
    email_alerts: true,
    critical_only: false,
    weekly_digest: true
  });

  useEffect(() => {
    if (user) {
      setProfileData({
        full_name: user.full_name || '',
        email: user.email || ''
      });
    }
    if (org) {
      setOrgData({
        name: org.name || '',
        slug: org.slug || ''
      });
    }
  }, [user, org]);

  const handleProfileSave = async () => {
    setIsLoading(true);
    setError('');
    try {
      await client.patch('/api/v1/auth/profile', {
        full_name: profileData.full_name
      });
      await refreshUser();
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update profile');
    } finally {
      setIsLoading(false);
    }
  };

  const handleOrgSave = async () => {
    setIsLoading(true);
    setError('');
    try {
      await client.patch('/api/v1/auth/org', {
        name: orgData.name
      });
      await refreshUser();
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update organization');
    } finally {
      setIsLoading(false);
    }
  };

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'organization', label: 'Organization', icon: Building2 },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'billing', label: 'Billing', icon: CreditCard }
  ];

  const renderTabContent = () => {
    switch (activeTab) {
      case 'profile':
        return (
          <div>
            <div style={{ marginBottom: '32px' }}>
              <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                Profile Settings
              </h2>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                Manage your personal information
              </p>
            </div>

            <div style={{ maxWidth: '480px' }}>
              <div style={{ marginBottom: '24px' }}>
                <label style={{ 
                  display: 'block', 
                  fontSize: 'var(--text-sm)', 
                  fontWeight: 500, 
                  color: 'var(--color-text-primary)',
                  marginBottom: '8px'
                }}>
                  Full Name
                </label>
                <input
                  type="text"
                  value={profileData.full_name}
                  onChange={(e) => setProfileData({ ...profileData, full_name: e.target.value })}
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  data-testid="profile-name"
                />
              </div>

              <div style={{ marginBottom: '24px' }}>
                <label style={{ 
                  display: 'block', 
                  fontSize: 'var(--text-sm)', 
                  fontWeight: 500, 
                  color: 'var(--color-text-primary)',
                  marginBottom: '8px'
                }}>
                  Email Address
                </label>
                <input
                  type="email"
                  value={profileData.email}
                  disabled
                  style={{ 
                    width: '100%', 
                    boxSizing: 'border-box',
                    backgroundColor: 'var(--color-surface)',
                    cursor: 'not-allowed'
                  }}
                />
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginTop: '6px' }}>
                  Contact support to change your email address
                </p>
              </div>

              <button
                onClick={handleProfileSave}
                disabled={isLoading}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '10px 20px',
                  backgroundColor: isLoading ? 'var(--color-border)' : 'var(--color-brand)',
                  color: 'white',
                  border: 'none',
                  borderRadius: 'var(--radius-md)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 600,
                  cursor: isLoading ? 'not-allowed' : 'pointer'
                }}
                data-testid="save-profile"
              >
                {isLoading ? (
                  <Loader2 style={{ width: '16px', height: '16px', animation: 'spin 0.6s linear infinite' }} />
                ) : saveSuccess ? (
                  <>
                    <Check style={{ width: '16px', height: '16px' }} />
                    Saved!
                  </>
                ) : (
                  'Save Changes'
                )}
              </button>
            </div>
          </div>
        );

      case 'organization':
        return (
          <div>
            <div style={{ marginBottom: '32px' }}>
              <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                Organization Settings
              </h2>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                Manage your organization details
              </p>
            </div>

            <div style={{ maxWidth: '480px' }}>
              <div style={{ marginBottom: '24px' }}>
                <label style={{ 
                  display: 'block', 
                  fontSize: 'var(--text-sm)', 
                  fontWeight: 500, 
                  color: 'var(--color-text-primary)',
                  marginBottom: '8px'
                }}>
                  Organization Name
                </label>
                <input
                  type="text"
                  value={orgData.name}
                  onChange={(e) => setOrgData({ ...orgData, name: e.target.value })}
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  data-testid="org-name"
                />
              </div>

              <div style={{ marginBottom: '24px' }}>
                <label style={{ 
                  display: 'block', 
                  fontSize: 'var(--text-sm)', 
                  fontWeight: 500, 
                  color: 'var(--color-text-primary)',
                  marginBottom: '8px'
                }}>
                  Organization Slug
                </label>
                <input
                  type="text"
                  value={orgData.slug}
                  disabled
                  style={{ 
                    width: '100%', 
                    boxSizing: 'border-box',
                    backgroundColor: 'var(--color-surface)',
                    cursor: 'not-allowed'
                  }}
                />
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginTop: '6px' }}>
                  Your unique organization identifier
                </p>
              </div>

              <div style={{
                padding: '20px',
                backgroundColor: 'var(--color-surface)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--color-border)',
                marginBottom: '24px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Current Plan
                  </span>
                  <span style={{
                    padding: '4px 12px',
                    backgroundColor: 'var(--color-brand-light)',
                    color: 'var(--color-brand)',
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-full)',
                    textTransform: 'capitalize'
                  }}>
                    {org?.plan || 'Free'}
                  </span>
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                  {org?.scan_limit_month?.toLocaleString() || '10,000'} scans/month
                </div>
              </div>

              <button
                onClick={handleOrgSave}
                disabled={isLoading}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '10px 20px',
                  backgroundColor: isLoading ? 'var(--color-border)' : 'var(--color-brand)',
                  color: 'white',
                  border: 'none',
                  borderRadius: 'var(--radius-md)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 600,
                  cursor: isLoading ? 'not-allowed' : 'pointer'
                }}
                data-testid="save-org"
              >
                {isLoading ? (
                  <Loader2 style={{ width: '16px', height: '16px', animation: 'spin 0.6s linear infinite' }} />
                ) : (
                  'Save Changes'
                )}
              </button>
            </div>
          </div>
        );

      case 'notifications':
        return (
          <div>
            <div style={{ marginBottom: '32px' }}>
              <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                Notification Preferences
              </h2>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                Control how you receive alerts
              </p>
            </div>

            <div style={{ maxWidth: '480px' }}>
              {[
                { key: 'email_alerts', label: 'Email Alerts', description: 'Receive email notifications for security alerts' },
                { key: 'critical_only', label: 'Critical Only', description: 'Only receive notifications for critical severity alerts' },
                { key: 'weekly_digest', label: 'Weekly Digest', description: 'Get a weekly summary of your security activity' }
              ].map((setting) => (
                <div 
                  key={setting.key}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    padding: '20px',
                    backgroundColor: 'var(--color-bg)',
                    borderRadius: 'var(--radius-lg)',
                    border: '1px solid var(--color-border)',
                    marginBottom: '12px'
                  }}
                >
                  <div>
                    <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                      {setting.label}
                    </div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                      {setting.description}
                    </div>
                  </div>
                  <button
                    onClick={() => setNotificationSettings(prev => ({ ...prev, [setting.key]: !prev[setting.key] }))}
                    style={{
                      width: '44px',
                      height: '24px',
                      borderRadius: 'var(--radius-full)',
                      backgroundColor: notificationSettings[setting.key] ? 'var(--color-brand)' : 'var(--color-border)',
                      border: 'none',
                      cursor: 'pointer',
                      position: 'relative',
                      transition: 'var(--transition-fast)',
                      flexShrink: 0
                    }}
                    data-testid={`toggle-${setting.key}`}
                  >
                    <div style={{
                      position: 'absolute',
                      top: '2px',
                      left: notificationSettings[setting.key] ? '22px' : '2px',
                      width: '20px',
                      height: '20px',
                      backgroundColor: 'white',
                      borderRadius: '50%',
                      transition: 'var(--transition-fast)',
                      boxShadow: 'var(--shadow-sm)'
                    }} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        );

      case 'security':
        return (
          <div>
            <div style={{ marginBottom: '32px' }}>
              <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                Security Settings
              </h2>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                Manage your account security
              </p>
            </div>

            <div style={{ maxWidth: '480px' }}>
              <div style={{
                padding: '20px',
                backgroundColor: 'var(--color-bg)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--color-border)',
                marginBottom: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                      Password
                    </div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                      Last changed 30 days ago
                    </div>
                  </div>
                  <button
                    style={{
                      padding: '8px 16px',
                      backgroundColor: 'var(--color-surface)',
                      color: 'var(--color-text-primary)',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: 'var(--text-sm)',
                      fontWeight: 500,
                      cursor: 'pointer'
                    }}
                  >
                    Change
                  </button>
                </div>
              </div>

              <div style={{
                padding: '20px',
                backgroundColor: 'var(--color-bg)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--color-border)',
                marginBottom: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                      Two-Factor Authentication
                    </div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                      Add an extra layer of security
                    </div>
                  </div>
                  <span style={{
                    padding: '4px 10px',
                    backgroundColor: 'var(--color-warning-bg)',
                    color: 'var(--color-warning)',
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-full)'
                  }}>
                    Coming Soon
                  </span>
                </div>
              </div>

              <div style={{
                padding: '20px',
                backgroundColor: 'var(--color-bg)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--color-border)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                      Active Sessions
                    </div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                      1 active session
                    </div>
                  </div>
                  <button
                    style={{
                      padding: '8px 16px',
                      backgroundColor: 'var(--color-danger-bg)',
                      color: 'var(--color-danger)',
                      border: 'none',
                      borderRadius: 'var(--radius-md)',
                      fontSize: 'var(--text-sm)',
                      fontWeight: 500,
                      cursor: 'pointer'
                    }}
                  >
                    Sign Out All
                  </button>
                </div>
              </div>
            </div>
          </div>
        );

      case 'billing':
        return (
          <div>
            <div style={{ marginBottom: '32px' }}>
              <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                Billing & Plans
              </h2>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
                Manage your subscription
              </p>
            </div>

            <div style={{ maxWidth: '600px' }}>
              {/* Current Plan */}
              <div style={{
                padding: '24px',
                backgroundColor: 'var(--color-brand-light)',
                borderRadius: 'var(--radius-lg)',
                border: '2px solid var(--color-brand)',
                marginBottom: '24px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                  <div>
                    <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                      {org?.plan === 'free' ? 'Free Plan' : 'Pro Plan'}
                    </div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>
                      {org?.scan_limit_month?.toLocaleString() || '10,000'} scans per month
                    </div>
                  </div>
                  <span style={{
                    padding: '6px 14px',
                    backgroundColor: 'var(--color-brand)',
                    color: 'white',
                    fontSize: 'var(--text-sm)',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-full)'
                  }}>
                    Current
                  </span>
                </div>
                <div style={{ 
                  height: '8px', 
                  backgroundColor: 'rgba(26,86,255,0.2)', 
                  borderRadius: 'var(--radius-full)',
                  overflow: 'hidden',
                  marginBottom: '8px'
                }}>
                  <div style={{ 
                    width: `${Math.min(((org?.scan_count_month || 0) / (org?.scan_limit_month || 10000)) * 100, 100)}%`,
                    height: '100%',
                    backgroundColor: 'var(--color-brand)',
                    borderRadius: 'var(--radius-full)'
                  }} />
                </div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
                  {org?.scan_count_month?.toLocaleString() || 0} of {org?.scan_limit_month?.toLocaleString() || '10,000'} scans used this month
                </div>
              </div>

              {/* Upgrade Options */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{
                  padding: '24px',
                  backgroundColor: 'var(--color-bg)',
                  borderRadius: 'var(--radius-lg)',
                  border: '1px solid var(--color-border)'
                }}>
                  <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '8px' }}>
                    Pro
                  </div>
                  <div style={{ fontSize: 'var(--text-3xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                    $49<span style={{ fontSize: 'var(--text-sm)', fontWeight: 500, color: 'var(--color-text-muted)' }}>/mo</span>
                  </div>
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)', marginBottom: '20px' }}>
                    100,000 scans/month
                  </div>
                  <button
                    style={{
                      width: '100%',
                      padding: '10px',
                      backgroundColor: 'var(--color-brand)',
                      color: 'white',
                      border: 'none',
                      borderRadius: 'var(--radius-md)',
                      fontSize: 'var(--text-sm)',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    Upgrade
                  </button>
                </div>

                <div style={{
                  padding: '24px',
                  backgroundColor: 'var(--color-bg)',
                  borderRadius: 'var(--radius-lg)',
                  border: '1px solid var(--color-border)'
                }}>
                  <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '8px' }}>
                    Enterprise
                  </div>
                  <div style={{ fontSize: 'var(--text-3xl)', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                    Custom
                  </div>
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)', marginBottom: '20px' }}>
                    Unlimited scans
                  </div>
                  <button
                    style={{
                      width: '100%',
                      padding: '10px',
                      backgroundColor: 'var(--color-surface)',
                      color: 'var(--color-text-primary)',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: 'var(--text-sm)',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '6px'
                    }}
                  >
                    Contact Sales
                    <ExternalLink style={{ width: '14px', height: '14px' }} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="page-transition" data-testid="settings-page">
      {/* Header */}
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ 
          fontSize: 'var(--text-2xl)', 
          fontWeight: 700, 
          color: 'var(--color-text-primary)',
          marginBottom: '4px'
        }}>
          Settings
        </h1>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)' }}>
          Manage your account and preferences
        </p>
      </div>

      {/* Error Alert */}
      {error && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '12px 16px',
          backgroundColor: 'var(--color-danger-bg)',
          border: '1px solid var(--color-danger-border)',
          borderRadius: 'var(--radius-md)',
          marginBottom: '24px'
        }}>
          <AlertCircle style={{ width: '18px', height: '18px', color: 'var(--color-danger)' }} />
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-danger)' }}>{error}</span>
        </div>
      )}

      <div style={{ display: 'flex', gap: '32px' }}>
        {/* Sidebar Navigation */}
        <div style={{ width: '220px', flexShrink: 0 }}>
          <nav style={{ 
            backgroundColor: 'var(--color-bg)',
            borderRadius: 'var(--radius-lg)',
            border: '1px solid var(--color-border)',
            overflow: 'hidden'
          }}>
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '14px 16px',
                    backgroundColor: isActive ? 'var(--color-brand-subtle)' : 'transparent',
                    border: 'none',
                    borderLeft: isActive ? '3px solid var(--color-brand)' : '3px solid transparent',
                    fontSize: 'var(--text-sm)',
                    fontWeight: isActive ? 600 : 500,
                    color: isActive ? 'var(--color-brand)' : 'var(--color-text-secondary)',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'var(--transition-fast)'
                  }}
                  data-testid={`tab-${tab.id}`}
                >
                  <Icon style={{ width: '18px', height: '18px' }} />
                  {tab.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Main Content */}
        <div style={{ 
          flex: 1,
          backgroundColor: 'var(--color-bg)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--color-border)',
          padding: '32px'
        }}>
          {renderTabContent()}
        </div>
      </div>

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default Settings;
