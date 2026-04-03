import React, { useState } from 'react';
import { AlertCircle, CheckCircle2, Clock } from 'lucide-react';
import { formatDate } from '../utils/formatters';
import client from '../api/client';

export const AlertRow = ({ alert, onUpdate }) => {
  const [loading, setLoading] = useState(false);

  const handleAcknowledge = async () => {
    setLoading(true);
    try {
      await client.patch(`/api/v1/alerts/${alert.id}/acknowledge`);
      onUpdate();
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleResolve = async () => {
    setLoading(true);
    try {
      await client.patch(`/api/v1/alerts/${alert.id}/resolve`);
      onUpdate();
    } catch (error) {
      console.error('Error resolving alert:', error);
    } finally {
      setLoading(false);
    }
  };

  const severityConfig = {
    critical: { bg: 'bg-red-100', text: 'text-red-800', border: 'border-red-300' },
    high: { bg: 'bg-orange-100', text: 'text-orange-800', border: 'border-orange-300' },
    medium: { bg: 'bg-amber-100', text: 'text-amber-800', border: 'border-amber-300' },
    low: { bg: 'bg-blue-100', text: 'text-blue-800', border: 'border-blue-300' },
  };

  const statusConfig = {
    open: { icon: AlertCircle, color: 'text-red-500' },
    acknowledged: { icon: Clock, color: 'text-amber-500' },
    resolved: { icon: CheckCircle2, color: 'text-green-500' },
  };

  const severity = severityConfig[alert.severity] || severityConfig.medium;
  const status = statusConfig[alert.status] || statusConfig.open;
  const StatusIcon = status.icon;

  return (
    <div
      className={`p-4 bg-white border ${severity.border} rounded-lg hover:shadow-md transition-shadow`}
      data-testid={`alert-row-${alert.id}`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <StatusIcon className={`w-5 h-5 ${status.color}`} />
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${severity.bg} ${severity.text}`}>
              {alert.severity.toUpperCase()}
            </span>
            <span className="text-xs text-gray-500">{formatDate(alert.created_at)}</span>
          </div>
          <h3 className="font-semibold text-gray-900 mb-1" data-testid="alert-title">{alert.title}</h3>
          <p className="text-sm text-gray-600">{alert.description}</p>
        </div>
        
        {alert.status === 'open' && (
          <div className="flex gap-2">
            <button
              onClick={handleAcknowledge}
              disabled={loading}
              className="px-3 py-1.5 text-sm font-medium text-amber-700 bg-amber-50 hover:bg-amber-100 rounded-lg transition-colors disabled:opacity-50"
              data-testid="acknowledge-alert-btn"
            >
              Acknowledge
            </button>
            <button
              onClick={handleResolve}
              disabled={loading}
              className="px-3 py-1.5 text-sm font-medium text-green-700 bg-green-50 hover:bg-green-100 rounded-lg transition-colors disabled:opacity-50"
              data-testid="resolve-alert-btn"
            >
              Resolve
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
