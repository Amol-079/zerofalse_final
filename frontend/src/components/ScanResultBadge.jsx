import React from 'react';
import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

export const ScanResultBadge = ({ decision }) => {
  const config = {
    allow: {
      bg: 'bg-green-100',
      text: 'text-green-800',
      icon: CheckCircle,
      label: 'ALLOW',
    },
    warn: {
      bg: 'bg-amber-100',
      text: 'text-amber-800',
      icon: AlertTriangle,
      label: 'WARN',
    },
    block: {
      bg: 'bg-red-100',
      text: 'text-red-800',
      icon: XCircle,
      label: 'BLOCK',
    },
  };

  const { bg, text, icon: Icon, label } = config[decision] || config.allow;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full ${bg} ${text} font-semibold text-xs`}
      data-testid={`scan-result-badge-${decision}`}
    >
      <Icon className="w-3.5 h-3.5" />
      {label}
    </span>
  );
};
