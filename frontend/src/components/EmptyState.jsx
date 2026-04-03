import React from 'react';

export const EmptyState = ({ icon: Icon, title, description, action }) => {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      <div className="mb-6">
        {Icon}
      </div>
      <h3 className="text-xl font-bold mb-2" style={{ fontFamily: 'Syne, sans-serif', color: 'var(--text-1)' }}>
        {title}
      </h3>
      <p className="text-sm mb-6" style={{ color: 'var(--text-3)', maxWidth: '400px' }}>
        {description}
      </p>
      {action && action}
    </div>
  );
};

export const ShieldPulseIcon = () => (
  <svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M32 8L12 16V28C12 41.2 20.8 53.2 32 56C43.2 53.2 52 41.2 52 28V16L32 8Z" fill="var(--brand-500)" fillOpacity="0.2" stroke="var(--brand-600)" strokeWidth="2"/>
    <path d="M16 44L24 36L32 42L48 28" stroke="var(--brand-600)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const TerminalIcon = () => (
  <svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect x="8" y="12" width="48" height="40" rx="4" fill="var(--brand-500)" fillOpacity="0.2" stroke="var(--brand-600)" strokeWidth="2"/>
    <path d="M16 24L24 32L16 40" stroke="var(--brand-600)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    <line x1="32" y1="38" x2="44" y2="38" stroke="var(--brand-600)" strokeWidth="2" strokeLinecap="round"/>
  </svg>
);

export const BellCheckIcon = () => (
  <svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M32 8C25.4 8 20 13.4 20 20V28C20 32 18 34 16 36H48C46 34 44 32 44 28V20C44 13.4 38.6 8 32 8Z" fill="var(--brand-500)" fillOpacity="0.2" stroke="var(--brand-600)" strokeWidth="2"/>
    <path d="M28 48C28 50.2 29.8 52 32 52C34.2 52 36 50.2 36 48" stroke="var(--brand-600)" strokeWidth="2" strokeLinecap="round"/>
    <path d="M24 22L28 26L36 18" stroke="var(--brand-600)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export const KeyIcon = () => (
  <svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="42" cy="22" r="10" fill="var(--brand-500)" fillOpacity="0.2" stroke="var(--brand-600)" strokeWidth="2"/>
    <circle cx="42" cy="22" r="4" fill="var(--brand-600)"/>
    <path d="M34 30L16 48M16 48L12 44M16 48L20 52" stroke="var(--brand-600)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);