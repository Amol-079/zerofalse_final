import React from 'react';

export const SkeletonCard = () => {
  return (
    <div className="bg-white p-6 rounded-xl border" style={{ borderColor: 'var(--border)', boxShadow: 'var(--shadow-2)' }}>
      <div className="flex items-center justify-between mb-4">
        <div className="h-3 w-24 animate-shimmer rounded" />
        <div className="w-10 h-10 rounded-lg animate-shimmer" />
      </div>
      <div className="h-8 w-20 animate-shimmer rounded" />
    </div>
  );
};