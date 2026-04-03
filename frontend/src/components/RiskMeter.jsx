import React from 'react';

export const RiskMeter = ({ score }) => {
  const percentage = Math.round(score * 100);
  
  const getColor = () => {
    if (score < 0.45) return 'bg-green-500';
    if (score < 0.75) return 'bg-amber-500';
    return 'bg-red-500';
  };

  return (
    <div className="flex items-center gap-2" data-testid="risk-meter">
      <div className="flex-1 h-2 bg-gray-200 rounded-full overflow-hidden">
        <div
          className={`h-full ${getColor()} transition-all duration-500 ease-out`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="text-sm font-semibold text-gray-700 min-w-[45px] text-right">
        {percentage}%
      </span>
    </div>
  );
};
