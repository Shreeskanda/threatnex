import { useMemo } from 'react';
import { getRiskColor } from '../utils';

interface RiskGaugeProps {
  score: number;
  threatLevel: string;
  size?: number;
}

export default function RiskGauge({ score, threatLevel, size = 180 }: RiskGaugeProps) {
  const radius = (size - 20) / 2;
  const circumference = Math.PI * radius; // half circle
  const strokeWidth = 14;

  // Arc goes from 180deg to 0deg (left to right, bottom half up)
  const getColor = (s: number) => {
    if (s >= 80) return '#dc2626';
    if (s >= 60) return '#ea580c';
    if (s >= 40) return '#d97706';
    if (s >= 20) return '#2563eb';
    return '#16a34a';
  };

  const pct = Math.min(100, Math.max(0, score)) / 100;
  const dashOffset = circumference * (1 - pct);
  const color = getColor(score);
  const textColor = getRiskColor(score);

  const cx = size / 2;
  const cy = size / 2;

  const gradientId = useMemo(() => `gauge-grad-${Math.random().toString(36).slice(2)}`, []);

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 2 + 30} viewBox={`0 0 ${size} ${size / 2 + 30}`}>
        <defs>
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#16a34a" />
            <stop offset="40%" stopColor="#2563eb" />
            <stop offset="65%" stopColor="#d97706" />
            <stop offset="80%" stopColor="#ea580c" />
            <stop offset="100%" stopColor="#dc2626" />
          </linearGradient>
        </defs>
        {/* Background track */}
        <path
          d={`M ${strokeWidth / 2 + 5} ${cy} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2 - 5} ${cy}`}
          fill="none"
          stroke="#e5e7eb"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        {/* Colored progress */}
        <path
          d={`M ${strokeWidth / 2 + 5} ${cy} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2 - 5} ${cy}`}
          fill="none"
          stroke={`url(#${gradientId})`}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{ transition: 'stroke-dashoffset 1s ease-out' }}
        />
        {/* Score text */}
        <text
          x={cx}
          y={cy - 8}
          textAnchor="middle"
          className={textColor}
          fill={color}
          fontSize="32"
          fontWeight="700"
          fontFamily="Inter, system-ui, sans-serif"
        >
          {score}
        </text>
        <text
          x={cx}
          y={cy + 12}
          textAnchor="middle"
          fill="#6b7280"
          fontSize="11"
          fontFamily="Inter, system-ui, sans-serif"
        >
          Risk Score
        </text>
        {/* Min/Max labels */}
        <text x={strokeWidth / 2 + 5} y={cy + 22} fill="#9ca3af" fontSize="10" textAnchor="middle">0</text>
        <text x={size - strokeWidth / 2 - 5} y={cy + 22} fill="#9ca3af" fontSize="10" textAnchor="middle">100</text>
      </svg>

      {/* Threat level badge */}
      <div
        className="mt-1 px-3 py-1 rounded-full text-xs font-semibold border"
        style={{ color, borderColor: color, backgroundColor: color + '15' }}
      >
        {threatLevel}
      </div>
    </div>
  );
}
