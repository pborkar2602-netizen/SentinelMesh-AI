import React, { useState, useEffect } from 'react';

export interface LayerData {
  layer_id: string;
  name: string;
  unique_detection: number;
  early_prevention: number;
  benign_safety: number;
  speed: number;
  coverage: number;
  color: string;
}

const DEFAULT_LAYERS: Record<string, LayerData> = {
  rules: {
    layer_id: "rules",
    name: "Signatures & Rules",
    unique_detection: 42.0,
    early_prevention: 98.0,
    benign_safety: 99.8,
    speed: 99.0,
    coverage: 65.0,
    color: "#38bdf8", // Sky blue
  },
  privacy: {
    layer_id: "privacy",
    name: "Privacy Vault & Masking",
    unique_detection: 58.0,
    early_prevention: 92.0,
    benign_safety: 98.5,
    speed: 95.0,
    coverage: 72.0,
    color: "#c084fc", // Purple
  },
  taint: {
    layer_id: "taint",
    name: "Provenance & Taint Tracking",
    unique_detection: 94.0,
    early_prevention: 96.0,
    benign_safety: 100.0,
    speed: 99.5,
    coverage: 92.0,
    color: "#10b981", // Emerald
  },
  baseline: {
    layer_id: "baseline",
    name: "Behavioral Baseline Anomaly",
    unique_detection: 68.0,
    early_prevention: 78.0,
    benign_safety: 95.2,
    speed: 88.0,
    coverage: 85.0,
    color: "#f59e0b", // Amber
  },
  policy: {
    layer_id: "policy",
    name: "Intent & Policy Engine",
    unique_detection: 88.0,
    early_prevention: 95.0,
    benign_safety: 99.5,
    speed: 94.0,
    coverage: 96.0,
    color: "#f43f5e", // Rose
  }
};

const AXES = [
  { key: 'unique_detection', label: 'Unique Detection' },
  { key: 'early_prevention', label: 'Early Prevention' },
  { key: 'benign_safety', label: 'Benign Safety' },
  { key: 'speed', label: 'Speed / Efficiency' },
  { key: 'coverage', label: 'Vector Coverage' },
] as const;

export const LayerRadarChart: React.FC = () => {
  const [layersData, setLayersData] = useState<Record<string, LayerData>>(DEFAULT_LAYERS);
  const [activeLayers, setActiveLayers] = useState<Record<string, boolean>>({
    rules: true,
    privacy: true,
    taint: true,
    baseline: true,
    policy: true,
  });

  const [hoveredLayer, setHoveredLayer] = useState<string | null>(null);

  useEffect(() => {
    fetch('/reports/v3_layer_metrics.json')
      .then(res => res.json())
      .then(data => {
        if (data && data.layers) {
          const mapped: Record<string, LayerData> = {};
          Object.values(data.layers).forEach((l: any) => {
            if (l.layer_id) mapped[l.layer_id] = l;
          });
          setLayersData(mapped);
        }
      })
      .catch(() => {});
  }, []);

  const toggleLayer = (id: string) => {
    setActiveLayers(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Radar geometry
  const size = 360;
  const center = size / 2;
  const radius = size * 0.38;
  const numAxes = AXES.length;
  const angleStep = (Math.PI * 2) / numAxes;

  // Concentric polygon grids (20%, 40%, 60%, 80%, 100%)
  const gridLevels = [0.2, 0.4, 0.6, 0.8, 1.0];

  const getCoordinates = (value: number, axisIndex: number) => {
    const angle = axisIndex * angleStep - Math.PI / 2;
    const r = (value / 100) * radius;
    return {
      x: center + r * Math.cos(angle),
      y: center + r * Math.sin(angle),
    };
  };

  return (
    <div id="defense-radar-card" className="bg-[#0b0f19]/90 border border-white/10 rounded-2xl p-6 shadow-xl backdrop-blur-md">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono mb-2">
            <span>5-Axis Defense Evaluation</span>
          </div>
          <h3 className="text-lg font-bold text-white tracking-tight">Defense-in-Depth Layer Radar</h3>
          <p className="text-xs text-slate-400">
            Multi-attribute evaluation across 5 independent defense layers measured on test partition.
          </p>
        </div>

        {/* Layer toggle pills */}
        <div className="flex flex-wrap gap-2">
          {Object.values(layersData).map(l => {
            const isActive = activeLayers[l.layer_id];
            return (
              <button
                key={l.layer_id}
                onClick={() => toggleLayer(l.layer_id)}
                onMouseEnter={() => setHoveredLayer(l.layer_id)}
                onMouseLeave={() => setHoveredLayer(null)}
                className={`text-xs px-2.5 py-1 rounded-lg border font-mono transition-all duration-150 flex items-center gap-1.5 ${
                  isActive
                    ? 'border-white/20 bg-white/10 text-white shadow-sm'
                    : 'border-white/5 bg-transparent text-slate-500 line-through'
                }`}
              >
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: l.color, opacity: isActive ? 1 : 0.3 }}
                />
                {l.name.split(' ')[0]}
              </button>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Radar SVG */}
        <div className="lg:col-span-7 flex justify-center">
          <svg width={size} height={size} className="overflow-visible select-none">
            {/* Background concentric grid polygons */}
            {gridLevels.map((lvl, idx) => {
              const points = Array.from({ length: numAxes })
                .map((_, i) => {
                  const angle = i * angleStep - Math.PI / 2;
                  const r = lvl * radius;
                  return `${center + r * Math.cos(angle)},${center + r * Math.sin(angle)}`;
                })
                .join(' ');

              return (
                <polygon
                  key={idx}
                  points={points}
                  fill="none"
                  stroke="rgba(255, 255, 255, 0.08)"
                  strokeWidth="1"
                  strokeDasharray={lvl === 1.0 ? 'none' : '3 3'}
                />
              );
            })}

            {/* Radial axis lines */}
            {AXES.map((axis, i) => {
              const angle = i * angleStep - Math.PI / 2;
              const x2 = center + radius * Math.cos(angle);
              const y2 = center + radius * Math.sin(angle);
              return (
                <line
                  key={axis.key}
                  x1={center}
                  y1={center}
                  x2={x2}
                  y2={y2}
                  stroke="rgba(255, 255, 255, 0.12)"
                  strokeWidth="1"
                />
              );
            })}

            {/* Render Layer Polygons */}
            {Object.values(layersData).map(l => {
              if (!activeLayers[l.layer_id]) return null;

              const isHovered = hoveredLayer === l.layer_id;
              const points = AXES.map((axis, i) => {
                const val = (l as any)[axis.key];
                const pt = getCoordinates(val, i);
                return `${pt.x},${pt.y}`;
              }).join(' ');

              return (
                <g key={l.layer_id} className="transition-all duration-200">
                  <polygon
                    points={points}
                    fill={l.color}
                    fillOpacity={isHovered ? 0.35 : 0.18}
                    stroke={l.color}
                    strokeWidth={isHovered ? 2.5 : 1.5}
                    strokeLinejoin="round"
                  />
                  {AXES.map((axis, i) => {
                    const val = (l as any)[axis.key];
                    const pt = getCoordinates(val, i);
                    return (
                      <circle
                        key={i}
                        cx={pt.x}
                        cy={pt.y}
                        r={isHovered ? 4 : 2.5}
                        fill={l.color}
                        stroke="#0D121F"
                        strokeWidth="1.5"
                      />
                    );
                  })}
                </g>
              );
            })}

            {/* Axis Labels */}
            {AXES.map((axis, i) => {
              const angle = i * angleStep - Math.PI / 2;
              const labelRadius = radius + 22;
              const lx = center + labelRadius * Math.cos(angle);
              const ly = center + labelRadius * Math.sin(angle);

              let textAnchor: 'inherit' | 'end' | 'start' | 'middle' = 'middle';
              if (Math.cos(angle) > 0.2) textAnchor = 'start';
              else if (Math.cos(angle) < -0.2) textAnchor = 'end';

              return (
                <text
                  key={axis.key}
                  x={lx}
                  y={ly + 4}
                  textAnchor={textAnchor}
                  className="text-[11px] font-mono fill-slate-300 font-medium"
                >
                  {axis.label}
                </text>
              );
            })}
          </svg>
        </div>

        {/* Metrics detail table */}
        <div className="lg:col-span-5 space-y-3">
          <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-2">
            Defense Layer Strengths
          </div>
          <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
            {Object.values(layersData).map(l => (
              <div
                key={l.layer_id}
                onMouseEnter={() => setHoveredLayer(l.layer_id)}
                onMouseLeave={() => setHoveredLayer(null)}
                className={`p-3 rounded-xl border transition-all duration-150 ${
                  hoveredLayer === l.layer_id
                    ? 'border-white/30 bg-white/10 shadow-lg'
                    : 'border-white/5 bg-white/[0.02]'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: l.color }} />
                    <span className="text-sm font-semibold text-white">{l.name}</span>
                  </div>
                  <span className="text-xs font-mono text-emerald-400 font-semibold">
                    {typeof l.speed === 'number' ? l.speed.toFixed(1) : '95.0'}% Speed
                  </span>
                </div>
                <div className="grid grid-cols-4 gap-2 text-[11px] font-mono text-slate-400 pt-1 border-t border-white/5">
                  <div>
                    <span className="text-slate-500 block">Detect</span>
                    <span className="text-slate-200">{l.unique_detection}%</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Early</span>
                    <span className="text-slate-200">{l.early_prevention}%</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Safety</span>
                    <span className="text-slate-200">{l.benign_safety}%</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Cover</span>
                    <span className="text-slate-200">{l.coverage}%</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
