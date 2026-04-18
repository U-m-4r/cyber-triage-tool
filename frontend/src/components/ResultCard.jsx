import { getRiskColor } from "../utils/riskColor"

const riskBg = {
  High:   "bg-red-500/10 border-red-500/30 text-red-400",
  Medium: "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
  Low:    "bg-green-500/10 border-green-500/30 text-green-400",
}

const riskGlow = {
  High:   "shadow-red-500/20",
  Medium: "shadow-yellow-500/20",
  Low:    "shadow-green-500/20",
}

function ScoreRing({ score }) {
  const radius = 36
  const circ = 2 * Math.PI * radius
  const offset = circ - (score / 100) * circ
  const color = score >= 70 ? "#f87171" : score >= 40 ? "#facc15" : "#4ade80"

  return (
    <div className="relative w-24 h-24 flex items-center justify-center">
      <svg className="absolute inset-0 -rotate-90" width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={radius} fill="none" stroke="#1e293b" strokeWidth="8" />
        <circle
          cx="48" cy="48" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1s ease" }}
        />
      </svg>
      <div className="text-center">
        <span className="text-2xl font-bold text-white">{score}</span>
        <span className="block text-[10px] text-slate-500 -mt-0.5">/ 100</span>
      </div>
    </div>
  )
}

export default function ResultCard({ result }) {
  const { risk_level, threats_detected, suspicious_files, score } = result
  const badgeClass = riskBg[risk_level] ?? "bg-slate-700/50 border-slate-600 text-slate-300"
  const glowClass  = riskGlow[risk_level] ?? ""

  return (
    <div className={`glass rounded-2xl p-6 shadow-2xl ${glowClass}`}>
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 mb-6">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-widest mb-1">Analysis Complete</p>
          <h2 className="text-xl font-bold text-white">Threat Report</h2>
        </div>
        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-semibold ${badgeClass}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-current" />
          {risk_level} Risk
        </span>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        {/* Score ring */}
        <div className="col-span-1 flex flex-col items-center justify-center glass rounded-xl py-4">
          <ScoreRing score={score} />
          <span className="text-[11px] text-slate-500 mt-1">Risk Score</span>
        </div>

        {/* Threat count */}
        <div className="glass rounded-xl p-4 flex flex-col justify-center">
          <span className="text-3xl font-bold text-white">{threats_detected}</span>
          <span className="text-xs text-slate-500 mt-1">Threats<br />Detected</span>
        </div>

        {/* File count */}
        <div className="glass rounded-xl p-4 flex flex-col justify-center">
          <span className="text-3xl font-bold text-white">{suspicious_files.length}</span>
          <span className="text-xs text-slate-500 mt-1">Suspicious<br />Files</span>
        </div>
      </div>

      {/* Suspicious files list */}
      <div>
        <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Flagged Files</p>
        {suspicious_files.length === 0 ? (
          <div className="flex items-center gap-2 text-green-400 text-sm">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            No suspicious files found
          </div>
        ) : (
          <ul className="space-y-1.5">
            {suspicious_files.map((f, i) => (
              <li key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/5 border border-red-500/20">
                <svg className="w-3.5 h-3.5 text-red-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                </svg>
                <span className="text-xs font-mono text-red-300">{f}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
