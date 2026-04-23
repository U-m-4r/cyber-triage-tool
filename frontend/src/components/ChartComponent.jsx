import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts"

const BAR_COLORS = ["#06b6d4", "#818cf8"]

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="glass rounded-lg px-3 py-2 text-xs shadow-xl">
      <p className="text-slate-400 mb-0.5">{label}</p>
      <p className="text-white font-semibold">{payload[0].value}</p>
    </div>
  )
}

export default function ChartComponent({ score, threatsDetected }) {
  const data = [
    { name: "Risk Score", value: score },
    { name: "Threats", value: threatsDetected },
  ]

  return (
    <div className="glass rounded-2xl p-6 shadow-2xl shadow-black/40">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-9 h-9 rounded-lg bg-violet-500/15 border border-violet-500/20 flex items-center justify-center">
          <svg className="w-4 h-4 text-violet-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
        </div>
        <div>
          <h2 className="text-sm font-semibold text-white">Threat Overview</h2>
          <p className="text-xs text-slate-500">Visual breakdown of findings</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 4, right: 8, left: -16, bottom: 0 }} barSize={48}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: "#64748b", fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: "#64748b", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
          <Bar dataKey="value" radius={[6, 6, 0, 0]}>
            {data.map((_, i) => (
              <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} fillOpacity={0.85} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-3 justify-center">
        {data.map((d, i) => (
          <div key={i} className="flex items-center gap-1.5 text-xs text-slate-500">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ background: BAR_COLORS[i] }} />
            {d.name}
          </div>
        ))}
      </div>
    </div>
  )
}
