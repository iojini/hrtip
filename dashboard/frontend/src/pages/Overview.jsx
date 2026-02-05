import { BarChart, Bar, PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { AlertTriangle, Shield, Target, Activity } from 'lucide-react'

const COLORS = ['#06b6d4', '#8b5cf6', '#f59e0b', '#ef4444', '#10b981', '#ec4899']

function StatCard({ title, value, subtitle, icon: Icon, color }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-500 uppercase tracking-wider">{title}</span>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-xs text-gray-500 mt-1">{subtitle}</div>
    </div>
  )
}

export default function Overview({ data }) {
  if (!data) return null

  const { summary, mitre_summary, anomalies, temporal } = data

  // IOC type chart data
  const typeData = Object.entries(summary.ioc_types).map(([name, value]) => ({
    name: name.toUpperCase(), value
  }))

  // Threat type chart data
  const threatData = Object.entries(summary.threat_types).map(([name, value]) => ({
    name: name.replace('_', ' '), value
  }))

  // Malware family chart data
  const malwareData = (mitre_summary.malware_families || []).map(([name, count]) => ({
    name, count
  }))

  // Temporal chart data
  const hourData = Object.entries(temporal?.hour_distribution || {}).map(([hour, count]) => ({
    hour: `${hour}:00`, count
  })).sort((a, b) => parseInt(a.hour) - parseInt(b.hour))

  // Tactic chart data
  const tacticData = (mitre_summary.top_tactics || []).map(([name, count]) => ({
    name: name.replace('and ', '& '), count
  }))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Threat Landscape Overview</h2>
          <p className="text-sm text-gray-500">Real-time threat intelligence from {Object.keys(summary.sources).length} feeds</p>
        </div>
        <div className="flex items-center gap-2 bg-gray-900 border border-gray-800 rounded px-3 py-1.5">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-xs text-gray-400">Live</span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard title="Total IOCs" value={summary.total_iocs.toLocaleString()} subtitle={`${Object.keys(summary.sources).length} active feeds`} icon={Shield} color="text-cyan-400" />
        <StatCard title="ATT&CK Coverage" value={`${Math.round(mitre_summary.kill_chain_coverage * 100)}%`} subtitle={`${mitre_summary.unique_techniques} techniques mapped`} icon={Target} color="text-purple-400" />
        <StatCard title="Anomalies" value={anomalies?.anomalies_found || 0} subtitle={`${anomalies?.anomaly_rate || 0}% anomaly rate`} icon={AlertTriangle} color="text-amber-400" />
        <StatCard title="Malware Families" value={mitre_summary.malware_families?.length || 0} subtitle="Active threat groups" icon={Activity} color="text-red-400" />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-2 gap-4">
        {/* IOC Types */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">IOC Type Distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={typeData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                {typeData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px' }} itemStyle={{ color: '#d1d5db' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Types */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Threat Types</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={threatData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis type="number" stroke="#6b7280" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="name" stroke="#6b7280" tick={{ fontSize: 11 }} width={100} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px' }} itemStyle={{ color: '#d1d5db' }} />
              <Bar dataKey="value" fill="#06b6d4" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-2 gap-4">
        {/* Malware Families */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Top Malware Families</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={malwareData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#6b7280" tick={{ fontSize: 11 }} />
              <YAxis stroke="#6b7280" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px' }} itemStyle={{ color: '#d1d5db' }} />
              <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Activity Timeline */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">24hr Activity Pattern</h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={hourData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="hour" stroke="#6b7280" tick={{ fontSize: 10 }} interval={3} />
              <YAxis stroke="#6b7280" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px' }} itemStyle={{ color: '#d1d5db' }} />
              <Area type="monotone" dataKey="count" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.15} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ATT&CK Tactics */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">MITRE ATT&CK Tactic Coverage</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={tacticData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="name" stroke="#6b7280" tick={{ fontSize: 10 }} angle={-20} textAnchor="end" height={60} />
            <YAxis stroke="#6b7280" tick={{ fontSize: 11 }} />
            <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px' }} itemStyle={{ color: '#d1d5db' }} />
            <Bar dataKey="count" fill="#ef4444" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
