import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

const TACTICS_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact'
]

const TECHNIQUE_NAMES = {
  'T1071.001': 'App Layer Protocol: Web',
  'T1566.001': 'Spearphishing Attachment',
  'T1055': 'Process Injection',
  'T1573': 'Encrypted Channel',
  'T1059.001': 'PowerShell',
  'T1547.001': 'Registry Run Keys',
  'T1105': 'Ingress Tool Transfer',
  'T1059.004': 'Unix Shell',
  'T1110.001': 'Password Guessing',
  'T1571': 'Non-Standard Port',
}

export default function AttackMap({ data }) {
  if (!data) return null
  const { mitre_summary } = data

  const tacticMap = {}
  for (const [name, count] of (mitre_summary.top_tactics || [])) {
    tacticMap[name] = count
  }

  const techData = (mitre_summary.top_techniques || []).map(([id, count]) => ({
    id, name: TECHNIQUE_NAMES[id] || id, count
  }))

  const maxTacticCount = Math.max(...Object.values(tacticMap), 1)

  const getHeatColor = (count) => {
    if (!count) return 'bg-gray-800/50 border-gray-800'
    const intensity = count / maxTacticCount
    if (intensity > 0.7) return 'bg-red-500/30 border-red-500/40 text-red-300'
    if (intensity > 0.4) return 'bg-amber-500/20 border-amber-500/30 text-amber-300'
    return 'bg-cyan-500/15 border-cyan-500/20 text-cyan-300'
  }

  const getMitreUrl = (id) => {
    return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/'
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white">MITRE ATT&CK Coverage</h2>
        <p className="text-sm text-gray-500">
          {mitre_summary.unique_techniques} techniques across {mitre_summary.unique_tactics} tactics
        </p>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">Kill Chain Heatmap</h3>
        <div className="grid grid-cols-7 gap-2">
          {TACTICS_ORDER.map(tactic => {
            const count = tacticMap[tactic] || 0
            return (
              <div key={tactic} className={'border rounded-lg p-3 text-center ' + getHeatColor(count)}>
                <div className="text-[10px] font-medium leading-tight mb-1">{tactic}</div>
                <div className="text-lg font-bold">{count || '-'}</div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">Top Techniques</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={techData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis type="number" stroke="#6b7280" tick={{ fontSize: 11 }} />
            <YAxis type="category" dataKey="name" stroke="#6b7280" tick={{ fontSize: 11 }} width={180} />
            <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }} />
            <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Technique ID</th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Name</th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Count</th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Reference</th>
            </tr>
          </thead>
          <tbody>
            {techData.map((tech, i) => (
              <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-4 py-2.5 text-sm font-mono text-cyan-400">{tech.id}</td>
                <td className="px-4 py-2.5 text-sm text-gray-300">{tech.name}</td>
                <td className="px-4 py-2.5 text-sm text-gray-400">{tech.count}</td>
                <td className="px-4 py-2.5">
                  <a href={getMitreUrl(tech.id)} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-500 hover:text-cyan-400">
                    MITRE
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
