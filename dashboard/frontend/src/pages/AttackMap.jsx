import { useState, useEffect } from 'react'
import { API_BASE } from '../App'

const TACTICS = [
  'reconnaissance', 'resource_development', 'initial_access', 'execution',
  'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
  'discovery', 'lateral_movement', 'collection', 'command_and_control', 'exfiltration', 'impact'
]

export default function AttackMap() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const apiUrl = API_BASE ? `${API_BASE}/dashboard-data` : '/api/dashboard-data'
        const response = await fetch(apiUrl)
        const result = await response.json()
        setData(result)
      } catch (err) {
        console.error(err)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  if (loading) return <div className="p-6 text-gray-400">Loading ATT&CK data...</div>

  const mitre = data?.mitre_summary || {}
  const tacticCounts = Object.fromEntries(mitre.top_tactics || [])
  const techniques = mitre.top_techniques || []

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">MITRE ATT&CK Map</h1>
        <p className="text-gray-400">Threat coverage across the kill chain</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-sm">Techniques Mapped</p>
          <p className="text-3xl font-bold text-white">{mitre.unique_techniques || 0}</p>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-sm">Tactics Covered</p>
          <p className="text-3xl font-bold text-white">{mitre.unique_tactics || 0}</p>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-sm">Kill Chain Coverage</p>
          <p className="text-3xl font-bold text-white">{Math.round((mitre.kill_chain_coverage || 0) * 100)}%</p>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-sm">IOCs Mapped</p>
          <p className="text-3xl font-bold text-white">{mitre.total_iocs_mapped || 0}</p>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h3 className="text-white font-semibold mb-4">Kill Chain Heatmap</h3>
        <div className="grid grid-cols-7 gap-2">
          {TACTICS.map(tactic => {
            const count = tacticCounts[tactic] || 0
            const intensity = Math.min(count / 50, 1)
            return (
              <div
                key={tactic}
                className="p-3 rounded-lg text-center"
                style={{ backgroundColor: `rgba(239, 68, 68, ${0.2 + intensity * 0.8})` }}
              >
                <p className="text-xs text-gray-300 truncate">{tactic.replace('_', ' ')}</p>
                <p className="text-xl font-bold text-white">{count}</p>
              </div>
            )
          })}
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h3 className="text-white font-semibold mb-4">Top Techniques</h3>
        <div className="space-y-2">
          {techniques.slice(0, 10).map(([techId, count]) => (
            <div key={techId} className="flex items-center gap-4">
              <span className="text-cyan-400 font-mono w-24">{techId}</span>
              <div className="flex-1 bg-gray-700 rounded-full h-4">
                <div
                  className="bg-red-500 h-4 rounded-full"
                  style={{ width: `${(count / (techniques[0]?.[1] || 1)) * 100}%` }}
                ></div>
              </div>
              <span className="text-gray-400 w-12 text-right">{count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
