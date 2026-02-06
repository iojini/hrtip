import { useState, useEffect } from 'react'
import { Target, Users, AlertCircle } from 'lucide-react'
import { API_BASE } from '../App'

export default function Campaigns() {
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

  if (loading) return <div className="p-6 text-gray-400">Loading campaigns...</div>

  const clusters = data?.clusters || []
  const anomalies = data?.anomalies || {}

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Threat Campaigns</h1>
        <p className="text-gray-400">ML-detected threat clusters and anomalies</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <Target className="text-cyan-400" />
            <div>
              <p className="text-gray-400 text-sm">Active Campaigns</p>
              <p className="text-2xl font-bold text-white">{clusters.length}</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <AlertCircle className="text-yellow-400" />
            <div>
              <p className="text-gray-400 text-sm">Anomalies Detected</p>
              <p className="text-2xl font-bold text-white">{anomalies.anomalies_found || 0}</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <Users className="text-purple-400" />
            <div>
              <p className="text-gray-400 text-sm">Anomaly Rate</p>
              <p className="text-2xl font-bold text-white">{anomalies.anomaly_rate || 0}%</p>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700">
          <h3 className="text-white font-semibold">Detected Campaigns</h3>
        </div>
        <div className="divide-y divide-gray-700">
          {clusters.map((cluster, i) => (
            <div key={i} className="p-4 hover:bg-gray-750">
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="text-white font-medium">{cluster.potential_campaign || `Cluster ${cluster.cluster_id}`}</h4>
                  <p className="text-gray-400 text-sm">{cluster.size} IOCs in cluster</p>
                </div>
                <span className={`px-2 py-1 rounded text-sm ${
                  cluster.size > 50 ? 'bg-red-900 text-red-300' : 
                  cluster.size > 20 ? 'bg-yellow-900 text-yellow-300' : 
                  'bg-green-900 text-green-300'
                }`}>
                  {cluster.size > 50 ? 'High' : cluster.size > 20 ? 'Medium' : 'Low'} Activity
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {(cluster.threat_types || []).map((t, j) => (
                  <span key={j} className="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">{t}</span>
                ))}
                {(cluster.malware_families || []).map((m, j) => (
                  <span key={j} className="bg-purple-900 text-purple-300 px-2 py-1 rounded text-xs">{m}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {anomalies.top_anomalies?.length > 0 && (
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="p-4 border-b border-gray-700">
            <h3 className="text-white font-semibold">Top Anomalies</h3>
          </div>
          <div className="divide-y divide-gray-700">
            {anomalies.top_anomalies.map((a, i) => (
              <div key={i} className="p-4 flex justify-between items-center">
                <div>
                  <span className="bg-cyan-900 text-cyan-300 px-2 py-1 rounded text-sm mr-2">{a.type}</span>
                  <span className="text-white font-mono text-sm">{a.value}</span>
                </div>
                <span className="text-yellow-400">Score: {a.score?.toFixed(2)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
