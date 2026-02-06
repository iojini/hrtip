import { useState, useEffect } from 'react'
import { CheckCircle, XCircle, Clock } from 'lucide-react'
import { API_BASE } from '../App'

export default function Feeds() {
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

  if (loading) return <div className="p-6 text-gray-400">Loading feed status...</div>

  const feeds = data?.feeds || {}

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Feed Status</h1>
        <p className="text-gray-400">Monitor threat intelligence feed health</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {Object.entries(feeds).map(([name, feed]) => (
          <div key={name} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex justify-between items-start mb-3">
              <h3 className="text-white font-medium capitalize">{name.replace('_', ' ')}</h3>
              {feed.status === 'active' ? (
                <CheckCircle className="text-green-400" size={20} />
              ) : (
                <XCircle className="text-red-400" size={20} />
              )}
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">IOCs Collected</span>
                <span className="text-white">{feed.iocs_collected?.toLocaleString() || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Status</span>
                <span className={feed.status === 'active' ? 'text-green-400' : 'text-red-400'}>
                  {feed.status || 'unknown'}
                </span>
              </div>
              {feed.last_run && (
                <div className="flex items-center gap-1 text-sm text-gray-500 mt-2">
                  <Clock size={14} />
                  <span>Last updated: {new Date(feed.last_run).toLocaleString()}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
