import { useState, useEffect } from 'react'
import { Search, Filter, Download } from 'lucide-react'
import { API_BASE } from '../App'

export default function IOCTable() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')

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

  if (loading) return <div className="p-6 text-gray-400">Loading IOCs...</div>

  const iocs = data?.top_iocs || []
  const types = [...new Set(iocs.map(i => i.type))]

  const filtered = iocs.filter(ioc => {
    const matchSearch = ioc.value?.toLowerCase().includes(search.toLowerCase())
    const matchType = !typeFilter || ioc.type === typeFilter
    return matchSearch && matchType
  })

  return (
    <div className="p-6 space-y-4">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-white">IOC Database</h1>
        <button className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg">
          <Download size={18} /> Export
        </button>
      </div>

      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 text-gray-400" size={20} />
          <input
            type="text"
            placeholder="Search IOCs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white"
        >
          <option value="">All Types</option>
          {types.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-900">
            <tr>
              <th className="text-left text-gray-400 p-4">Type</th>
              <th className="text-left text-gray-400 p-4">Value</th>
              <th className="text-left text-gray-400 p-4">Confidence</th>
              <th className="text-left text-gray-400 p-4">Threat Type</th>
              <th className="text-left text-gray-400 p-4">Malware</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc, i) => (
              <tr key={i} className="border-t border-gray-700 hover:bg-gray-750">
                <td className="p-4">
                  <span className="bg-cyan-900 text-cyan-300 px-2 py-1 rounded text-sm">{ioc.type}</span>
                </td>
                <td className="p-4 text-white font-mono text-sm truncate max-w-md">{ioc.value}</td>
                <td className="p-4">
                  <div className="flex items-center gap-2">
                    <div className="w-16 bg-gray-700 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full ${ioc.confidence_score >= 70 ? 'bg-green-500' : ioc.confidence_score >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
                        style={{width: `${ioc.confidence_score}%`}}
                      ></div>
                    </div>
                    <span className="text-gray-400 text-sm">{ioc.confidence_score}</span>
                  </div>
                </td>
                <td className="p-4 text-gray-300">{ioc.threat_type || '-'}</td>
                <td className="p-4 text-gray-300">{ioc.malware || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
