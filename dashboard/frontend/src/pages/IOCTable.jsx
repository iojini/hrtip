import { useState } from 'react'
import { Search, ArrowUpDown, ExternalLink } from 'lucide-react'

export default function IOCTable({ data }) {
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('confidence_score')
  const [filterType, setFilterType] = useState('all')

  if (!data) return null

  const iocs = data.top_iocs || []

  const filtered = iocs
    .filter(ioc => {
      if (filterType !== 'all' && ioc.type !== filterType) return false
      if (search && !ioc.value.toLowerCase().includes(search.toLowerCase()) &&
          !(ioc.malware || '').toLowerCase().includes(search.toLowerCase())) return false
      return true
    })
    .sort((a, b) => (b[sortBy] || 0) - (a[sortBy] || 0))

  const typeColors = {
    ipv4: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    domain: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    url: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    sha256: 'bg-red-500/10 text-red-400 border-red-500/20',
    md5: 'bg-pink-500/10 text-pink-400 border-pink-500/20',
  }

  const severityColor = (score) => {
    if (score >= 80) return 'text-red-400'
    if (score >= 60) return 'text-amber-400'
    if (score >= 40) return 'text-yellow-400'
    return 'text-gray-400'
  }

  const severityBg = (score) => {
    if (score >= 80) return 'bg-red-500'
    if (score >= 60) return 'bg-amber-500'
    if (score >= 40) return 'bg-yellow-500'
    return 'bg-gray-500'
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-bold text-white">IOC Database</h2>
        <p className="text-sm text-gray-500">Enriched indicators of compromise with confidence scoring</p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search IOCs, malware families..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-gray-900 border border-gray-800 rounded pl-9 pr-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50"
          />
        </div>
        <div className="flex gap-1">
          {['all', 'ipv4', 'domain', 'url', 'sha256'].map(type => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                filterType === type
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : 'bg-gray-900 text-gray-500 border border-gray-800 hover:text-white'
              }`}
            >
              {type === 'all' ? 'All' : type.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase tracking-wider">Type</th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase tracking-wider">Value</th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase tracking-wider">Malware</th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase tracking-wider">Threat Type</th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase tracking-wider cursor-pointer" onClick={() => setSortBy('confidence_score')}>
                <span className="flex items-center gap-1">Confidence <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase tracking-wider">Sources</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc, i) => (
              <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                <td className="px-4 py-3">
                  <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-medium border ${typeColors[ioc.type] || 'bg-gray-800 text-gray-400'}`}>
                    {ioc.type.toUpperCase()}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm font-mono text-gray-300">{ioc.value}</td>
                <td className="px-4 py-3 text-sm">
                  {ioc.malware ? (
                    <span className="text-red-400 font-medium">{ioc.malware}</span>
                  ) : (
                    <span className="text-gray-600">—</span>
                  )}
                </td>
                <td className="px-4 py-3 text-sm text-gray-400">{(ioc.threat_type || '').replace('_', ' ')}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 rounded-full bg-gray-800 overflow-hidden">
                      <div className={`h-full rounded-full ${severityBg(ioc.confidence_score)}`} style={{ width: `${ioc.confidence_score}%` }} />
                    </div>
                    <span className={`text-sm font-medium ${severityColor(ioc.confidence_score)}`}>{ioc.confidence_score}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap">
                    {(ioc.sources || []).map((s, j) => (
                      <span key={j} className="text-[10px] bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{s}</span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
