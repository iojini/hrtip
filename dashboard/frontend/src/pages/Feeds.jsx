import { CheckCircle, AlertCircle, Clock, RefreshCw } from 'lucide-react'

const feedInfo = {
  urlhaus: { name: 'URLhaus', desc: 'Malware URLs', org: 'Abuse.ch' },
  feodotracker: { name: 'Feodo Tracker', desc: 'Botnet C2 IPs', org: 'Abuse.ch' },
  threatfox: { name: 'ThreatFox', desc: 'IOCs with malware context', org: 'Abuse.ch' },
  malwarebazaar: { name: 'MalwareBazaar', desc: 'Malware hashes', org: 'Abuse.ch' },
  openphish: { name: 'OpenPhish', desc: 'Phishing URLs', org: 'OpenPhish' },
  alienvault_otx: { name: 'AlienVault OTX', desc: 'Threat pulses', org: 'AT&T Cybersecurity' },
  mastodon: { name: 'Mastodon Infosec', desc: 'Security researcher posts', org: 'Fediverse' },
  rss_feeds: { name: 'RSS Feeds', desc: 'Security news & blogs', org: 'Various' },
}

function timeAgo(dateStr) {
  if (!dateStr) return 'Never'
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function Feeds({ data }) {
  if (!data) return null

  const feeds = data.feeds || {}
  const totalIOCs = Object.values(feeds).reduce((sum, f) => sum + (f.iocs_collected || 0), 0)
  const activeFeeds = Object.values(feeds).filter(f => f.status === 'active').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Feed Status</h2>
          <p className="text-sm text-gray-500">{activeFeeds} active feeds collecting {totalIOCs} IOCs</p>
        </div>
        <button className="flex items-center gap-2 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded px-3 py-1.5 text-sm hover:bg-cyan-500/20 transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          Run All Collectors
        </button>
      </div>

      {/* Feed Cards */}
      <div className="grid grid-cols-2 gap-4">
        {Object.entries(feeds).map(([key, feed]) => {
          const info = feedInfo[key] || { name: key, desc: '', org: '' }
          const isActive = feed.status === 'active'

          return (
            <div key={key} className="bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-gray-700 transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="text-sm font-semibold text-white">{info.name}</h3>
                  <p className="text-xs text-gray-500">{info.desc}</p>
                </div>
                <div className="flex items-center gap-1.5">
                  {isActive ? (
                    <>
                      <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                      <span className="text-[11px] text-green-400">Active</span>
                    </>
                  ) : (
                    <>
                      <AlertCircle className="w-3.5 h-3.5 text-red-400" />
                      <span className="text-[11px] text-red-400">Error</span>
                    </>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="bg-gray-800/50 rounded p-2">
                  <div className="text-[10px] text-gray-500 uppercase">IOCs</div>
                  <div className="text-lg font-bold text-white">{feed.iocs_collected || 0}</div>
                </div>
                <div className="bg-gray-800/50 rounded p-2">
                  <div className="text-[10px] text-gray-500 uppercase">Source</div>
                  <div className="text-xs text-gray-300 mt-1">{info.org}</div>
                </div>
                <div className="bg-gray-800/50 rounded p-2">
                  <div className="text-[10px] text-gray-500 uppercase">Last Run</div>
                  <div className="flex items-center gap-1 mt-1">
                    <Clock className="w-3 h-3 text-gray-500" />
                    <span className="text-xs text-gray-300">{timeAgo(feed.last_run)}</span>
                  </div>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Collection Summary */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Collection Summary</h3>
        <div className="space-y-2">
          {Object.entries(feeds).map(([key, feed]) => {
            const info = feedInfo[key] || { name: key }
            const pct = totalIOCs > 0 ? (feed.iocs_collected / totalIOCs) * 100 : 0
            return (
              <div key={key} className="flex items-center gap-3">
                <span className="text-xs text-gray-400 w-32">{info.name}</span>
                <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-cyan-500" style={{ width: `${pct}%` }} />
                </div>
                <span className="text-xs text-gray-500 w-12 text-right">{feed.iocs_collected}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
