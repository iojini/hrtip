import { AlertTriangle, Shield, Bug, Network } from 'lucide-react'

const campaignIcons = {
  'Emotet Botnet Campaign': Bug,
  'Phishing Campaign': AlertTriangle,
  'Mirai Botnet Activity': Network,
  'Cobalt Strike Infrastructure': Shield,
}

const severityColors = {
  critical: 'border-red-500/40 bg-red-500/5',
  high: 'border-amber-500/40 bg-amber-500/5',
  medium: 'border-yellow-500/40 bg-yellow-500/5',
  low: 'border-gray-500/40 bg-gray-500/5',
}

const severityBadge = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

function getSeverity(cluster) {
  if (cluster.malware_families?.length && cluster.size > 10) return 'critical'
  if (cluster.threat_types?.includes('botnet_c2') || cluster.malware_families?.length) return 'high'
  if (cluster.threat_types?.includes('phishing')) return 'medium'
  return 'low'
}

export default function Campaigns({ data }) {
  if (!data) return null

  const clusters = data.clusters || []
  const anomalies = data.anomalies || {}

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white">Threat Campaigns</h2>
        <p className="text-sm text-gray-500">ML-identified threat clusters and anomalous indicators</p>
      </div>

      {/* Campaign Cards */}
      <div className="grid grid-cols-2 gap-4">
        {clusters.map((cluster, i) => {
          const severity = getSeverity(cluster)
          const Icon = campaignIcons[cluster.potential_campaign] || Shield
          return (
            <div key={i} className={`border rounded-lg p-5 ${severityColors[severity]}`}>
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${severity === 'critical' ? 'bg-red-500/10' : severity === 'high' ? 'bg-amber-500/10' : 'bg-cyan-500/10'}`}>
                    <Icon className={`w-5 h-5 ${severity === 'critical' ? 'text-red-400' : severity === 'high' ? 'text-amber-400' : 'text-cyan-400'}`} />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">{cluster.potential_campaign}</h3>
                    <p className="text-xs text-gray-500">{cluster.size} related indicators</p>
                  </div>
                </div>
                <span className={`text-[10px] font-medium uppercase px-2 py-0.5 rounded border ${severityBadge[severity]}`}>
                  {severity}
                </span>
              </div>

              <div className="space-y-2 mb-3">
                {cluster.malware_families?.length > 0 && (
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-gray-500 w-16">Malware</span>
                    <div className="flex gap-1">
                      {cluster.malware_families.map((m, j) => (
                        <span key={j} className="text-[11px] bg-red-500/10 text-red-400 px-2 py-0.5 rounded border border-red-500/20">{m}</span>
                      ))}
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-gray-500 w-16">Threats</span>
                  <div className="flex gap-1">
                    {(cluster.threat_types || []).map((t, j) => (
                      <span key={j} className="text-[11px] bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{t.replace('_', ' ')}</span>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-gray-500 w-16">Sources</span>
                  <div className="flex gap-1">
                    {(cluster.sources || []).map((s, j) => (
                      <span key={j} className="text-[11px] bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{s}</span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="border-t border-gray-800 pt-2">
                <span className="text-[11px] text-gray-500">Sample IOCs:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(cluster.sample_iocs || []).slice(0, 3).map((ioc, j) => (
                    <span key={j} className="text-[11px] font-mono bg-gray-800/70 text-gray-400 px-2 py-0.5 rounded">{ioc}</span>
                  ))}
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Anomalies Section */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <h3 className="text-sm font-semibold text-gray-300">Anomalous Indicators</h3>
          <span className="text-xs bg-amber-500/10 text-amber-400 px-2 py-0.5 rounded border border-amber-500/20 ml-auto">
            {anomalies.anomalies_found || 0} detected ({anomalies.anomaly_rate || 0}% rate)
          </span>
        </div>

        <div className="space-y-2">
          {(anomalies.top_anomalies || []).map((a, i) => (
            <div key={i} className="flex items-center justify-between bg-gray-800/30 rounded px-4 py-2.5 border border-gray-800">
              <div className="flex items-center gap-3">
                <span className="text-[11px] bg-purple-500/10 text-purple-400 px-2 py-0.5 rounded border border-purple-500/20">
                  {a.type?.toUpperCase()}
                </span>
                <span className="text-sm font-mono text-gray-300">{a.value}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-20 h-1.5 rounded-full bg-gray-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${a.score >= 80 ? 'bg-red-500' : a.score >= 60 ? 'bg-amber-500' : 'bg-yellow-500'}`}
                    style={{ width: `${a.score}%` }}
                  />
                </div>
                <span className={`text-sm font-medium ${a.score >= 80 ? 'text-red-400' : a.score >= 60 ? 'text-amber-400' : 'text-yellow-400'}`}>
                  {a.score}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
