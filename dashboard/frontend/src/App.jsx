import { useState, useEffect } from 'react'
import axios from 'axios'
import Sidebar from './components/Sidebar'
import Overview from './pages/Overview'
import IOCTable from './pages/IOCTable'
import AttackMap from './pages/AttackMap'
import Campaigns from './pages/Campaigns'
import Feeds from './pages/Feeds'

function App() {
  const [page, setPage] = useState('overview')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/dashboard-data')
      setData(response.data)
    } catch (err) {
      // Load demo data if API unavailable
      setData(getDemoData())
    }
    setLoading(false)
  }

  const renderPage = () => {
    if (loading) {
      return (
        <div className="flex items-center justify-center h-full">
          <div className="text-gray-400 text-lg">Loading threat intelligence...</div>
        </div>
      )
    }

    switch (page) {
      case 'overview': return <Overview data={data} />
      case 'iocs': return <IOCTable data={data} />
      case 'attack-map': return <AttackMap data={data} />
      case 'campaigns': return <Campaigns data={data} />
      case 'feeds': return <Feeds data={data} />
      default: return <Overview data={data} />
    }
  }

  return (
    <div className="flex h-screen bg-gray-950 text-white">
      <Sidebar currentPage={page} onNavigate={setPage} />
      <main className="flex-1 overflow-y-auto p-6">
        {renderPage()}
      </main>
    </div>
  )
}

function getDemoData() {
  return {
    summary: {
      total_iocs: 505,
      sources: { urlhaus: 100, feodotracker: 5, threatfox: 100, malwarebazaar: 100, openphish: 100, alienvault_otx: 100 },
      ioc_types: { url: 200, ipv4: 45, domain: 120, sha256: 100, md5: 40 },
      threat_types: { malware_download: 120, botnet_c2: 45, phishing: 200, malware: 140 }
    },
    top_iocs: [
      { type: 'ipv4', value: '162.243.103.246', confidence_score: 95, malware: 'Emotet', threat_type: 'botnet_c2', sources: ['feodotracker', 'threatfox', 'alienvault_otx'] },
      { type: 'ipv4', value: '185.148.168.220', confidence_score: 90, malware: 'Emotet', threat_type: 'botnet_c2', sources: ['feodotracker'] },
      { type: 'sha256', value: 'e7cd605568c38bd6...', confidence_score: 88, malware: 'CobaltStrike', threat_type: 'malware', sources: ['malwarebazaar'] },
      { type: 'url', value: 'http://evil-phish.xyz/login', confidence_score: 85, malware: null, threat_type: 'phishing', sources: ['openphish'] },
      { type: 'sha256', value: '8703b4c09bbbf7a4...', confidence_score: 82, malware: 'Stealc', threat_type: 'malware', sources: ['malwarebazaar'] },
      { type: 'domain', value: 'x7k9m2p4q8.xyz', confidence_score: 78, malware: null, threat_type: 'malware', sources: ['threatfox'] },
      { type: 'ipv4', value: '45.33.32.156', confidence_score: 75, malware: 'QakBot', threat_type: 'botnet_c2', sources: ['feodotracker'] },
      { type: 'sha256', value: 'fec0c195adaccc77...', confidence_score: 72, malware: 'Mirai', threat_type: 'malware', sources: ['malwarebazaar'] },
    ],
    mitre_summary: {
      total_iocs_mapped: 350,
      unique_techniques: 18,
      unique_tactics: 9,
      kill_chain_coverage: 0.57,
      top_techniques: [
        ['T1071.001', 45], ['T1566.001', 38], ['T1055', 30], ['T1573', 28], ['T1059.001', 25],
        ['T1547.001', 22], ['T1105', 20], ['T1059.004', 18], ['T1110.001', 15], ['T1571', 12]
      ],
      top_tactics: [
        ['Command and Control', 85], ['Initial Access', 68], ['Execution', 55],
        ['Defense Evasion', 45], ['Persistence', 35], ['Credential Access', 28],
        ['Impact', 20], ['Collection', 15], ['Exfiltration', 10]
      ],
      malware_families: [['Emotet', 45], ['Mirai', 38], ['CobaltStrike', 25], ['Stealc', 18], ['QakBot', 12], ['Smoke Loader', 10]]
    },
    clusters: [
      { cluster_id: 0, potential_campaign: 'Emotet Botnet Campaign', size: 15, threat_types: ['botnet_c2'], malware_families: ['Emotet'], sources: ['feodotracker', 'threatfox'], sample_iocs: ['162.243.103.246', '185.148.168.220', '167.86.75.145'] },
      { cluster_id: 1, potential_campaign: 'Phishing Campaign', size: 42, threat_types: ['phishing'], malware_families: [], sources: ['openphish', 'alienvault_otx'], sample_iocs: ['evil-phish.xyz', 'secure-login-bank.com', 'account-verify.tk'] },
      { cluster_id: 2, potential_campaign: 'Mirai Botnet Activity', size: 28, threat_types: ['malware'], malware_families: ['Mirai'], sources: ['malwarebazaar'], sample_iocs: ['fec0c195adaccc77...', 'e8d4dc3fe29cd37e...'] },
      { cluster_id: 3, potential_campaign: 'Cobalt Strike Infrastructure', size: 10, threat_types: ['malware'], malware_families: ['CobaltStrike'], sources: ['malwarebazaar', 'threatfox'], sample_iocs: ['e7cd605568c38bd6...', '8.137.149.67'] },
    ],
    anomalies: {
      anomalies_found: 12,
      anomaly_rate: 2.4,
      top_anomalies: [
        { value: 'x7k9m2p4q8.xyz', type: 'domain', score: 95.2 },
        { value: '198.51.100.50', type: 'ipv4', score: 88.7 },
        { value: 'a1b2c3d4e5.tk', type: 'domain', score: 82.1 },
      ]
    },
    feeds: {
      urlhaus: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 100 },
      feodotracker: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 5 },
      threatfox: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 100 },
      malwarebazaar: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 100 },
      openphish: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 100 },
      alienvault_otx: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 100 },
      mastodon: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 78 },
      rss_feeds: { status: 'active', last_run: '2026-02-05T02:00:00Z', iocs_collected: 15 },
    },
    temporal: {
      hour_distribution: {0:12, 1:8, 2:15, 3:22, 4:18, 5:10, 6:8, 7:12, 8:25, 9:30, 10:35, 11:28, 12:20, 13:32, 14:45, 15:38, 16:30, 17:25, 18:20, 19:15, 20:18, 21:22, 22:25, 23:18},
      behavioral_pattern: 'mixed_schedule'
    }
  }
}

export default App
