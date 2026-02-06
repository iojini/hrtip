import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Overview from './pages/Overview'
import IOCTable from './pages/IOCTable'
import AttackMap from './pages/AttackMap'
import Campaigns from './pages/Campaigns'
import Feeds from './pages/Feeds'

// Use environment variable for API URL, fallback to localhost for development
const API_BASE = import.meta.env.VITE_API_URL || ''

export { API_BASE }

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-900">
        <Sidebar />
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/iocs" element={<IOCTable />} />
            <Route path="/attack-map" element={<AttackMap />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/feeds" element={<Feeds />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
