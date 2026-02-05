import { Shield, LayoutDashboard, Table, Grid3X3, Network, Radio } from 'lucide-react'

const navItems = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'iocs', label: 'IOC Database', icon: Table },
  { id: 'attack-map', label: 'ATT&CK Map', icon: Grid3X3 },
  { id: 'campaigns', label: 'Campaigns', icon: Network },
  { id: 'feeds', label: 'Feed Status', icon: Radio },
]

export default function Sidebar({ currentPage, onNavigate }) {
  return (
    <div className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col">
      <div className="p-4 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-cyan-400" />
          <div>
            <h1 className="text-sm font-bold text-white tracking-wide">HRTIP</h1>
            <p className="text-[10px] text-gray-500 leading-tight">Healthcare & Retail<br/>Threat Intelligence</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-2 space-y-1">
        {navItems.map(item => {
          const Icon = item.icon
          const active = currentPage === item.id
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded text-sm transition-colors ${
                active
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white border border-transparent'
              }`}
            >
              <Icon className="w-4 h-4" />
              {item.label}
            </button>
          )
        })}
      </nav>

      <div className="p-3 border-t border-gray-800">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-[11px] text-gray-500">System Active</span>
        </div>
      </div>
    </div>
  )
}
