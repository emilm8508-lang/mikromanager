import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Server, Key, Search, ScrollText, Network } from 'lucide-react'
import { cn } from '../lib/utils'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/devices', label: 'Urządzenia', icon: Server },
  { to: '/map', label: 'Mapa sieci', icon: Network },
  { to: '/scanner', label: 'Skaner', icon: Search },
  { to: '/credentials', label: 'Poświadczenia', icon: Key },
  { to: '/logs', label: 'Logi', icon: ScrollText },
]

export function Sidebar() {
  return (
    <aside className="w-56 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-gray-800">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 bg-indigo-600 rounded-lg flex items-center justify-center">
            <Network size={15} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-gray-100 leading-none">MikroManager</p>
            <p className="text-[10px] text-gray-500 mt-0.5">RouterOS v7</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {nav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-600/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-5 py-3 border-t border-gray-800">
        <p className="text-[10px] text-gray-600">MikroManager v1.0</p>
      </div>
    </aside>
  )
}
