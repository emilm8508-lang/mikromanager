import { Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/Sidebar'
import { Dashboard } from './pages/Dashboard'
import { Devices } from './pages/Devices'
import { DeviceDetail } from './pages/DeviceDetail'
import { NetworkMap } from './pages/NetworkMap'
import { Scanner } from './pages/Scanner'
import { Credentials } from './pages/Credentials'
import { Logs } from './pages/Logs'
import { Central } from './pages/Central'
import { Vulnerabilities } from './pages/Vulnerabilities'
import { LinuxHosts } from './pages/LinuxHosts'
import { Inventory } from './pages/Inventory'
import { AuditLog } from './pages/AuditLog'
import { Security } from './pages/Security'
import { AuthGate } from './pages/Login'

export default function App() {
  return (
    <AuthGate>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto scrollbar-thin">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/:id" element={<DeviceDetail />} />
            <Route path="/map" element={<NetworkMap />} />
            <Route path="/scanner" element={<Scanner />} />
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/linux" element={<LinuxHosts />} />
            <Route path="/inventory" element={<Inventory />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/security" element={<Security />} />
            <Route path="/central" element={<Central />} />
          </Routes>
        </main>
      </div>
    </AuthGate>
  )
}
