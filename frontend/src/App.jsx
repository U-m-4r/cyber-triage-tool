import { Navigate, Route, Routes } from 'react-router-dom'

import LandingPage from './routes/LandingPage.jsx'
import LoginPage from './routes/LoginPage.jsx'
import DashboardPage from './routes/DashboardPage.jsx'
import CaseWorkspacePage from './routes/CaseWorkspacePage.jsx'
import AppShell from './components/dashboard/AppShell.jsx'
import CasesPage from './routes/CasesPage.jsx'
import WorkspaceModule from './routes/WorkspaceModule.jsx'
import { NAV_ITEMS } from './data/navigation.js'

export default function App() {
  const laterModules = NAV_ITEMS.filter((item) => !['/dashboard', '/cases'].includes(item.path))

  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />

      <Route element={<AppShell />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/cases" element={<CasesPage />} />
        <Route path="/cases/:caseId" element={<CaseWorkspacePage />} />
        {laterModules.map((item) => (
          <Route
            key={item.path}
            path={item.path}
            element={<WorkspaceModule key={item.path} />}
          />
        ))}
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
