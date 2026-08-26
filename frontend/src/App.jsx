import { Navigate, Route, Routes } from 'react-router-dom'

import LandingPage from './routes/LandingPage.jsx'
import LoginPage from './routes/LoginPage.jsx'
import DashboardPage from './routes/DashboardPage.jsx'
import CaseWorkspacePage from './routes/CaseWorkspacePage.jsx'
import AppShell from './components/dashboard/AppShell.jsx'
import ModulePlaceholder from './routes/ModulePlaceholder.jsx'
import { NAV_ITEMS } from './data/navigation.js'

/**
 * Phase 1 routes: landing -> login -> dashboard -> case workspace.
 *
 * The remaining sidebar destinations resolve to a shared placeholder so the
 * application shell is navigable end to end without stubbing out the later
 * forensic modules (evidence ingestion, IOC graph, reporting, ...).
 */
export default function App() {
  const laterModules = NAV_ITEMS.filter((item) => item.path !== '/dashboard')

  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />

      <Route element={<AppShell />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        {/* Grouped with the dashboard rather than the placeholders: /cases stays
            a ModulePlaceholder from NAV_ITEMS, and the router matches this more
            specific path for a case ID. */}
        <Route path="/cases/:caseId" element={<CaseWorkspacePage />} />
        {laterModules.map((item) => (
          <Route
            key={item.path}
            path={item.path}
            element={<ModulePlaceholder title={item.label} phase={item.phase} />}
          />
        ))}
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
