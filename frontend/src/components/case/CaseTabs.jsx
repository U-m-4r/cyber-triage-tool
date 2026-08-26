import { CASE_TABS } from '../../data/navigation.js'
import './CaseTabs.css'

/**
 * Investigation tab strip inside a case workspace.
 *
 * Only Overview is implemented. Unbuilt tabs render as disabled buttons rather
 * than being hidden, because an investigator needs to see the whole workflow —
 * but they are genuinely inert and each says what it is waiting on, so the strip
 * never implies functionality that does not exist.
 *
 * @param {object} props
 * @param {string} props.activeTab
 * @param {(id: string) => void} props.onSelect
 */
export default function CaseTabs({ activeTab, onSelect }) {
  return (
    <div className="case-tabs" role="tablist" aria-label="Investigation sections">
      {CASE_TABS.map((tab) => {
        const active = tab.id === activeTab

        return (
          <button
            key={tab.id}
            className={`case-tab${active ? ' case-tab--active' : ''}${
              tab.available ? '' : ' case-tab--pending'
            }`}
            type="button"
            role="tab"
            aria-selected={active}
            disabled={!tab.available}
            title={tab.available ? undefined : `Not implemented — ${tab.phase}`}
            onClick={() => tab.available && onSelect(tab.id)}
          >
            {tab.label}
            {!tab.available && <span className="case-tab__flag">Planned</span>}
          </button>
        )
      })}
    </div>
  )
}
