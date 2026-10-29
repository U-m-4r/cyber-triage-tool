import { deriveIndicators } from '../../utils/relationships.js'
import { useMemo, useState } from 'react'
import Panel from '../dashboard/Panel.jsx'
import Icon from '../ui/Icon.jsx'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import './CaseIoc.css'

const TYPE_META = {
  host: { label: 'Hosts', icon: 'host' },
  network: { label: 'Network endpoints', icon: 'network' },
  technique: { label: 'ATT&CK techniques', icon: 'triage' },
  file: { label: 'Evidence files', icon: 'file' },
  registry: { label: 'Registry keys', icon: 'registry' },
}

const TYPE_ORDER = ['network', 'file', 'registry', 'technique', 'host']
/**
 * IOC Graph tab of the case workspace.
 *
 * @param {{ caseRecord: object }} props
 */
export default function CaseIoc({ caseRecord }) {
  const [typeFilter, setTypeFilter] = useState('ALL')

  const findings = Array.isArray(caseRecord?.findings) ? caseRecord.findings : []
  const indicators = useMemo(() => deriveIndicators(findings), [findings])
  const declaredTotal = caseRecord?.counts?.iocs

  const presentTypes = useMemo(
    () => TYPE_ORDER.filter((t) => indicators.some((i) => i.type === t)),
    [indicators],
  )

  const filtered = useMemo(
    () => (typeFilter === 'ALL' ? indicators : indicators.filter((i) => i.type === typeFilter)),
    [indicators, typeFilter],
  )

  const explanation = <section className="integration-page">
    <h2>How to read this view</h2>
    <p>IOC means indicator of compromise. This view groups evidence files, network references and registry sources mentioned in saved findings. An entity is a reference for investigation, not a confirmed IOC.</p>
    <p>Left nodes are recorded hosts; right nodes are referenced entities. A line means a finding links that host to that entity. Colors show the highest risk among its findings. “Refs” counts findings that mention the entity, not attacks or uploads.</p>
    <p>Evidence filenames refer to uploaded sources, not individual files inside a disk image. YARA pattern matches are listed separately. Only the case’s saved ranked findings (up to 100) contribute to this view.</p>
  </section>

  const recordedHits = (caseRecord?.iocs || []).length > 0 && <section className="integration-page">
    <h3>Recorded YARA matches</h3><p>Rule matches identify patterns for review; they do not prove compromise.</p>
    <ul>{caseRecord.iocs.map((hit, index) => <li key={`${hit.rule}-${index}`}>
      <strong>{hit.rule}</strong> — {hit.target} · {hit.meta?.description || 'Pattern matched'}
    </li>)}</ul></section>

  if (indicators.length === 0) {
    return (
      <div className="case-ioc">
        {explanation}
        {recordedHits}
        <Panel
          title="Evidence relationships"
          subtitle={
            typeof declaredTotal === 'number'
              ? `${declaredTotal} indicators counted during intake`
              : 'Indicator relationships'
          }
        >
          <div className="case-ioc__empty">
            <Icon name="graph" size={16} className="case-ioc__empty-icon" />
            <p className="case-ioc__empty-copy">
              No supported entities were found in the saved findings. YARA matches, when present, are listed separately above.
            </p>
          </div>
        </Panel>
      </div>
    )
  }

  return (
    <div className="case-ioc">
      {explanation}
      {recordedHits}
      <div className="case-ioc__controls" role="group" aria-label="Filter indicators by type">
        <span className="case-ioc__count">
          <strong className="tabular">{indicators.length}</strong> entities referenced by{' '}
          {findings.length} findings
          {typeof declaredTotal === 'number' && (
            <span className="case-ioc__count-note"> · {declaredTotal} YARA matches recorded at intake</span>
          )}
        </span>
        <div className="case-ioc__chips">
          <TypeChip active={typeFilter === 'ALL'} onClick={() => setTypeFilter('ALL')}>
            All
          </TypeChip>
          {presentTypes.map((type) => (
            <TypeChip key={type} active={typeFilter === type} onClick={() => setTypeFilter(type)}>
              {TYPE_META[type]?.label ?? type}
            </TypeChip>
          ))}
        </div>
      </div>

      <div className="case-ioc__layout">
        <Panel className="case-ioc__list-panel" title="Referenced entities" subtitle="Grouped by type; refs count findings" flush>
          <IndicatorGroups
            indicators={filtered}
            types={typeFilter === 'ALL' ? presentTypes : [typeFilter]}
          />
        </Panel>

        <Panel
          className="case-ioc__graph-panel"
          title="Relationships"
          subtitle="Host to indicator edges"
        >
          <RelationshipGraph indicators={filtered} />
        </Panel>
      </div>
    </div>
  )
}

function TypeChip({ active, onClick, children }) {
  return (
    <button
      type="button"
      className={`case-ioc__chip${active ? ' case-ioc__chip--active' : ''}`}
      onClick={onClick}
      aria-pressed={active}
    >
      {children}
    </button>
  )
}

function IndicatorGroups({ indicators, types }) {
  return (
    <div className="case-ioc__groups">
      {types.map((type) => {
        const rows = indicators.filter((i) => i.type === type)
        if (rows.length === 0) return null
        return (
          <section className="ioc-group" key={type}>
            <h3 className="ioc-group__head eyebrow">
              <Icon name={TYPE_META[type]?.icon ?? 'shield'} size={12} />
              {TYPE_META[type]?.label ?? type} ({rows.length})
            </h3>
            <ul className="ioc-group__list">
              {rows.map((ind) => (
                <li className="ioc-item" key={ind.id}>
                  <span className="ioc-item__value mono" title={ind.value}>
                    {ind.value}
                  </span>
                  <span className="ioc-item__hosts">
                    {ind.hosts.length > 0 ? ind.hosts.join(', ') : '—'}
                  </span>
                  <span className="ioc-item__refs tabular">
                    {ind.findingIds.length} ref{ind.findingIds.length === 1 ? '' : 's'}
                  </span>
                  <SeverityBadge severity={ind.severity} size="sm" />
                </li>
              ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}

function truncate(str, max) {
  if (typeof str !== 'string') return ''
  return str.length > max ? `${str.slice(0, max - 1)}…` : str
}

/**
 * Lightweight relationship view: hosts on the left, indicators on the right,
 * an edge for every host an indicator was observed on. Deliberately not a
 * force-directed graph — a deterministic two-column layout stays readable and
 * needs no extra dependency. Indicator nodes carry severity by colour; hosts and
 * edges stay neutral.
 */
function RelationshipGraph({ indicators }) {
  const hosts = useMemo(() => {
    const set = new Set()
    for (const ind of indicators) for (const h of ind.hosts) set.add(h)
    return [...set]
  }, [indicators])

  if (indicators.length === 0) {
    return <p className="case-ioc__graph-empty">No indicators match the current filter.</p>
  }

  const W = 760
  const rowH = 34
  const padY = 22
  const leftX = 150
  const rightX = 470
  const rows = Math.max(hosts.length, indicators.length, 1)
  const H = rows * rowH + padY * 2

  const nodeY = (index, count) => {
    const blockH = count * rowH
    const startY = (H - blockH) / 2 + rowH / 2
    return startY + index * rowH
  }

  const hostY = (h) => nodeY(hosts.indexOf(h), hosts.length)

  return (
    <div className="case-ioc__graph">
      {hosts.length === 0 && <p className="case-ioc__graph-empty">No host was recorded for these findings, so there are no host connections to draw. The nodes below show referenced entities only.</p>}
      <svg
        className="case-ioc__svg"
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        role="img"
        aria-label="Host to indicator relationship graph"
      >
        {/* Edges first so nodes sit on top. */}
        {indicators.map((ind, i) => {
          const iy = nodeY(i, indicators.length)
          const targets = ind.hosts
          return targets.map((h, j) => {
            const hy = h != null ? hostY(h) : H / 2
            return (
              <path
                key={`${ind.id}-edge-${j}`}
                className="ioc-edge"
                d={`M ${leftX} ${hy} C ${(leftX + rightX) / 2} ${hy}, ${(leftX + rightX) / 2} ${iy}, ${rightX} ${iy}`}
                fill="none"
              />
            )
          })
        })}

        {/* Host nodes */}
        {hosts.map((h) => {
          const hy = hostY(h)
          return (
            <g key={`host-${h}`} className="ioc-host">
              <circle className="ioc-host__dot" cx={leftX} cy={hy} r={5} />
              <text className="ioc-host__label" x={leftX - 14} y={hy} textAnchor="end" dominantBaseline="middle">
                {truncate(h, 16)}
                <title>{h}</title>
              </text>
            </g>
          )
        })}

        {/* Indicator nodes */}
        {indicators.map((ind, i) => {
          const iy = nodeY(i, indicators.length)
          const sevKey = String(ind.severity).toLowerCase()
          return (
            <g key={`ind-${ind.id}`} className="ioc-node">
              <circle className={`ioc-node__dot ioc-node__dot--${sevKey}`} cx={rightX} cy={iy} r={4.5} />
              <text className="ioc-node__label" x={rightX + 12} y={iy} dominantBaseline="middle">
                {truncate(ind.value, 34)}
                <title>{ind.value}</title>
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
