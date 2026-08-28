import { Fragment, useMemo, useState } from 'react'
import Panel from '../dashboard/Panel.jsx'
import Icon from '../ui/Icon.jsx'
import { formatTimestamp } from '../../utils/format.js'
import './CaseEvidence.css'

const KIND_ICON = {
  image: 'evidence',
  log: 'reports',
  registry: 'registry',
  capture: 'network',
}

// Human-readable type for the source kind. Processing state is neutral because
// an unparsed source is not a severity.
const KIND_LABEL = {
  image: 'Disk / memory image',
  log: 'Log file',
  registry: 'Registry hive',
  capture: 'Packet capture',
}

const STATE_LABEL = {
  PARSED: 'Parsed',
  INDEXING: 'Indexing',
  QUEUED: 'Queued',
}

/**
 * Evidence tab of the case workspace.
 *
 * A chain-of-custody view: every acquired source is traceable to who took it,
 * when, and to a SHA-256 digest that still matches. Cryptographic integrity is
 * surfaced prominently because in a forensic context "we have the disk" is not a
 * fact until it verifies. Outstanding acquisitions are listed separately so they
 * never inflate the evidence already in hand.
 *
 * @param {{ caseRecord: import('../../data/mockCases.js').CaseRecord }} props
 */
export default function CaseEvidence({ caseRecord }) {
  const evidence = caseRecord?.evidence ?? {}
  const sources = Array.isArray(evidence.sources) ? evidence.sources : []
  const pending = Array.isArray(evidence.pending) ? evidence.pending : []
  const [openId, setOpenId] = useState(null)

  const stats = useMemo(() => {
    const parsed = sources.filter((s) => s.state === 'PARSED').length
    const verified = sources.filter((s) => s.integrity === 'HASH MATCH').length
    const hashed = sources.filter((s) => s.sha256).length
    return { parsed, verified, hashed }
  }, [sources])

  const declaredCount = caseRecord?.counts?.evidence

  if (sources.length === 0 && pending.length === 0) {
    return (
      <div className="case-evidence-tab">
        <Panel title="Evidence" subtitle="Chain of custody">
          <div className="case-evidence-tab__empty">
            <Icon name="evidence" size={16} className="case-evidence-tab__empty-icon" />
            <p className="case-evidence-tab__empty-copy">
              No evidence sources have been recorded for this case yet. Acquired sources and their
              hashes appear here once intake begins.
            </p>
          </div>
        </Panel>
      </div>
    )
  }

  return (
    <div className="case-evidence-tab">
      <div className="case-evidence-tab__summary">
        <SummaryStat label="Sources acquired" value={sources.length} />
        <SummaryStat label="Parsed" value={stats.parsed} />
        <SummaryStat label="Hash-verified" value={stats.verified} icon="lock" />
        <SummaryStat label="Outstanding" value={pending.length} />
        {typeof declaredCount === 'number' && (
          <SummaryStat label="Case evidence count" value={declaredCount} />
        )}
      </div>

      <Panel
        className="case-evidence-tab__panel"
        title="Acquired sources"
        subtitle={`${sources.length} in hand · ${stats.verified} hash-verified · ${stats.hashed} digested`}
        flush
      >
        <div className="case-evidence-tab__table-wrap">
          <table className="case-evidence-tab__table">
            <thead>
              <tr>
                <th scope="col">Source</th>
                <th scope="col">Type</th>
                <th scope="col">Size</th>
                <th scope="col">Acquired</th>
                <th scope="col">Custodian</th>
                <th scope="col">Integrity</th>
                <th scope="col">State</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((source) => {
                const open = openId === source.id
                return (
                  <Fragment key={source.id}>
                    <tr
                      className={`ev-row${open ? ' ev-row--open' : ''}`}
                      onClick={() => setOpenId(open ? null : source.id)}
                      aria-expanded={open}
                    >
                      <td className="ev-row__source">
                        <span className="ev-row__icon">
                          <Icon name={KIND_ICON[source.kind] ?? 'file'} size={14} />
                        </span>
                        <span className="ev-row__label mono">{source.label ?? source.id ?? '—'}</span>
                      </td>
                      <td className="ev-row__type">{KIND_LABEL[source.kind] ?? source.kind ?? '—'}</td>
                      <td className="tabular">{source.size ?? '—'}</td>
                      <td className="tabular">{formatTimestamp(source.acquiredAt)}</td>
                      <td>{source.custodian ?? '—'}</td>
                      <td>
                        <span
                          className={`ev-row__integrity${
                            source.integrity === 'HASH MATCH' ? ' ev-row__integrity--ok' : ''
                          }`}
                        >
                          <Icon name="lock" size={11} />
                          {source.integrity ?? 'Unverified'}
                        </span>
                      </td>
                      <td>
                        <span className={`ev-row__state ev-row__state--${String(source.state ?? '').toLowerCase()}`}>
                          {STATE_LABEL[source.state] ?? source.state ?? '—'}
                        </span>
                      </td>
                    </tr>
                    {open && (
                      <tr className="ev-detail-row">
                        <td colSpan={7}>
                          <div className="ev-detail">
                            <div className="ev-detail__facts">
                              <DetailFact label="Source ID" value={source.id} mono />
                              <DetailFact label="Description" value={source.detail} />
                              <DetailFact label="Acquired" value={formatTimestamp(source.acquiredAt)} />
                              <DetailFact label="Custodian" value={source.custodian} mono />
                            </div>
                            <div className="ev-detail__hash">
                              <span className="eyebrow">SHA-256 (chain of custody)</span>
                              <code className="ev-detail__digest mono">
                                {source.sha256 ?? '—'}
                              </code>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      {pending.length > 0 && (
        <Panel
          className="case-evidence-tab__panel"
          title="Outstanding acquisitions"
          subtitle={`${pending.length} not yet in hand`}
          flush
        >
          <ul className="case-evidence-tab__pending">
            {pending.map((item) => (
              <li className="ev-pending" key={item.id}>
                <span className="ev-pending__mark" aria-hidden="true" />
                <div>
                  <p className="ev-pending__label">{item.label ?? item.id}</p>
                  {item.reason && <p className="ev-pending__reason">{item.reason}</p>}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}

function SummaryStat({ label, value, icon }) {
  return (
    <div className="case-evidence-tab__stat">
      <span className="case-evidence-tab__stat-value tabular">
        {icon && <Icon name={icon} size={13} />}
        {value}
      </span>
      <span className="case-evidence-tab__stat-label">{label}</span>
    </div>
  )
}

function DetailFact({ label, value, mono }) {
  return (
    <div className="ev-detail__fact">
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : undefined}>{value ?? '—'}</dd>
    </div>
  )
}
