import Panel from '../dashboard/Panel.jsx'
import Icon from '../ui/Icon.jsx'
import { formatTimestamp } from '../../utils/format.js'
import './EvidenceStatus.css'

const KIND_ICON = {
  image: 'evidence',
  log: 'reports',
  registry: 'registry',
  capture: 'network',
}

const STATE_LABEL = {
  PARSED: 'Parsed',
  INDEXING: 'Indexing',
  QUEUED: 'Queued',
}

/**
 * Chain-of-custody view of what has been acquired for the case.
 *
 * Each source carries its hash, custodian and acquisition time, because in a
 * forensic context "we have the disk" is not a fact until it is traceable to who
 * took it and to a digest that still matches. Processing state is deliberately
 * neutral in colour — an unparsed source is not a severity.
 *
 * Outstanding acquisitions are listed separately so they never read as evidence
 * already in hand.
 *
 * @param {{ evidence: { sources: Array<object>, pending: Array<object> } }} props
 */
export default function EvidenceStatus({ evidence }) {
  const { sources, pending } = evidence
  const parsed = sources.filter((source) => source.state === 'PARSED').length
  const verified = sources.filter((source) => source.integrity === 'HASH MATCH').length

  return (
    <Panel
      className="case-evidence"
      title="Evidence Status"
      subtitle={`${sources.length} acquired · ${parsed} parsed · ${verified} hash-verified · ${pending.length} outstanding`}
      flush
    >
      <ul className="case-evidence__list">
        {sources.map((source) => (
          <li className="ev-source" key={source.id}>
            <span className="ev-source__icon">
              <Icon name={KIND_ICON[source.kind] ?? 'file'} size={14} />
            </span>

            <div className="ev-source__identity">
              <div className="ev-source__label-line">
                <span className="ev-source__label mono">{source.label}</span>
                <span className={`ev-source__state ev-source__state--${source.state.toLowerCase()}`}>
                  {STATE_LABEL[source.state] ?? source.state}
                </span>
              </div>
              <p className="ev-source__detail">
                {source.detail} · {source.size}
              </p>
            </div>

            <div className="ev-source__custody">
              <span className="ev-source__custody-item">
                <Icon name="clock" size={11} />
                {formatTimestamp(source.acquiredAt)}
              </span>
              <span className="ev-source__custody-item">
                <Icon name="fingerprint" size={11} />
                {source.custodian}
              </span>
            </div>

            <div className="ev-source__integrity">
              <span className="ev-source__integrity-state">
                <Icon name="lock" size={11} />
                {source.integrity}
              </span>
              {/* Truncated for scanning; the full digest is on the title so it
                  can still be read and copied without a detail view. */}
              <span className="ev-source__hash mono" title={`SHA-256 ${source.sha256}`}>
                {source.sha256.slice(0, 16)}…
              </span>
            </div>
          </li>
        ))}
      </ul>

      {pending.length > 0 && (
        <section className="case-evidence__pending">
          <h3 className="eyebrow">Outstanding acquisitions</h3>
          <ul className="case-evidence__pending-list">
            {pending.map((item) => (
              <li className="ev-pending" key={item.id}>
                <span className="ev-pending__mark" aria-hidden="true" />
                <div>
                  <p className="ev-pending__label">{item.label}</p>
                  <p className="ev-pending__reason">{item.reason}</p>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
    </Panel>
  )
}
