import { useMemo } from 'react'
import Panel from '../dashboard/Panel.jsx'
import Icon from '../ui/Icon.jsx'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import { formatPercent, formatTimestamp } from '../../utils/format.js'
import './PriorityFindings.css'

// Duplicated from AiTriagePanel rather than exported from it: the two panels
// happen to agree today, but the workspace will grow artifact types the compact
// dashboard list will not carry.
const ARTIFACT_ICON = {
  network: 'network',
  file: 'file',
  registry: 'registry',
  system_log: 'reports',
}

const SEVERITY_RANK = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
}

/**
 * Ranked findings for the case.
 *
 * Ordered by severity band first and risk score second, which is the order an
 * investigator works in — a CRITICAL finding is reviewed before a higher-scoring
 * HIGH one. Every row keeps its rationale and its source path, because a finding
 * an investigator cannot trace back to an artifact is not evidence.
 *
 * @param {object} props
 * @param {Array<object>} props.findings
 * @param {string} props.status  Used to explain an empty list honestly.
 */
export default function PriorityFindings({ findings, status }) {
  const ordered = useMemo(
    () =>
      [...findings].sort(
        (a, b) =>
          (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
          b.riskScore - a.riskScore,
      ),
    [findings],
  )

  const reviewed = ordered.filter((finding) => finding.reviewed).length

  return (
    <Panel
      className="case-findings"
      title="Priority Findings"
      subtitle={
        ordered.length
          ? `${ordered.length} findings ranked by severity, then risk score · ${reviewed} reviewed`
          : 'Nothing ranked yet'
      }
      flush={ordered.length > 0}
    >
      {ordered.length === 0 ? (
        <div className="case-findings__empty">
          <Icon name="triage" size={16} className="case-findings__empty-icon" />
          <p className="case-findings__empty-copy">
            No findings have been ranked for this case. Rule hits recorded during intake are counted
            in the case totals, but they are not ordered into findings until the {status.toLowerCase()}{' '}
            stage completes.
          </p>
        </div>
      ) : (
        <ul className="case-findings__list">
          {ordered.map((finding) => (
            <li className="case-finding" key={finding.id}>
              <span className="case-finding__icon">
                <Icon name={ARTIFACT_ICON[finding.artifactType] ?? 'shield'} size={14} />
              </span>

              <div className="case-finding__body">
                <div className="case-finding__title-line">
                  <span className="case-finding__id mono">{finding.id}</span>
                  <span className="case-finding__title">{finding.title}</span>
                  <SeverityBadge severity={finding.severity} size="sm" />
                  {finding.reviewed && (
                    <span className="case-finding__reviewed">Reviewed</span>
                  )}
                </div>

                <p className="case-finding__rationale">{finding.rationale}</p>

                <div className="case-finding__meta">
                  <span className="case-finding__source mono" title={finding.source}>
                    {finding.source}
                  </span>
                  <span className="case-finding__meta-item">
                    <Icon name="host" size={11} />
                    <span className="mono">{finding.host}</span>
                  </span>
                  <span className="case-finding__meta-item mono" title="MITRE ATT&CK technique">
                    {finding.technique.id} · {finding.technique.name}
                  </span>
                  <span className="case-finding__meta-item">
                    <Icon name="clock" size={11} />
                    {formatTimestamp(finding.observedAt)}
                  </span>
                </div>
              </div>

              <div className="case-finding__score">
                <span className="case-finding__score-label">Risk</span>
                <span className="case-finding__score-value tabular">{finding.riskScore}</span>
                <span className="case-finding__score-confidence tabular">
                  {formatPercent(finding.confidence)} conf.
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
