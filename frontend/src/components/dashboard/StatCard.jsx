import Icon from '../ui/Icon.jsx'
import { formatCount } from '../../utils/format.js'
import './StatCard.css'

/**
 * Top-level dashboard metric.
 *
 * Deliberately plain: a number, its movement, and one line of composition. The
 * KPI strip is context for the case list below it, not the subject of the
 * screen, so it carries no chart, rail or tone fill.
 *
 * @param {{ metric: import('../../data/mockDashboard.js').DashboardMetric }} props
 */
export default function StatCard({ metric }) {
  return (
    <article className="stat-card">
      <span className="stat-card__label">{metric.label}</span>

      <div className="stat-card__figure">
        <span className="stat-card__value tabular">
          {formatCount(metric.value, metric.format)}
        </span>
        {metric.delta && (
          <span className={`stat-card__delta stat-card__delta--${metric.delta.direction}`}>
            <Icon name="arrowRight" size={11} strokeWidth={2} className="stat-card__delta-icon" />
            {metric.delta.value}
            <span className="stat-card__delta-period">{metric.delta.period}</span>
          </span>
        )}
      </div>

      <p className="stat-card__detail">{metric.detail}</p>
    </article>
  )
}
