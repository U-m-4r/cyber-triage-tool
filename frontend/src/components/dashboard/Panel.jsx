import './Panel.css'

/**
 * Section container used across the application shell.
 *
 * @param {object} props
 * @param {string} props.title
 * @param {string} [props.subtitle]
 * @param {React.ReactNode} [props.action]  Right-aligned header control.
 * @param {boolean} [props.flush]           Removes body padding (for lists/tables).
 */
export default function Panel({ title, subtitle, action, flush = false, className = '', children }) {
  return (
    <section className={`panel ${className}`.trim()}>
      <header className="panel__head">
        <div className="panel__titles">
          <h2 className="panel__title">{title}</h2>
          {subtitle && <p className="panel__subtitle">{subtitle}</p>}
        </div>
        {action && <div className="panel__action">{action}</div>}
      </header>
      <div className={`panel__body${flush ? ' panel__body--flush' : ''}`}>{children}</div>
    </section>
  )
}
