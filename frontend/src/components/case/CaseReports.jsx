import { useState, useEffect } from 'react'
import Icon from '../ui/Icon.jsx'
import { generateReport, listReports, getReportDownloadUrl } from '../../services/triageService.js'
import './CaseReports.css'

/**
 * Reports tab inside the case workspace.
 *
 * Allows the investigator to generate a PDF triage report for the current case
 * and lists any previously generated reports.
 */
export default function CaseReports({ caseRecord }) {
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(null)
  const [reports, setReports] = useState([])
  const [loadingHistory, setLoadingHistory] = useState(true)

  const caseId = caseRecord?.id

  // Load report history
  useEffect(() => {
    if (!caseId) return
    let cancelled = false
    setLoadingHistory(true)

    listReports(caseId)
      .then((data) => {
        if (!cancelled) {
          setReports(data?.reports ?? [])
        }
      })
      .catch(() => {
        if (!cancelled) setReports([])
      })
      .finally(() => {
        if (!cancelled) setLoadingHistory(false)
      })

    return () => { cancelled = true }
  }, [caseId])

  async function handleGenerate() {
    if (generating || !caseId) return
    setGenerating(true)
    setError(null)
    setSuccess(null)

    try {
      const blob = await generateReport(caseId)

      // Trigger download
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `CyberTriage_${caseId}_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      setSuccess('Report generated and downloaded successfully.')

      // Refresh report history
      listReports(caseId)
        .then((data) => setReports(data?.reports ?? []))
        .catch(() => {})
    } catch (err) {
      setError(err.message || 'Failed to generate report. Please try again.')
    } finally {
      setGenerating(false)
    }
  }

  function handleDirectDownload() {
    window.open(getReportDownloadUrl(caseId), '_blank')
  }

  return (
    <div className="case-reports">
      <section className="case-reports__generate" aria-labelledby="generate-heading">
        <h2 className="case-reports__heading" id="generate-heading">
          <Icon name="reports" size={18} />
          Generate Case Report
        </h2>
        <p className="case-reports__description">
          Generate a comprehensive PDF triage report for{' '}
          <span className="mono">{caseId}</span>. The report includes the case
          summary, threat assessment, priority findings, recommended actions,
          evidence status, and activity log.
        </p>

        <div className="case-reports__actions">
          <button
            className="case-reports__btn case-reports__btn--primary"
            onClick={handleGenerate}
            disabled={generating}
          >
            {generating ? (
              <>
                <span className="case-reports__spinner" />
                Generating…
              </>
            ) : (
              <>
                <Icon name="reports" size={14} />
                Generate PDF Report
              </>
            )}
          </button>

          <button
            className="case-reports__btn case-reports__btn--secondary"
            onClick={handleDirectDownload}
            disabled={generating}
          >
            <Icon name="arrowRight" size={14} />
            Quick Download
          </button>
        </div>

        {error && (
          <p className="case-reports__feedback case-reports__feedback--error" role="alert">
            {error}
          </p>
        )}
        {success && (
          <p className="case-reports__feedback case-reports__feedback--success" role="status">
            {success}
          </p>
        )}
      </section>

      <section className="case-reports__history" aria-labelledby="history-heading">
        <h2 className="case-reports__heading" id="history-heading">
          Report History
        </h2>

        {loadingHistory ? (
          <p className="case-reports__empty">Loading report history…</p>
        ) : reports.length === 0 ? (
          <p className="case-reports__empty">
            No reports generated yet. Click the button above to create your first
            report.
          </p>
        ) : (
          <table className="case-reports__table">
            <thead>
              <tr>
                <th>Generated</th>
                <th>Size</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report, idx) => (
                <tr key={idx}>
                  <td className="mono">
                    {new Date(report.generated_at).toLocaleString()}
                  </td>
                  <td>
                    {report.size_bytes
                      ? `${(report.size_bytes / 1024).toFixed(1)} KB`
                      : '—'}
                  </td>
                  <td>
                    <button
                      className="case-reports__download-btn"
                      onClick={handleDirectDownload}
                    >
                      <Icon name="arrowRight" size={12} />
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
