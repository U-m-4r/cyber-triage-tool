import { useState } from 'react'
import { analyzeDataset } from '../../services/triageService.js'
import './CaseAnalysis.css'

export default function CaseAnalysis({ caseRecord, onAnalysisComplete }) {
  const [file, setFile] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState(null)
  const [results, setResults] = useState(null)

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setError(null)
    }
  }

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select a CSV dataset to analyze.')
      return
    }

    setIsAnalyzing(true)
    setError(null)

    try {
      // Analyze and save to case
      const res = await analyzeDataset(file, { data: { caseId: caseRecord.id } })
      setResults(res)
      if (onAnalysisComplete) {
        onAnalysisComplete() // Refresh the case data
      }
    } catch (err) {
      setError(err.message || 'Analysis failed')
    } finally {
      setIsAnalyzing(false)
    }
  }

  return (
    <div className="case-analysis">
      <div className="analysis-header">
        <h3>Machine Learning Anomaly Detection</h3>
        <p>
          Upload a network flow dataset (CSV) for this case. The ML pipeline will
          preprocess the data, isolate anomalies, and rank artifacts by risk score.
          Top findings will be automatically added to the case.
        </p>
      </div>

      <div className="analysis-upload-section">
        <div className="file-input-group">
          <input
            type="file"
            accept=".csv"
            id="dataset-upload"
            onChange={handleFileChange}
            disabled={isAnalyzing}
          />
          <label htmlFor="dataset-upload" className="file-label">
            {file ? file.name : 'Choose a CSV file'}
          </label>
        </div>

        <button
          className="run-analysis-btn"
          onClick={handleAnalyze}
          disabled={!file || isAnalyzing}
        >
          {isAnalyzing ? 'Running ML Pipeline...' : 'Run Analysis'}
        </button>

        {error && <div className="analysis-error">{error}</div>}
      </div>

      {isAnalyzing && (
        <div className="analysis-loading">
          <div className="spinner"></div>
          <p>Processing records and calculating anomaly scores...</p>
        </div>
      )}

      {results && !isAnalyzing && (
        <div className="analysis-results">
          <div className="results-summary">
            <h4>Analysis Complete</h4>
            <div className="summary-grid">
              <div className="metric">
                <span className="label">Total Records</span>
                <span className="value">{results.summary.total_records}</span>
              </div>
              <div className="metric critical">
                <span className="label">Critical Priority</span>
                <span className="value">{results.summary.critical}</span>
              </div>
              <div className="metric high">
                <span className="label">High Priority</span>
                <span className="value">{results.summary.high}</span>
              </div>
              <div className="metric medium">
                <span className="label">Medium Priority</span>
                <span className="value">{results.summary.medium}</span>
              </div>
            </div>
            <p className="findings-note">
              The top artifacts have been added to the Case Findings. Switch to the Overview or Reports tab to see them.
            </p>
          </div>

          <div className="results-table-container">
            <h4>Top {results.artifacts.length} Anomalous Artifacts</h4>
            <table className="results-table">
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>Risk Score</th>
                  <th>Source IP</th>
                  <th>Dest IP</th>
                  <th>Protocol</th>
                  <th>Anomaly Score</th>
                </tr>
              </thead>
              <tbody>
                {results.artifacts.map((artifact, index) => (
                  <tr key={index} className={`priority-${artifact.priority.toLowerCase()}`}>
                    <td className="priority-cell">{artifact.priority}</td>
                    <td>{artifact.risk_score}</td>
                    <td>{artifact.get?.('Source IP') || artifact['Source IP'] || 'N/A'}</td>
                    <td>{artifact.get?.('Destination IP') || artifact['Destination IP'] || 'N/A'}</td>
                    <td>{artifact.get?.('Protocol') || artifact['Protocol'] || 'N/A'}</td>
                    <td>{artifact.anomaly_score.toFixed(3)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
