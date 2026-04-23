import { useState } from "react"
import { uploadFile } from "../services/api"
import UploadCard from "../components/UploadCard"
import ResultCard from "../components/ResultCard"
import ChartComponent from "../components/ChartComponent"

export default function Dashboard() {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleFileChange = (e) => {
    setFile(e.target.files[0])
    setResult(null)
    setError(null)
  }

  const handleUpload = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const data = await uploadFile(file)
      setResult(data)
    } catch {
      setError("Upload failed. Please try again.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative min-h-screen bg-slate-950 text-white overflow-x-hidden">
      {/* Ambient background blobs */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] rounded-full bg-cyan-500/10 blur-[120px]" />
        <div className="absolute top-1/2 -right-60 w-[500px] h-[500px] rounded-full bg-violet-600/10 blur-[120px]" />
        <div className="absolute -bottom-40 left-1/3 w-[400px] h-[400px] rounded-full bg-cyan-400/5 blur-[100px]" />
      </div>

      <div className="relative z-10 flex flex-col items-center px-4 py-16">
        {/* Header */}
        <div className="mb-12 text-center animate-fade-in-up">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium tracking-widest uppercase mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            Threat Intelligence
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold tracking-tight bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent">
            Cyber Triage
          </h1>
          <p className="mt-3 text-slate-400 text-sm max-w-sm mx-auto">
            Upload a file for instant threat analysis, risk scoring, and anomaly detection.
          </p>
        </div>

        {/* Upload card */}
        <div className="w-full max-w-lg animate-fade-in-up-delay">
          <UploadCard
            onFileChange={handleFileChange}
            onUpload={handleUpload}
            loading={loading}
            selectedFileName={file?.name ?? null}
          />
        </div>

        {/* Error banner */}
        {error && (
          <div className="mt-6 w-full max-w-lg animate-fade-in-up">
            <div className="glass rounded-xl px-4 py-3 border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center gap-2">
              <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              {error}
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="w-full max-w-2xl mt-10 flex flex-col gap-6">
            <div className="animate-fade-in-up">
              <ResultCard result={result} />
            </div>
            <div className="animate-fade-in-up-delay">
              <ChartComponent score={result.score} threatsDetected={result.threats_detected} />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
