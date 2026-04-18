export default function UploadCard({ onFileChange, onUpload, loading, selectedFileName }) {
  return (
    <div className="glass rounded-2xl p-6 shadow-2xl shadow-black/40">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/20 flex items-center justify-center">
          <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
        </div>
        <div>
          <h2 className="text-sm font-semibold text-white">File Upload</h2>
          <p className="text-xs text-slate-500">Supports any file type</p>
        </div>
      </div>

      {/* Drop zone */}
      <label className="group relative flex flex-col items-center justify-center w-full h-36 rounded-xl border-2 border-dashed border-slate-700 hover:border-cyan-500/50 bg-slate-900/50 hover:bg-cyan-500/5 transition-all cursor-pointer">
        <input type="file" onChange={onFileChange} className="absolute inset-0 opacity-0 cursor-pointer" />
        <svg className="w-8 h-8 text-slate-600 group-hover:text-cyan-500 transition-colors mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <span className="text-sm text-slate-500 group-hover:text-slate-400 transition-colors">
          Drop file here or <span className="text-cyan-400">browse</span>
        </span>
      </label>

      {/* Selected file pill */}
      {selectedFileName && (
        <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700">
          <svg className="w-3.5 h-3.5 text-cyan-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <span className="text-xs text-slate-300 truncate">{selectedFileName}</span>
        </div>
      )}

      {/* Upload button */}
      <button
        onClick={onUpload}
        disabled={loading || !selectedFileName}
        className="cta-btn mt-4 w-full flex items-center justify-center gap-2.5 py-3 px-4 rounded-xl font-semibold text-sm text-white tracking-wide"
      >
        {/* Scan-line overlay — only while loading */}
        {loading && <span className="scan-line" />}

        {loading ? (
          <>
            {/* Radar / sonar icon */}
            <svg className="w-4 h-4 animate-spin shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m8.66-13l-.87.5M4.21 17.5l-.87.5M20.66 17.5l-.87-.5M4.21 6.5l-.87-.5M21 12h-1M4 12H3" />
            </svg>
            <span className="relative z-10">Scanning</span>
            <span className="dot-wave relative z-10 flex items-end gap-0.5 pb-0.5">
              <span /><span /><span />
            </span>
          </>
        ) : (
          <>
            {/* Shield-check icon */}
            <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Run Analysis
          </>
        )}
      </button>
    </div>
  )
}
