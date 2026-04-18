# Implementation Plan: Cyber Triage Dashboard

## Overview

Implement a Vite + React single-page dashboard with Tailwind CSS dark theme, file upload with mock fallback, structured result display, and Recharts visualization. Tasks build incrementally from dependency setup through component creation to final wiring.

## Tasks

- [x] 1. Install dependencies and configure Tailwind CSS
  - Run `npm install recharts` and `npm install @tailwindcss/vite tailwindcss` inside `frontend/`
  - Update `frontend/vite.config.js` to add the `tailwindcss()` plugin from `@tailwindcss/vite`
  - Replace contents of `frontend/src/index.css` with `@import "tailwindcss";`
  - _Requirements: Tailwind & Dependency Setup (design.md)_

- [x] 2. Implement the `uploadFile` API service
  - [x] 2.1 Rewrite `frontend/src/services/api.js` with the `uploadFile(file)` function and `mockUploadResponse()` fallback
    - Create an axios instance with `baseURL: "http://localhost:5000"`
    - Implement `uploadFile`: POST to `/upload` with FormData; on any error resolve with mock data after ~1500 ms
    - Export `uploadFile` as a named export
    - _Requirements: 1.1, 1.2 (uploadFile spec in design.md)_

  - [ ]* 2.2 Write property test: `uploadFile` never rejects
    - **Property: For all `uploadFile(f)` calls the function must never throw — it always resolves (real response or mock fallback)**
    - **Validates: design.md Correctness Properties §2**
    - Use Vitest + `@fast-check/vitest`; mock axios to throw a network error and assert the returned promise resolves to a valid `AnalysisResult` shape

  - [ ]* 2.3 Write property test: mock fallback shape is valid
    - **Property: When backend returns a non-2xx response, `uploadFile` must resolve with mock data, not reject**
    - **Validates: design.md Correctness Properties §6**
    - Assert resolved value has `risk_level`, `threats_detected`, `suspicious_files`, `score` fields with correct types

- [x] 3. Implement `UploadCard` component
  - Create `frontend/src/components/UploadCard.jsx`
  - Render a file `<input>` wired to `onFileChange`, display `selectedFileName` when set, and an Upload `<button>` that calls `onUpload` and shows a spinner when `loading` is true
  - Apply Tailwind dark-theme classes (bg-gray-800, text-white, etc.)
  - _Requirements: 2.1, 2.2 (UploadCard props spec in design.md)_

- [x] 4. Implement `getRiskColor` utility and `ResultCard` component
  - [x] 4.1 Create `frontend/src/utils/riskColor.js` exporting `getRiskColor(riskLevel)`
    - Map `"High"` → `"text-red-400"`, `"Medium"` → `"text-yellow-400"`, `"Low"` → `"text-green-400"`, fallback → `"text-gray-400"`
    - _Requirements: 3.1 (getRiskColor spec in design.md)_

  - [ ]* 4.2 Write property test: `getRiskColor` always returns a non-empty string
    - **Property: For all `result` values, `getRiskColor(result.risk_level)` must return a non-empty Tailwind class string**
    - **Validates: design.md Correctness Properties §3**
    - Use fast-check to generate arbitrary strings and assert the return value is a non-empty string starting with `"text-"`

  - [x] 4.3 Create `frontend/src/components/ResultCard.jsx`
    - Accept `result` prop (AnalysisResult shape)
    - Display risk level badge using `getRiskColor`, score, `threats_detected` count, and `suspicious_files` list
    - Apply Tailwind dark-theme card styles
    - _Requirements: 3.1, 3.2 (ResultCard spec in design.md)_

- [x] 5. Implement `ChartComponent`
  - Create `frontend/src/components/ChartComponent.jsx`
  - Accept `score` (0–100) and `threatsDetected` props
  - Render a Recharts `BarChart` with two bars: "Risk Score" and "Threats Detected"
  - _Requirements: 4.1 (ChartComponent spec in design.md)_

  - [ ]* 5.1 Write property test: chart renders bar proportional to score
    - **Property: For all `score` values `s` where `0 <= s <= 100`, `ChartComponent` must render a bar with height proportional to `s`**
    - **Validates: design.md Correctness Properties §4**
    - Use fast-check to generate integers in [0, 100]; render with `@testing-library/react` and assert the data passed to the chart contains the generated score value

- [x] 6. Implement `Dashboard` page and wire all components
  - [x] 6.1 Rewrite `frontend/src/pages/dashboard.jsx` as a full React component
    - Add `useState` for `file`, `loading`, `result`, `error`
    - Implement `handleFileChange`: set `file` state, reset `result` and `error` to null
    - Implement `handleUpload`: guard on `file === null` (return early without setting `loading`), set `loading = true`, call `uploadFile(file)`, set `result` on success or `error` on failure, always set `loading = false` in `finally`
    - Render page title, `UploadCard`, optional error banner, and conditionally `ResultCard` + `ChartComponent` when `result` is set
    - _Requirements: 1.1, 1.2, 2.1, 2.2, 3.1, 3.2, 4.1 (Dashboard spec in design.md)_

  - [ ]* 6.2 Write property test: `handleUpload` loading lifecycle
    - **Property: For all file inputs `f` where `f !== null`, `handleUpload()` must set `loading = true` before awaiting and `loading = false` after resolution**
    - **Validates: design.md Correctness Properties §1**
    - Mock `uploadFile` to return a controlled promise; assert `loading` transitions correctly

  - [ ]* 6.3 Write property test: `handleUpload` early-return when file is null
    - **Property: When `file === null`, `handleUpload()` must return early without setting `loading = true`**
    - **Validates: design.md Correctness Properties §5**
    - Render Dashboard with no file selected, call `handleUpload`, assert `loading` remains false

- [x] 7. Update `App.jsx`
  - Ensure `frontend/src/App.jsx` imports `Dashboard` from `"./pages/dashboard"` (lowercase filename) and renders it
  - Remove any leftover boilerplate styles from `App.css` that conflict with Tailwind
  - _Requirements: Component structure (design.md)_

- [x] 8. Final checkpoint — Ensure all tests pass
  - Run `npm run test -- --run` inside `frontend/` and confirm all property and unit tests pass
  - Verify the dev server starts without errors (`npm run dev`)
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references the relevant section of `design.md` for traceability
- Checkpoints ensure incremental validation before moving to the next phase
- Property tests use Vitest + `@fast-check/vitest`; install with `npm install -D vitest @fast-check/vitest @testing-library/react @testing-library/jest-dom jsdom` if not already present
