const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

// Obfuscated octets (e.g. 45.61.x.x) are kept, so a first-seen destination reads
// the same here as it does in the finding it came from.
const IP_RE = /\b(?:\d{1,3}|x)(?:\.(?:\d{1,3}|x)){3}(?::\d{1,5})?\b/g

function worseSeverity(a, b) {
  return (SEVERITY_RANK[a] ?? 9) <= (SEVERITY_RANK[b] ?? 9) ? a : b
}

/**
 * Derives IOC-like indicators from the case findings. Nothing is invented: an
 * indicator only exists because a ranked finding refers to it, and it inherits
 * the worst severity among the findings that do.
 */
export function deriveIndicators(findings) {
  const map = new Map()

  const push = (type, value, finding) => {
    if (!value) return
    const key = `${type}::${value}`
    const existing = map.get(key)
    if (existing) {
      existing.severity = worseSeverity(existing.severity, finding.severity ?? 'INFO')
      if (finding.host) existing.hosts.add(finding.host)
      existing.findingIds.add(finding.id)
    } else {
      map.set(key, {
        id: key,
        type,
        value,
        severity: finding.severity ?? 'INFO',
        hosts: new Set(finding.host ? [finding.host] : []),
        findingIds: new Set(finding.id ? [finding.id] : []),
      })
    }
  }

  for (const finding of findings) {
    if (finding.technique?.id) {
      push('technique', `${finding.technique.id} · ${finding.technique.name}`, finding)
    }

    const haystack = `${finding.source ?? ''} ${finding.rationale ?? ''}`
    const matches = haystack.match(IP_RE)
    if (matches) {
      for (const m of new Set(matches)) push('network', m, finding)
    }

    if (finding.artifactType === 'file' && finding.source) push('file', finding.source, finding)
    if (finding.artifactType === 'registry' && finding.source) push('registry', finding.source, finding)
  }

  return [...map.values()].map((ind) => ({
    ...ind,
    hosts: [...ind.hosts],
    findingIds: [...ind.findingIds],
  }))
}
