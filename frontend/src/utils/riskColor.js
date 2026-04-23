export function getRiskColor(riskLevel) {
  const map = {
    High: "text-red-400",
    Medium: "text-yellow-400",
    Low: "text-green-400"
  }
  return map[riskLevel] ?? "text-gray-400"
}
