import axios from "axios"

const API = axios.create({ baseURL: "http://localhost:5000" })

export function mockUploadResponse() {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        risk_level: "High",
        threats_detected: 3,
        suspicious_files: ["malware.exe", "trojan.dll"],
        score: 87
      })
    }, 1500)
  })
}

export async function uploadFile(file) {
  const formData = new FormData()
  formData.append("file", file)

  try {
    const response = await API.post("/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" }
    })
    return response.data
  } catch (error) {
    return await mockUploadResponse()
  }
}
