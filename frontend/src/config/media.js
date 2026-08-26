/**
 * Media configuration for the cinematic routes.
 *
 * `BACKGROUND_VIDEO_SRC` currently points at the asset referenced by
 * frontend/landingpage.md, which is hosted on a third-party CloudFront
 * distribution. Replace it with a self-hosted file (e.g. /media/triage-loop.mp4
 * placed in frontend/public) before any deployment — an external CDN we do not
 * control is not a dependency this page should carry.
 *
 * If the video fails to load, CinematicBackground falls back to a pure-CSS
 * gradient field, so the composition never renders on flat black.
 */

export const BACKGROUND_VIDEO_SRC =
  'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260808_064556_051587f1-74a1-4336-8c05-4dde3594ed05.mp4'

export const BACKGROUND_VIDEO_TYPE = 'video/mp4'
