import { useEffect, useRef, useState } from 'react'

import { BACKGROUND_VIDEO_SRC, BACKGROUND_VIDEO_TYPE } from '../../config/media.js'
import './CinematicBackground.css'

/**
 * Full-bleed background for the landing and login routes.
 *
 * Layers, back to front:
 *   -4  CSS gradient field (always painted; the only visible layer if the video
 *       never loads)
 *   -3  looping muted video
 *   -2  vignette
 *   -1  optional dim scrim, used by the login route to subdue the composition
 *
 * @param {{ dim?: boolean }} props `dim` darkens the field for form-focused routes.
 */
export default function CinematicBackground({ dim = false }) {
  const [videoFailed, setVideoFailed] = useState(false)
  const videoRef = useRef(null)

  // The dimmed variant also slows the loop. Same footage as the landing route,
  // just less movement behind a form the investigator has to read.
  useEffect(() => {
    if (videoRef.current) videoRef.current.playbackRate = dim ? 0.55 : 1
  }, [dim, videoFailed])

  return (
    <>
      <div className="cinematic-field" aria-hidden="true" />
      {!videoFailed && (
        <video
          ref={videoRef}
          className="cinematic-video"
          autoPlay
          muted
          loop
          playsInline
          disablePictureInPicture
          preload="auto"
          aria-hidden="true"
          onError={() => setVideoFailed(true)}
        >
          <source src={BACKGROUND_VIDEO_SRC} type={BACKGROUND_VIDEO_TYPE} />
        </video>
      )}
      <div className="cinematic-vignette" aria-hidden="true" />
      {dim && <div className="cinematic-scrim" aria-hidden="true" />}
    </>
  )
}
