/**
 * Cyber Triage mark.
 *
 * Follows the reference's 25x25 clipped-disc construction (light ground, angular
 * shards) but the geometry is our own: an aperture split into examination
 * quadrants, with one accent shard to carry the brand colour.
 */
export default function BrandMark({ size = 25, className }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 25 25"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <clipPath id="ct-disc">
          <circle cx="12.5" cy="12.5" r="12.5" />
        </clipPath>
      </defs>
      <g clipPath="url(#ct-disc)">
        <rect width="25" height="25" fill="#ededed" />
        {/* upper-left shard */}
        <path d="M0 0h12.5L6.4 11.2 0 8.6Z" fill="#0a0b0b" />
        {/* right sweep */}
        <path d="M12.5 0H25v9.8l-8.9 3.1Z" fill="#050606" />
        {/* accent shard */}
        <path d="M25 9.8V25h-8.2l-.7-12.1Z" fill="#46b5c4" />
        {/* lower-left counterform */}
        <path d="M0 8.6l6.4 2.6L4.1 25H0Z" fill="#737778" />
        {/* central aperture */}
        <path d="M6.4 11.2l9.7 1.7.7 12.1H4.1Z" fill="#fafafa" />
        <circle cx="12.5" cy="12.5" r="2.4" fill="#050606" />
      </g>
    </svg>
  )
}
