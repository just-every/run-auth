// Line icons for the homepage drawings, stroked in currentColor.
const paths = {
  user: <><circle cx="12" cy="8" r="4" /><path d="M4.5 21c0-4.4 3.4-7 7.5-7s7.5 2.6 7.5 7" /></>,
  doc: <><path d="M7 3h7l4 4v14H7Z" /><path d="M14 3v4h4M10 11h5M10 15h5M10 18h3" /></>,
  chart: <><path d="M12 3a9 9 0 1 0 9 9h-9Z" /><path d="M15 3.5A9 9 0 0 1 20.5 9H15Z" /></>,
  file: <><path d="M7 3h7l4 4v14H7Z" /><path d="M14 3v4h4" /></>,
  refresh: <><path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v4.5h-4.5" /></>,
  list: <><rect x="5" y="3" width="14" height="18" rx="2" /><path d="M9 8h6M9 12h6M9 16h4" /></>,
  sliders: <><path d="M4 7h10M18 7h2M4 17h4M12 17h8" /><circle cx="16" cy="7" r="2" /><circle cx="10" cy="17" r="2" /></>,
  spark: <><path d="M12 3c.6 4.2 1.8 5.4 6 6-4.2.6-5.4 1.8-6 6-.6-4.2-1.8-5.4-6-6 4.2-.6 5.4-1.8 6-6ZM18.5 15.5c.3 1.6.8 2.1 2.5 2.5-1.7.4-2.2.9-2.5 2.5-.3-1.6-.8-2.1-2.5-2.5 1.7-.4 2.2-.9 2.5-2.5Z" /></>,
  swap: <><path d="M4 8h14l-3.5-3.5M20 16H6l3.5 3.5" /></>,
  arrow: <><path d="M4 12h15M14 6.5l5.5 5.5-5.5 5.5" /></>,
} as const

export type IconName = keyof typeof paths
export const Icon = ({ name, className }: { name: IconName; className?: string }) =>
  <svg className={className ?? 'icon'} viewBox="0 0 24 24" aria-hidden="true">{paths[name]}</svg>
