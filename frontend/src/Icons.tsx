import type { ReactNode } from "react";

// Line icons for the sidebar: 24×24 viewBox, drawn with currentColor so they
// follow the theme and the active state. No icon library needed.
const paths: Record<string, ReactNode> = {
  // CISO: overall posture — shield with a check.
  CISO: (
    <>
      <path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.3 7.5 9.5 4.4-1.2 7.5-4.9 7.5-9.5V6L12 3Z" />
      <path d="m8.8 12.2 2.2 2.2 4.3-4.6" />
    </>
  ),
  // Application security: a bug.
  AppSec: (
    <>
      <rect x="7.5" y="8" width="9" height="12" rx="4.5" />
      <path d="M12 12v8M9.5 8.3 8 5.5M14.5 8.3 16 5.5M4 12h3.5M16.5 12H20M4.5 18l3.2-1.6M19.5 18l-3.2-1.6M4.5 7l3.2 1.8M19.5 7l-3.2 1.8" />
    </>
  ),
  // Engineering: code.
  Engineering: (
    <>
      <path d="m8.5 7.5-4.5 4.5 4.5 4.5M15.5 7.5 20 12l-4.5 4.5M13.5 5l-3 14" />
    </>
  ),
  // Organization scorecard: a building.
  Organization: (
    <>
      <path d="M4 20.5h16M6 20.5V5.5A1.5 1.5 0 0 1 7.5 4h6A1.5 1.5 0 0 1 15 5.5v15M15 10h2.5A1.5 1.5 0 0 1 19 11.5v9" />
      <path d="M9 8h3M9 11.5h3M9 15h3" />
    </>
  ),
  // Metric explorer: magnifier over bars.
  Explorer: (
    <>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m15.5 15.5 5 5M8 12.5v-2M10.5 12.5v-4M13 12.5v-3" />
    </>
  ),
  // Metric dictionary: a book.
  Dictionary: (
    <>
      <path d="M5 5.5A2.5 2.5 0 0 1 7.5 3H19v15H7.5A2.5 2.5 0 0 0 5 20.5v-15Z" />
      <path d="M5 20.5A2.5 2.5 0 0 1 7.5 18H19v3H7.5M9 7.5h6M9 11h4" />
    </>
  ),
  // Generate report: document with a download arrow.
  Generate: (
    <>
      <path d="M14 3H7.5A1.5 1.5 0 0 0 6 4.5v15A1.5 1.5 0 0 0 7.5 21h9a1.5 1.5 0 0 0 1.5-1.5V7l-4-4Z" />
      <path d="M14 3v4h4M12 10.5v6M9.5 14l2.5 2.5 2.5-2.5" />
    </>
  ),
  // Report library: stacked documents.
  Reports: (
    <>
      <path d="M8 3h8.5L20 6.5V17a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" />
      <path d="M4 7v13a1 1 0 0 0 1 1h11M10.5 9h6M10.5 12.5h6" />
    </>
  ),
  // Report builder: layout blocks.
  Builder: (
    <>
      <rect x="3.5" y="3.5" width="17" height="17" rx="2" />
      <path d="M3.5 9h17M10 9v11.5" />
    </>
  ),
  // Data & metrics: a database.
  Data: (
    <>
      <ellipse cx="12" cy="6" rx="7" ry="2.8" />
      <path d="M5 6v6c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8V6M5 12v6c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8v-6" />
    </>
  ),
  // SLA policy: a clock.
  SLA: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
};

export function NavIcon({ name }: { name: string }) {
  return (
    <svg
      className="nav-svg"
      viewBox="0 0 24 24"
      width="20"
      height="20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}

/** The Snyk dog, coloured by CSS (the PNG is used as a mask). */
export function SnykMark({ className = "" }: { className?: string }) {
  return <span className={"snyk-mark " + className} role="img" aria-label="Snyk" />;
}
