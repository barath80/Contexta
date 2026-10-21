'use client';

import { AlertTriangle, Inbox, Loader2, RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';

export const LEVEL_STYLES: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  info: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200',
  none: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
};

export const LEVEL_COLORS: Record<string, string> = {
  critical: '#DC2626',
  high: '#F59E0B',
  medium: '#3B82F6',
  low: '#94A3B8',
};

export function LevelBadge({ level, children }: { level: string; children?: ReactNode }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase ${LEVEL_STYLES[level] ?? LEVEL_STYLES.none}`}>
      {children ?? level}
    </span>
  );
}

export function Card({
  title,
  action,
  children,
  className = '',
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between mb-3 gap-2">
          {title && <h3 className="text-base font-semibold text-gray-900 dark:text-white">{title}</h3>}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-8 text-sm text-gray-500 dark:text-gray-300" role="status">
      <Loader2 className="w-4 h-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center" role="alert">
      <AlertTriangle className="w-6 h-6 text-critical" />
      <p className="text-sm text-gray-700 dark:text-gray-200 max-w-md">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
          <RefreshCw className="w-3 h-3" /> Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-8 text-center">
      <Inbox className="w-7 h-7 text-gray-400" />
      <p className="text-sm font-medium text-gray-700 dark:text-gray-100">{title}</p>
      {hint && <p className="text-xs text-gray-500 dark:text-gray-300 max-w-sm">{hint}</p>}
      {action}
    </div>
  );
}

/** Renders loading / error / empty / content for a query-backed block. */
export function Async<T>({
  q,
  empty,
  children,
}: {
  q: { data: T | null; loading: boolean; error: string | null; refetch: () => void };
  empty?: { when: (d: T) => boolean; title: string; hint?: string; action?: ReactNode };
  children: (data: T) => ReactNode;
}) {
  if (q.data === null) {
    if (q.error) return <ErrorState message={q.error} onRetry={q.refetch} />;
    return <Spinner />;
  }
  if (empty && empty.when(q.data)) return <EmptyState title={empty.title} hint={empty.hint} action={empty.action} />;
  return <>{children(q.data)}</>;
}

export function Button({
  children,
  onClick,
  disabled,
  variant = 'primary',
  type = 'button',
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: 'primary' | 'secondary' | 'danger';
  type?: 'button' | 'submit';
  title?: string;
}) {
  const styles = {
    primary: 'bg-primary text-white hover:bg-primary-dark',
    secondary: 'border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700',
    danger: 'bg-critical text-white hover:bg-red-700',
  }[variant];
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${styles}`}
    >
      {children}
    </button>
  );
}

export const inputClass =
  'w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary';

export function Modal({ title, onClose, children, wide }: { title: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" onClick={onClose}>
      <div
        className={`bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full ${wide ? 'max-w-4xl' : 'max-w-xl'} max-h-[90vh] flex flex-col`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="text-gray-500 hover:text-gray-900 dark:hover:text-white text-xl leading-none">
            ×
          </button>
        </div>
        <div className="p-5 overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------- formatting
function parseUtc(iso: string | null | undefined): number {
  if (!iso) return NaN;
  // Backend timestamps are UTC and may lack a zone suffix.
  return Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`);
}

export function timeAgo(iso: string | null | undefined): string {
  const ts = parseUtc(iso);
  if (Number.isNaN(ts)) return '—';
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function fmtDate(iso: string | null | undefined): string {
  const ts = parseUtc(iso);
  return Number.isNaN(ts) ? '—' : new Date(ts).toLocaleString();
}

/** INR lakhs -> "₹12.5 L" / "₹1.20 Cr". */
export function fmtLakhs(v: number | null | undefined): string {
  if (v === null || v === undefined) return '—';
  return v >= 100 ? `₹${(v / 100).toFixed(2)} Cr` : `₹${v.toFixed(1)} L`;
}

export const titleCase = (s: string) => s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
