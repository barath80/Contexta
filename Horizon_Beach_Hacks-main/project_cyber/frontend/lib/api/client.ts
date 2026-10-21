/**
 * HTTP client: bearer auth, single-flight token refresh, typed errors, SSE streaming.
 */

import { API_CONFIG } from './config';

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(message: string, status: number, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  query?: Query;
  skipAuth?: boolean;
  signal?: AbortSignal;
}

function buildUrl(endpoint: string, query?: Query): string {
  const url = `${API_CONFIG.baseUrl}${endpoint}`;
  if (!query) return url;
  const params = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') params.append(k, String(v));
  });
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

/** FastAPI errors: {detail: string} | {detail: {message}} | {detail, errors:[{field,message}]} */
function errorMessage(data: unknown, status: number): string {
  if (data && typeof data === 'object') {
    const d = data as { detail?: unknown; errors?: { field: string; message: string }[] };
    if (Array.isArray(d.errors) && d.errors.length) {
      return d.errors.map((e) => (e.field ? `${e.field}: ${e.message}` : e.message)).join('; ');
    }
    if (typeof d.detail === 'string') return d.detail;
    if (d.detail && typeof d.detail === 'object' && 'message' in d.detail) {
      return String((d.detail as { message: unknown }).message);
    }
  }
  if (status === 429) return 'Too many requests. Please wait a moment and try again.';
  if (status >= 500) return 'The server hit an unexpected error.';
  return `Request failed (HTTP ${status})`;
}

class ApiClient {
  private refreshing: Promise<boolean> | null = null;

  getToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(API_CONFIG.tokenKey);
  }

  private setTokens(access: string, refresh?: string): void {
    localStorage.setItem(API_CONFIG.tokenKey, access);
    if (refresh) localStorage.setItem(API_CONFIG.refreshTokenKey, refresh);
  }

  clearTokens(): void {
    if (typeof window === 'undefined') return;
    localStorage.removeItem(API_CONFIG.tokenKey);
    localStorage.removeItem(API_CONFIG.refreshTokenKey);
  }

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  /** One refresh at a time; concurrent 401s share the same attempt. */
  private refreshAccessToken(): Promise<boolean> {
    if (this.refreshing) return this.refreshing;
    this.refreshing = (async () => {
      const refresh = localStorage.getItem(API_CONFIG.refreshTokenKey);
      if (!refresh) return false;
      try {
        const res = await fetch(buildUrl('/auth/refresh'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refresh }),
        });
        if (!res.ok) return false;
        const data = await res.json();
        this.setTokens(data.access_token, data.refresh_token);
        return true;
      } catch {
        return false;
      }
    })().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private sessionExpired(): never {
    this.clearTokens();
    if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
      window.location.href = '/login';
    }
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }

  private async send(endpoint: string, opts: RequestOptions, extraHeaders: Record<string, string> = {}): Promise<Response> {
    const { method = 'GET', body, query, skipAuth = false, signal } = opts;
    const doFetch = () => {
      const headers: Record<string, string> = { ...extraHeaders };
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      const token = this.getToken();
      if (!skipAuth && token) headers['Authorization'] = `Bearer ${token}`;
      return fetch(buildUrl(endpoint, query), {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal,
      });
    };

    let res: Response;
    try {
      res = await doFetch();
    } catch (err) {
      if ((err as Error).name === 'AbortError') throw err;
      throw new ApiError('Cannot reach the Contexta API. Check your connection and that the backend is running.', 0, err);
    }
    if (res.status === 401 && !skipAuth) {
      if (!(await this.refreshAccessToken())) this.sessionExpired();
      res = await doFetch();
      if (res.status === 401) this.sessionExpired();
    }
    return res;
  }

  async request<T>(endpoint: string, opts: RequestOptions = {}): Promise<T> {
    const res = await this.send(endpoint, opts, { Accept: 'application/json' });
    const text = await res.text();
    let data: unknown = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
    if (!res.ok) throw new ApiError(errorMessage(data, res.status), res.status, data);
    return data as T;
  }

  get<T>(endpoint: string, query?: Query, signal?: AbortSignal) {
    return this.request<T>(endpoint, { method: 'GET', query, signal });
  }
  post<T>(endpoint: string, body?: unknown, query?: Query) {
    return this.request<T>(endpoint, { method: 'POST', body: body ?? {}, query });
  }
  put<T>(endpoint: string, body?: unknown) {
    return this.request<T>(endpoint, { method: 'PUT', body });
  }
  patch<T>(endpoint: string, body?: unknown) {
    return this.request<T>(endpoint, { method: 'PATCH', body });
  }
  delete<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }

  /** POST and consume a Server-Sent-Events response, invoking onEvent per `data:` frame. */
  async stream<E>(endpoint: string, body: unknown, onEvent: (event: E) => void, signal?: AbortSignal): Promise<void> {
    const res = await this.send(endpoint, { method: 'POST', body, signal }, { Accept: 'text/event-stream' });
    if (!res.ok) {
      const text = await res.text();
      let data: unknown = text;
      try {
        data = JSON.parse(text);
      } catch {
        /* keep text */
      }
      throw new ApiError(errorMessage(data, res.status), res.status, data);
    }
    if (!res.body) throw new ApiError('Streaming is not supported by this browser.', 0);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        const payload = frame
          .split('\n')
          .filter((l) => l.startsWith('data:'))
          .map((l) => l.slice(5).trim())
          .join('');
        if (payload) onEvent(JSON.parse(payload) as E);
      }
    }
  }

  async login(email: string, password: string): Promise<void> {
    const res = await fetch(buildUrl('/auth/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: email, password }).toString(),
    }).catch((err) => {
      throw new ApiError('Cannot reach the Contexta API. Check that the backend is running.', 0, err);
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new ApiError(errorMessage(data, res.status), res.status, data);
    this.setTokens(data.access_token, data.refresh_token);
  }

  async logout(): Promise<void> {
    try {
      if (this.isAuthenticated()) await this.request('/auth/logout', { method: 'POST', body: {} });
    } catch {
      /* the local session is cleared regardless */
    }
    this.clearTokens();
  }
}

export const apiClient = new ApiClient();
export default apiClient;
