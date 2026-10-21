/**
 * API configuration. The backend serves everything under /api/v1.
 */

const trim = (v: string) => v.replace(/\/+$/, '');

export const API_CONFIG = {
  baseUrl: trim(process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'),
  tokenKey: process.env.NEXT_PUBLIC_TOKEN_KEY || 'contexta_access_token',
  refreshTokenKey: process.env.NEXT_PUBLIC_REFRESH_TOKEN_KEY || 'contexta_refresh_token',
};
