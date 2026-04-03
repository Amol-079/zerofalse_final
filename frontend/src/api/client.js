/**
 * Axios API client — single source of truth.
 * Token getter set once here. No duplicate setters in App.js or AuthContext.
 */
import axios from 'axios';

const client = axios.create({
  baseURL: process.env.REACT_APP_API_URL || '',
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
});

let _getToken = null;
let _navigate = null;

export const setClerkTokenGetter = (fn) => { _getToken = fn; };
export const setNavigateFn = (fn) => { _navigate = fn; };
export const getNavigateFn = () => _navigate;

client.interceptors.request.use(async (config) => {
  if (_getToken) {
    try {
      const token = await _getToken();
      if (token) config.headers.Authorization = `Bearer ${token}`;
    } catch { /* not signed in */ }
  }
  return config;
});

client.interceptors.response.use(
  (r) => r,
  (e) => Promise.reject(e),
);

export default client;
