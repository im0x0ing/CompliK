const AUTH_STORAGE_KEY = "complik-admin-basic";

export function getBasicAuthHeader() {
  const encoded = window.sessionStorage.getItem(AUTH_STORAGE_KEY);
  return encoded ? `Basic ${encoded}` : null;
}

export function hasBasicAuth() {
  return Boolean(window.sessionStorage.getItem(AUTH_STORAGE_KEY));
}

export function setBasicAuth(username: string, password: string) {
  window.sessionStorage.setItem(AUTH_STORAGE_KEY, window.btoa(`${username}:${password}`));
}

export function clearBasicAuth() {
  window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
}
