export const workspaceToken = () => sessionStorage.getItem('aegis-workspace-token') || '';

export function workspaceAuthHeaders() {
  const token = workspaceToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
