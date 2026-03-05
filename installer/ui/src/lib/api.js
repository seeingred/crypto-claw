const API_BASE = '/api';

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const config = {
    headers: {
      'Content-Type': 'application/json',
    },
    ...options,
  };

  const response = await fetch(url, config);

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(
      `API error ${response.status}: ${errorBody || response.statusText}`
    );
  }

  const text = await response.text();
  if (!text) return {};
  return JSON.parse(text);
}

export async function testSSHConnection(config) {
  return request('/servers/test', {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

export async function saveServers(serverA, serverB, localMode) {
  return request('/servers', {
    method: 'POST',
    body: JSON.stringify({ serverA, serverB, localMode }),
  });
}

export async function runDKG() {
  return request('/dkg/run', {
    method: 'POST',
  });
}

export async function saveLLMConfig(config) {
  return request('/llm', {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

export async function saveTelegramToken(token) {
  return request('/telegram/token', {
    method: 'POST',
    body: JSON.stringify({ token }),
  });
}

export async function verifyTelegramUser() {
  return request('/telegram/verify', {
    method: 'POST',
  });
}

export async function startDeployment() {
  return request('/deploy', {
    method: 'POST',
  });
}

export function subscribeDeployLogs(callback) {
  const evtSource = new EventSource(`${API_BASE}/deploy/logs`);

  evtSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      callback(data);
    } catch {
      callback({ message: event.data });
    }
  };

  evtSource.onerror = () => {
    callback({ type: 'error', message: 'Connection to log stream lost.' });
    evtSource.close();
  };

  return () => evtSource.close();
}

export async function getState() {
  return request('/state', {
    method: 'GET',
  });
}
