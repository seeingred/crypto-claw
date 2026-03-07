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

function toSSHConfig(s) {
  return {
    host: s.host || '',
    port: parseInt(s.port, 10) || 22,
    user: s.username || '',
    password: s.password || '',
    keyPath: s.sshKeyPath || '',
  };
}

export async function saveServers(serverA, serverB, localMode) {
  return request('/servers/save', {
    method: 'POST',
    body: JSON.stringify({
      serverA: toSSHConfig(serverA),
      serverB: toSSHConfig(serverB),
      localMode,
    }),
  });
}

export async function installPrepare() {
  return request('/install/prepare', {
    method: 'POST',
  });
}

export async function installRestore(mnemonic) {
  return request('/install/restore', {
    method: 'POST',
    body: JSON.stringify({ mnemonic }),
  });
}

export async function startUpdate() {
  return request('/update', {
    method: 'POST',
  });
}

export async function saveLLMConfig(config) {
  return request('/llm/save', {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

export async function saveTelegramToken(token) {
  return request('/telegram/save', {
    method: 'POST',
    body: JSON.stringify({ botToken: token }),
  });
}

export async function verifyTelegram() {
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
  let connected = false;

  evtSource.onopen = () => {
    connected = true;
  };

  evtSource.onmessage = (event) => {
    connected = true;
    try {
      const data = JSON.parse(event.data);
      callback(data);
    } catch {
      callback({ type: 'log', message: event.data });
    }
  };

  evtSource.onerror = () => {
    // EventSource fires onerror on close after server sends its final event.
    // Only report an error if we never successfully connected.
    if (!connected) {
      callback({ type: 'error', message: 'Connection to log stream failed.' });
    }
    evtSource.close();
  };

  return () => evtSource.close();
}

export async function getState() {
  return request('/state', {
    method: 'GET',
  });
}
