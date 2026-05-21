const { Octokit } = require('@octokit/rest');
const axios = require('axios');
const crypto = require('crypto');
const net = require('net');
const { createMlKem768 } = require('mlkem');
const { SocksClient } = require('socks');
const { HttpsProxyAgent } = require('https-proxy-agent');

// Configuration
const GITHUB_TOKEN = process.env.SCANNER_GITHUB_TOKEN;
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM;
const MAIN_REPO = { owner: 'yourorg', repo: 'main-repo' };
const PROXY_LIST = [
  'socks5://user:pass@proxy1:1080',
  'socks5://user:pass@proxy2:1080',
  'http://user:pass@proxy3:3128',
];
const CONNECTION_TIMEOUT_MS = 45000;
const TTL_MS = 20 * 60 * 1000;
const POLL_INTERVAL_MS = 10000;

function decryptWithRSA(encryptedBuffer, privateKeyPem) {
  const keyLen = encryptedBuffer.readUInt16BE(0);
  const encryptedAesKey = encryptedBuffer.slice(2, 2 + keyLen);
  let offset = 2 + keyLen;
  const iv = encryptedBuffer.slice(offset, offset + 12); offset += 12;
  const authTag = encryptedBuffer.slice(offset, offset + 16); offset += 16;
  const ciphertext = encryptedBuffer.slice(offset);
  
  const aesKey = crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedAesKey
  );
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString());
}

async function fetchEncFile(octokit, branchName) {
  try {
    const { data: contents } = await octokit.rest.repos.getContent({
      ...MAIN_REPO,
      path: '',
      ref: branchName,
    });
    
    const encFile = Array.isArray(contents) ? contents.find(f => f.name.endsWith('.enc')) : null;
    if (!encFile) return null;
    
    const { data: fileData } = await axios.get(encFile.download_url, { responseType: 'arraybuffer' });
    return Buffer.from(fileData);
  } catch (err) {
    if (err.status !== 404) console.error('Fetch error:', err.message);
    return null;
  }
}

async function closePRAndDeleteBranch(octokit, prNumber, branchName) {
  try {
    await octokit.rest.pulls.update({ 
      ...MAIN_REPO, 
      pull_number: prNumber, 
      state: 'closed' 
    });
    await octokit.rest.git.deleteRef({ 
      ...MAIN_REPO, 
      ref: `heads/${branchName}` 
    });
    console.log(`Cleaned up PR #${prNumber} and branch ${branchName}`);
  } catch (err) {
    console.error('Cleanup error:', err.message);
  }
}

async function connectViaProxy(proxyUrl, targetHost, targetPort) {
  if (proxyUrl.startsWith('socks')) {
    const url = new URL(proxyUrl);
    const [username, password] = url.username ? [url.username, url.password] : [undefined, undefined];
    
    const { socket } = await SocksClient.createConnection({
      proxy: {
        host: url.hostname,
        port: parseInt(url.port),
        type: 5,
        userId: username,
        password: password,
      },
      command: 'connect',
      destination: { host: targetHost, port: targetPort },
      timeout: CONNECTION_TIMEOUT_MS,
    });
    
    return socket;
  } else if (proxyUrl.startsWith('http')) {
    const agent = new HttpsProxyAgent(proxyUrl);
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: targetHost, port: targetPort, agent });
      socket.once('connect', () => resolve(socket));
      socket.once('error', reject);
      setTimeout(() => reject(new Error('HTTP proxy connection timeout')), CONNECTION_TIMEOUT_MS);
    });
  } else {
    throw new Error(`Unsupported proxy type: ${proxyUrl}`);
  }
}

async function pqHandshakeClient(socket) {
  const kem = await createMlKem768();
  const [senderPublicKey, senderSecretKey] = kem.generateKeyPair();
  
  const userPublicKey = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout waiting for user public key')), 10000);
    socket.once('data', (data) => {
      clearTimeout(timeout);
      resolve(data);
    });
  });
  
  const { cipherText, sharedSecret } = kem.encaps(userPublicKey);
  socket.write(Buffer.from(cipherText));
  
  const sessionKey = crypto.createHash('sha256').update(sharedSecret).digest();
  
  console.log('Post-quantum handshake completed');
  
  // Create encrypted reader/writer (same as user side)
  let sequence = 0;
  const encrypt = (data) => {
    const iv = Buffer.alloc(12);
    iv.writeUInt32BE(sequence++);
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const packet = Buffer.concat([iv, authTag, encrypted]);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(packet.length);
    return Buffer.concat([length, packet]);
  };
  
  let buffer = Buffer.alloc(0);
  const decrypt = (chunk, callback) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4) {
      const packetLen = buffer.readUInt32BE(0);
      if (buffer.length >= 4 + packetLen) {
        const packet = buffer.slice(4, 4 + packetLen);
        const iv = packet.slice(0, 12);
        const authTag = packet.slice(12, 28);
        const ciphertext = packet.slice(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
        decipher.setAuthTag(authTag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        buffer = buffer.slice(4 + packetLen);
        callback(plaintext);
      } else {
        break;
      }
    }
  };
  
  return { encrypt, decrypt, socket, sessionKey };
}

async function connectToUser(ip, port, proxyUrl) {
  console.log(`Connecting to ${ip}:${port} via ${proxyUrl}`);
  const rawSocket = await connectViaProxy(proxyUrl, ip, port);
  const { encrypt, decrypt, socket } = await pqHandshakeClient(rawSocket);
  
  // Send ping to verify channel works
  const pingMsg = JSON.stringify({ type: 'ping', ts: Date.now() });
  socket.write(encrypt(Buffer.from(pingMsg)));
  
  let pongReceived = false;
  const pongPromise = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('No pong response')), 5000);
    const handler = (chunk) => {
      decrypt(chunk, (plaintext) => {
        const msg = JSON.parse(plaintext.toString());
        if (msg.type === 'pong') {
          clearTimeout(timeout);
          pongReceived = true;
          socket.removeListener('data', handler);
          resolve();
        }
      });
    };
    socket.on('data', handler);
  });
  
  await pongPromise;
  console.log('Channel verified, connection established');
  
  return { encrypt, decrypt, socket };
}

async function processPullRequest(octokit, pr) {
  const branch = pr.head.ref;
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  
  if (!uuidPattern.test(branch)) {
    console.log(`Skipping non-UUID branch: ${branch}`);
    return false;
  }
  
  console.log(`Processing PR #${pr.number} branch ${branch}`);
  
  const encBuffer = await fetchEncFile(octokit, branch);
  if (!encBuffer) {
    console.log(`No .enc file found in branch ${branch}`);
    await closePRAndDeleteBranch(octokit, pr.number, branch);
    return false;
  }
  
  let payload;
  try {
    payload = decryptWithRSA(encBuffer, PRIVATE_KEY_PEM);
  } catch (err) {
    console.error(`Decryption failed for PR #${pr.number}:`, err.message);
    await closePRAndDeleteBranch(octokit, pr.number, branch);
    return false;
  }
  
  const { ip, timestamp, uuid, metadata } = payload;
  console.log(`Decrypted payload: ${ip}, UUID: ${uuid}, Age: ${Math.round((Date.now() - timestamp) / 1000)}s`);
  
  if (Date.now() - timestamp > TTL_MS) {
    console.log(`UUID expired (${Math.round((Date.now() - timestamp) / 1000)}s old), closing`);
    await closePRAndDeleteBranch(octokit, pr.number, branch);
    return false;
  }
  
  // Shuffle proxies for rotation
  const shuffledProxies = [...PROXY_LIST];
  for (let i = shuffledProxies.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffledProxies[i], shuffledProxies[j]] = [shuffledProxies[j], shuffledProxies[i]];
  }
  
  let connected = false;
  for (const proxyUrl of shuffledProxies) {
    try {
      const { encrypt, decrypt, socket } = await connectToUser(ip, 44333, proxyUrl);
      
      console.log(`✓ Successfully connected to ${ip} via ${proxyUrl}`);
      await closePRAndDeleteBranch(octokit, pr.number, branch);
      connected = true;
      
      // Keep connection alive and monitor health
      let lastPing = Date.now();
      const healthInterval = setInterval(() => {
        if (Date.now() - lastPing > 60000) {
          console.log('Health check failed, closing connection');
          socket.destroy();
          clearInterval(healthInterval);
        }
      }, 15000);
      
      const pingInterval = setInterval(() => {
        if (!socket.destroyed) {
          const pingMsg = JSON.stringify({ type: 'ping', ts: Date.now() });
          socket.write(encrypt(Buffer.from(pingMsg)));
        }
      }, 30000);
      
      socket.on('data', (chunk) => {
        decrypt(chunk, (plaintext) => {
          const msg = JSON.parse(plaintext.toString());
          if (msg.type === 'pong') {
            lastPing = Date.now();
          } else {
            console.log('Received from user:', msg);
          }
        });
      });
      
      socket.on('close', () => {
        console.log(`Connection to ${ip} closed`);
        clearInterval(healthInterval);
        clearInterval(pingInterval);
      });
      
      break;
      
    } catch (err) {
      console.error(`Failed via ${proxyUrl}:`, err.message);
      continue;
    }
  }
  
  if (!connected) {
    console.log(`All proxies failed for ${ip}, closing PR`);
    await closePRAndDeleteBranch(octokit, pr.number, branch);
  }
  
  return connected;
}

async function main() {
  if (!GITHUB_TOKEN) {
    console.error('SCANNER_GITHUB_TOKEN environment variable not set');
    process.exit(1);
  }
  
  if (!PRIVATE_KEY_PEM) {
    console.error('PRIVATE_KEY_PEM environment variable not set');
    process.exit(1);
  }
  
  const octokit = new Octokit({ auth: GITHUB_TOKEN });
  console.log('Scanner started, polling every', POLL_INTERVAL_MS / 1000, 'seconds');
  console.log('Watching repo:', `${MAIN_REPO.owner}/${MAIN_REPO.repo}`);
  
  while (true) {
    try {
      const { data: pulls } = await octokit.rest.pulls.list({
        ...MAIN_REPO,
        state: 'open',
        sort: 'created',
        direction: 'desc'
      });
      
      console.log(`Found ${pulls.length} open pull requests`);
      
      for (const pr of pulls) {
        await processPullRequest(octokit, pr);
      }
      
    } catch (err) {
      console.error('Scanner error:', err.message);
    }
    
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down scanner...');
  process.exit(0);
});

main().catch(console.error);
