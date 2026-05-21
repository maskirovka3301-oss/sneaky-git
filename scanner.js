const { Octokit } = require('@octokit/rest');
const axios = require('axios');
const crypto = require('crypto');
const net = require('net');
const fs = require('fs').promises;
const { createMlKem768 } = require('mlkem');
const { SocksClient } = require('socks');
const { HttpsProxyAgent } = require('https-proxy-agent');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Configuration
let CONFIG;
let dynamicProxies = new Map(); // Store dynamic proxy instances: port -> { process, expiry, clientIp }

async function loadConfig() {
  try {
    const configPath = path.join(__dirname, 'config.json');
    const configData = await fs.readFile(configPath, 'utf8');
    CONFIG = JSON.parse(configData);
    console.log('✅ Configuration loaded from config.json');
    
    // Validate residential proxy provider config
    if (CONFIG.residentialProxyProvider.enabled) {
      console.log(`📡 Residential Proxy Provider: ${CONFIG.residentialProxyProvider.name}`);
      
      // Check for required config fields based on provider
      const provider = CONFIG.residentialProxyProvider.name.toLowerCase();
      const providerConfig = CONFIG.residentialProxyProvider.config;
      
      switch(provider) {
        case 'oxylabs':
          if (!providerConfig.username || !providerConfig.password) {
            console.warn('⚠️  Oxylabs: username/password not configured');
          }
          break;
        case 'brightdata':
        case 'luminati':
          if (!providerConfig.apiKey) {
            console.warn('⚠️  BrightData: API key not configured');
          }
          break;
        case 'smartproxy':
          if (!providerConfig.username || !providerConfig.password) {
            console.warn('⚠️  Smartproxy: username/password not configured');
          }
          break;
        case 'geosurf':
          if (!providerConfig.username || !providerConfig.password) {
            console.warn('⚠️  GeoSurf: username/password not configured');
          }
          break;
        case 'netnut':
          if (!providerConfig.apiKey) {
            console.warn('⚠️  NetNut: API key not configured');
          }
          break;
        case 'custom':
          console.log('📝 Using custom residential proxy provider');
          break;
        default:
          console.warn(`⚠️  Unknown provider: ${provider}, using generic configuration`);
      }
    }
    
  } catch (err) {
    console.error('❌ Failed to load config.json:', err.message);
    process.exit(1);
  }
}

async function loadPrivateKey() {
  try {
    const privateKey = await fs.readFile(CONFIG.encryption.privateKeyPath, 'utf8');
    return privateKey;
  } catch (err) {
    console.error('❌ Failed to load private key:', err.message);
    process.exit(1);
  }
}

function decryptWithRSA(encryptedBuffer, privateKeyPem) {
  const keyLen = encryptedBuffer.readUInt16BE(0);
  const encryptedAesKey = encryptedBuffer.slice(2, 2 + keyLen);
  let offset = 2 + keyLen;
  const iv = encryptedBuffer.slice(offset, offset + CONFIG.encryption.ivLength); 
  offset += CONFIG.encryption.ivLength;
  const authTag = encryptedBuffer.slice(offset, offset + 16); 
  offset += 16;
  const ciphertext = encryptedBuffer.slice(offset);
  
  const padding = crypto.constants[CONFIG.encryption.rsaPadding];
  const aesKey = crypto.privateDecrypt(
    { key: privateKeyPem, padding: padding },
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
      owner: CONFIG.github.owner,
      repo: CONFIG.github.repo,
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
    if (CONFIG.cleanup.closePRAfterConnection) {
      await octokit.rest.pulls.update({ 
        owner: CONFIG.github.owner,
        repo: CONFIG.github.repo,
        pull_number: prNumber, 
        state: 'closed' 
      });
      console.log(`✅ Closed PR #${prNumber}`);
    }
    
    if (CONFIG.cleanup.deleteBranchAfterConnection) {
      await octokit.rest.git.deleteRef({ 
        owner: CONFIG.github.owner,
        repo: CONFIG.github.repo,
        ref: `heads/${branchName}` 
      });
      console.log(`✅ Deleted branch ${branchName}`);
    }
  } catch (err) {
    console.error('Cleanup error:', err.message);
  }
}

async function instantiateDynamicProxy(clientIp, targetPort, clientMetadata = {}) {
  if (!CONFIG.proxies.dynamic.enabled || !CONFIG.residentialProxyProvider.enabled) {
    return null;
  }

  // Find an available port in the configured range
  let proxyPort = null;
  for (let port = CONFIG.proxies.dynamic.portRange.start; port <= CONFIG.proxies.dynamic.portRange.end; port++) {
    if (!dynamicProxies.has(port)) {
      proxyPort = port;
      break;
    }
  }
  
  if (!proxyPort) {
    throw new Error('No available ports in configured range');
  }
  
  // Build the shell command with replacements
  let command = CONFIG.proxies.dynamic.shellCommand;
  let args = [...CONFIG.proxies.dynamic.arguments];
  
  // Prepare provider-specific replacements
  const provider = CONFIG.residentialProxyProvider;
  const providerConfig = provider.config;
  
  // Generate session ID if needed
  let sessionId = providerConfig.sessionId;
  if (sessionId === 'random') {
    sessionId = crypto.randomBytes(16).toString('hex');
  }
  
  const replacements = {
    // Provider information
    '{PROVIDER_NAME}': provider.name,
    '{PROVIDER_API_KEY}': providerConfig.apiKey || '',
    '{PROVIDER_API_SECRET}': providerConfig.apiSecret || '',
    '{PROVIDER_USERNAME}': providerConfig.username || '',
    '{PROVIDER_PASSWORD}': providerConfig.password || '',
    '{PROVIDER_COUNTRY}': providerConfig.country || 'US',
    '{PROVIDER_SESSION_ID}': sessionId,
    '{PROVIDER_STICKY}': providerConfig.stickySession ? 'true' : 'false',
    
    // Client information
    '{CLIENT_IP}': clientIp,
    '{TARGET_PORT}': targetPort.toString(),
    '{PROXY_PORT}': proxyPort.toString(),
    
    // Metadata
    '{TIMESTAMP}': Date.now().toString(),
    '{CLIENT_HOSTNAME}': clientMetadata.hostname || 'unknown',
    '{CLIENT_PLATFORM}': clientMetadata.platform || 'unknown'
  };
  
  // Replace placeholders in command
  command = command.replace(/{[^}]+}/g, (match) => replacements[match] || match);
  args = args.map(arg => arg.replace(/{[^}]+}/g, (match) => replacements[match] || match));
  
  const fullCommand = `${command} ${args.join(' ')}`;
  console.log(`🚀 Instantiating ${provider.name} proxy on port ${proxyPort}`);
  console.log(`   Command: ${fullCommand.substring(0, 150)}...`);
  
  let retries = 0;
  while (retries < CONFIG.proxies.dynamic.maxRetries) {
    try {
      // Execute the shell command
      const { stdout, stderr } = await execPromise(fullCommand, { timeout: 15000 });
      
      if (stderr) {
        console.warn(`Proxy instantiation warnings: ${stderr.substring(0, 200)}`);
      }
      
      console.log(`✅ ${provider.name} proxy started on port ${proxyPort}`);
      if (stdout) {
        console.log(`   Output: ${stdout.substring(0, 200)}`);
      }
      
      // Wait for proxy to be ready
      await waitForProxyReady(proxyPort);
      
      // Store proxy info for cleanup
      dynamicProxies.set(proxyPort, {
        clientIp,
        targetPort,
        startTime: Date.now(),
        command: fullCommand,
        provider: provider.name,
        sessionId: sessionId
      });
      
      return { proxyPort, type: 'dynamic', provider: provider.name };
      
    } catch (err) {
      retries++;
      console.error(`❌ Failed to instantiate proxy (attempt ${retries}/${CONFIG.proxies.dynamic.maxRetries}):`, err.message);
      
      if (retries < CONFIG.proxies.dynamic.maxRetries) {
        console.log(`Retrying in ${CONFIG.proxies.dynamic.retryDelayMs}ms...`);
        await new Promise(resolve => setTimeout(resolve, CONFIG.proxies.dynamic.retryDelayMs));
      }
    }
  }
  
  throw new Error(`Failed to instantiate ${provider.name} proxy after ${CONFIG.proxies.dynamic.maxRetries} attempts`);
}

async function waitForProxyReady(proxyPort, maxAttempts = 10) {
  const healthEndpoint = CONFIG.proxies.dynamic.healthCheckEndpoint;
  
  for (let i = 0; i < maxAttempts; i++) {
    try {
      // Try to connect to the proxy port
      const testSocket = new net.Socket();
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timeout')), 2000);
        testSocket.connect(proxyPort, '127.0.0.1', () => {
          clearTimeout(timeout);
          testSocket.destroy();
          resolve();
        });
        testSocket.on('error', reject);
      });
      
      // If health check endpoint is configured, test it
      if (healthEndpoint && healthEndpoint.includes('{PROXY_PORT}')) {
        const endpoint = healthEndpoint.replace('{PROXY_PORT}', proxyPort);
        try {
          await axios.get(endpoint, { timeout: 2000 });
        } catch (err) {
          // Non-fatal if health endpoint fails, proxy might still work
          console.warn(`Health check endpoint failed: ${err.message}`);
        }
      }
      
      console.log(`✅ Proxy on port ${proxyPort} is ready`);
      return true;
      
    } catch (err) {
      if (i < maxAttempts - 1) {
        console.log(`Waiting for proxy on port ${proxyPort} to be ready... (${i + 1}/${maxAttempts})`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      } else {
        throw new Error(`Proxy on port ${proxyPort} not ready after ${maxAttempts} attempts`);
      }
    }
  }
}

async function cleanupDynamicProxy(proxyPort) {
  if (!dynamicProxies.has(proxyPort)) {
    return;
  }
  
  const proxyInfo = dynamicProxies.get(proxyPort);
  console.log(`🧹 Cleaning up ${proxyInfo.provider} proxy on port ${proxyPort}`);
  
  try {
    // Execute cleanup command if configured
    if (CONFIG.proxies.dynamic.cleanupCommand) {
      let cleanupCmd = CONFIG.proxies.dynamic.cleanupCommand;
      
      // Add provider-specific replacements
      const replacements = {
        '{PROXY_PORT}': proxyPort.toString(),
        '{PROVIDER_NAME}': proxyInfo.provider,
        '{SESSION_ID}': proxyInfo.sessionId || ''
      };
      
      cleanupCmd = cleanupCmd.replace(/{[^}]+}/g, (match) => replacements[match] || match);
      
      await execPromise(cleanupCmd, { timeout: 5000 });
      console.log(`✅ Executed cleanup command for port ${proxyPort}`);
    }
    
    dynamicProxies.delete(proxyPort);
    console.log(`✅ Cleaned up proxy on port ${proxyPort}`);
  } catch (err) {
    console.error(`Failed to cleanup proxy on port ${proxyPort}:`, err.message);
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
      timeout: CONFIG.connection.timeoutMs,
    });
    
    return socket;
  } else if (proxyUrl.startsWith('http')) {
    const agent = new HttpsProxyAgent(proxyUrl);
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: targetHost, port: targetPort, agent });
      socket.once('connect', () => resolve(socket));
      socket.once('error', reject);
      setTimeout(() => reject(new Error('HTTP proxy connection timeout')), CONFIG.connection.timeoutMs);
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
  
  console.log('✅ Post-quantum handshake completed');
  
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

async function connectToUser(ip, port, proxyConfig) {
  let socket;
  
  if (proxyConfig.type === 'dynamic') {
    // Connect through local dynamic proxy
    console.log(`Connecting via ${proxyConfig.provider} dynamic proxy on local port ${proxyConfig.proxyPort}`);
    socket = await new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: '127.0.0.1', port: proxyConfig.proxyPort });
      sock.once('connect', () => resolve(sock));
      sock.once('error', reject);
      setTimeout(() => reject(new Error('Dynamic proxy connection timeout')), CONFIG.connection.timeoutMs);
    });
  } else {
    // Connect through static proxy
    console.log(`Connecting via static proxy: ${proxyConfig.url.substring(0, 50)}...`);
    socket = await connectViaProxy(proxyConfig.url, ip, port);
  }
  
  const { encrypt, decrypt, socket: encryptedSocket } = await pqHandshakeClient(socket);
  
  // Send ping to verify channel works
  const pingMsg = JSON.stringify({ type: 'ping', ts: Date.now() });
  encryptedSocket.write(encrypt(Buffer.from(pingMsg)));
  
  let pongReceived = false;
  const pongPromise = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('No pong response')), 5000);
    const handler = (chunk) => {
      decrypt(chunk, (plaintext) => {
        const msg = JSON.parse(plaintext.toString());
        if (msg.type === 'pong') {
          clearTimeout(timeout);
          pongReceived = true;
          encryptedSocket.removeListener('data', handler);
          resolve();
        }
      });
    };
    encryptedSocket.on('data', handler);
  });
  
  await pongPromise;
  console.log('✅ Channel verified, connection established');
  
  return { encrypt, decrypt, socket: encryptedSocket, proxyConfig };
}

async function processPullRequest(octokit, pr, privateKey) {
  const branch = pr.head.ref;
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  
  if (!uuidPattern.test(branch)) {
    console.log(`Skipping non-UUID branch: ${branch}`);
    return false;
  }
  
  console.log(`\n📡 Processing PR #${pr.number} branch ${branch}`);
  
  const encBuffer = await fetchEncFile(octokit, branch);
  if (!encBuffer) {
    console.log(`No .enc file found in branch ${branch}`);
    if (CONFIG.cleanup.failedConnectionCleanup) {
      await closePRAndDeleteBranch(octokit, pr.number, branch);
    }
    return false;
  }
  
  let payload;
  try {
    payload = decryptWithRSA(encBuffer, privateKey);
  } catch (err) {
    console.error(`Decryption failed for PR #${pr.number}:`, err.message);
    if (CONFIG.cleanup.failedConnectionCleanup) {
      await closePRAndDeleteBranch(octokit, pr.number, branch);
    }
    return false;
  }
  
  const { ip, timestamp, uuid, metadata } = payload;
  const ageSeconds = Math.round((Date.now() - timestamp) / 1000);
  console.log(`📦 Decrypted payload:`);
  console.log(`   IP: ${ip}`);
  console.log(`   UUID: ${uuid}`);
  console.log(`   Age: ${ageSeconds}s`);
  console.log(`   Hostname: ${metadata.hostname}`);
  console.log(`   Platform: ${metadata.platform}`);
  
  if (Date.now() - timestamp > CONFIG.connection.ttlMs) {
    console.log(`⏰ UUID expired (${ageSeconds}s old), closing`);
    if (CONFIG.cleanup.failedConnectionCleanup) {
      await closePRAndDeleteBranch(octokit, pr.number, branch);
    }
    return false;
  }
  
  // Try to instantiate dynamic proxy first if enabled
  let dynamicProxy = null;
  if (CONFIG.proxies.dynamic.enabled && CONFIG.residentialProxyProvider.enabled) {
    try {
      dynamicProxy = await instantiateDynamicProxy(ip, CONFIG.connection.targetPort, metadata);
      console.log(`✅ Dynamic proxy created on port ${dynamicProxy.proxyPort} using ${dynamicProxy.provider}`);
    } catch (err) {
      console.error(`Failed to create dynamic proxy: ${err.message}`);
      if (!CONFIG.residentialProxyProvider.fallbackToStatic) {
        console.log('No fallback to static proxies enabled, aborting connection');
        if (CONFIG.cleanup.failedConnectionCleanup) {
          await closePRAndDeleteBranch(octokit, pr.number, branch);
        }
        return false;
      }
      console.log('Falling back to static proxies...');
    }
  }
  
  // Build list of proxies to try
  const proxiesToTry = [];
  
  if (dynamicProxy) {
    proxiesToTry.push(dynamicProxy);
  }
  
  // Add static proxies if fallback is enabled
  if (CONFIG.residentialProxyProvider.fallbackToStatic) {
    for (const proxyUrl of CONFIG.proxies.static) {
      proxiesToTry.push({ type: 'static', url: proxyUrl });
    }
  }
  
  // Shuffle proxies for rotation
  for (let i = proxiesToTry.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [proxiesToTry[i], proxiesToTry[j]] = [proxiesToTry[j], proxiesToTry[i]];
  }
  
  let connected = false;
  let successfulProxy = null;
  
  for (const proxyConfig of proxiesToTry) {
    try {
      const { encrypt, decrypt, socket, proxyConfig: usedProxy } = await connectToUser(
        ip, 
        CONFIG.connection.targetPort, 
        proxyConfig
      );
      
      const proxyDesc = usedProxy.type === 'dynamic' 
        ? `${usedProxy.provider} dynamic proxy ${usedProxy.proxyPort}` 
        : `static proxy ${usedProxy.url.substring(0, 50)}`;
      
      console.log(`✓ Successfully connected to ${ip} via ${proxyDesc}`);
      
      // Clean up PR and branch now that we're connected
      await closePRAndDeleteBranch(octokit, pr.number, branch);
      connected = true;
      successfulProxy = usedProxy;
      
      // Keep connection alive and monitor health
      let lastPing = Date.now();
      const healthInterval = setInterval(() => {
        if (Date.now() - lastPing > CONFIG.connection.healthCheckTimeoutMs) {
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
      }, CONFIG.connection.healthCheckIntervalMs);
      
      socket.on('data', (chunk) => {
        decrypt(chunk, (plaintext) => {
          const msg = JSON.parse(plaintext.toString());
          if (msg.type === 'pong') {
            lastPing = Date.now();
            console.log('💓 Health check OK');
          } else {
            console.log('📨 Received from user:', msg);
          }
        });
      });
      
      socket.on('close', () => {
        console.log(`🔌 Connection to ${ip} closed`);
        clearInterval(healthInterval);
        clearInterval(pingInterval);
        
        // Cleanup dynamic proxy if it was used
        if (successfulProxy && successfulProxy.type === 'dynamic') {
          cleanupDynamicProxy(successfulProxy.proxyPort);
        }
      });
      
      // Keep the connection alive indefinitely
      await new Promise(() => {});
      
    } catch (err) {
      const proxyDesc = proxyConfig.type === 'dynamic' 
        ? `${proxyConfig.provider} dynamic proxy ${proxyConfig.proxyPort}` 
        : `static proxy ${proxyConfig.url?.substring(0, 50)}`;
      
      console.error(`Failed via ${proxyDesc}:`, err.message);
      
      // Cleanup dynamic proxy if it failed
      if (proxyConfig.type === 'dynamic') {
        await cleanupDynamicProxy(proxyConfig.proxyPort);
      }
      continue;
    }
  }
  
  if (!connected) {
    console.log(`❌ All proxies failed for ${ip}`);
    if (CONFIG.cleanup.failedConnectionCleanup) {
      await closePRAndDeleteBranch(octokit, pr.number, branch);
    }
  }
  
  return connected;
}

async function main() {
  await loadConfig();
  
  const githubToken = process.env.SCANNER_GITHUB_TOKEN;
  if (!githubToken) {
    console.error('❌ SCANNER_GITHUB_TOKEN environment variable not set');
    process.exit(1);
  }
  
  let privateKey;
  try {
    privateKey = await loadPrivateKey();
  } catch (err) {
    console.error('Failed to load private key:', err.message);
    process.exit(1);
  }
  
  const octokit = new Octokit({ auth: githubToken });
  console.log('\n🚀 Scanner started');
  console.log(`📊 Polling every ${CONFIG.github.pollIntervalMs / 1000} seconds`);
  console.log(`👁️  Watching repo: ${CONFIG.github.owner}/${CONFIG.github.repo}`);
  
  if (CONFIG.residentialProxyProvider.enabled) {
    console.log(`🔐 Residential Proxy Provider: ${CONFIG.residentialProxyProvider.name}`);
    console.log(`   Fallback to static: ${CONFIG.residentialProxyProvider.fallbackToStatic ? 'YES' : 'NO'}`);
  }
  
  console.log(`🔄 Dynamic proxies: ${CONFIG.proxies.dynamic.enabled ? 'ENABLED' : 'DISABLED'}`);
  console.log(`📦 Static proxies: ${CONFIG.proxies.static.length}`);
  console.log('-------------------------------------------\n');
  
  while (true) {
    try {
      const { data: pulls } = await octokit.rest.pulls.list({
        owner: CONFIG.github.owner,
        repo: CONFIG.github.repo,
        state: 'open',
        sort: 'created',
        direction: 'desc'
      });
      
      if (pulls.length > 0) {
        console.log(`📋 Found ${pulls.length} open pull requests`);
      }
      
      for (const pr of pulls) {
        await processPullRequest(octokit, pr, privateKey);
      }
      
    } catch (err) {
      console.error('Scanner error:', err.message);
    }
    
    await new Promise(resolve => setTimeout(resolve, CONFIG.github.pollIntervalMs));
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down scanner...');
  
  // Cleanup all dynamic proxies
  for (const [port, info] of dynamicProxies) {
    await cleanupDynamicProxy(port);
  }
  
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Shutting down scanner...');
  for (const [port, info] of dynamicProxies) {
    await cleanupDynamicProxy(port);
  }
  process.exit(0);
});

main().catch(console.error);
