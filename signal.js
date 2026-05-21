#!/usr/bin/env node

const { randomUUID } = require('crypto');
const { v4: uuidv4 } = require('uuid');
const simpleGit = require('simple-git');
const { Octokit } = require('@octokit/rest');
const axios = require('axios');
const fs = require('fs').promises;
const crypto = require('crypto');
const net = require('net');
const { createMlKem768 } = require('mlkem');
const { createUPnPClient } = require('nat-upnp');

// Configuration
const LISTEN_PORT = 44333;
const LOCAL_PROXY_PORT = 8080;
const PUBLIC_KEY_URL = 'https://your-vps.com/signal/public.pem';
const MAIN_REPO_OWNER = 'yourorg';
const MAIN_REPO_NAME = 'main-repo';

async function getPublicIP() {
  const res = await axios.get('https://api.ipify.org?format=json');
  return res.data.ip;
}

async function fetchPublicRSAKey() {
  const res = await axios.get(PUBLIC_KEY_URL);
  return res.data;
}

function encryptWithRSA(plaintext, rsaPublicKeyPem) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedAesKey = crypto.publicEncrypt(
    { key: rsaPublicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    aesKey
  );
  const result = Buffer.alloc(2 + encryptedAesKey.length + iv.length + authTag.length + encrypted.length);
  let offset = 0;
  result.writeUInt16BE(encryptedAesKey.length, offset); offset += 2;
  encryptedAesKey.copy(result, offset); offset += encryptedAesKey.length;
  iv.copy(result, offset); offset += iv.length;
  authTag.copy(result, offset); offset += authTag.length;
  encrypted.copy(result, offset);
  return result;
}

async function createBranchAndPush(uuid, encData) {
  const git = simpleGit();
  const repoRoot = process.cwd();
  const fileName = crypto.randomBytes(16).toString('hex') + '.enc';
  const filePath = `${repoRoot}/${fileName}`;
  await fs.writeFile(filePath, encData);
  await git.checkoutLocalBranch(uuid);
  await git.add(fileName);
  await git.commit(`Add signal file for ${uuid}`);
  await git.push('origin', uuid, ['--set-upstream']);
  return fileName;
}

async function createPR(uuid, branchName) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) throw new Error('GITHUB_TOKEN environment variable not set');
  const octokit = new Octokit({ auth: token });
  const git = simpleGit();
  const remotes = await git.getRemotes(true);
  const origin = remotes.find(r => r.name === 'origin');
  const forkOwner = origin.refs.fetch.split(':')[1].split('/')[0];
  const pr = await octokit.rest.pulls.create({
    owner: MAIN_REPO_OWNER,
    repo: MAIN_REPO_NAME,
    title: `Signal from ${uuid}`,
    head: `${forkOwner}:${branchName}`,
    base: 'main',
    body: 'Automated signal connection request',
  });
  return pr.data.number;
}

async function setupUPnP() {
  try {
    const client = createUPnPClient();
    await client.portMapping({
      public: LISTEN_PORT,
      private: LISTEN_PORT,
      ttl: 3600,
    });
    console.log(`UPnP: forwarded port ${LISTEN_PORT}`);
    return client;
  } catch (err) {
    console.warn('UPnP failed, ensure port is manually forwarded', err.message);
    return null;
  }
}

async function handleInboundConnection(socket, onReady) {
  try {
    const kem = await createMlKem768();
    const [recipientPublicKey, recipientSecretKey] = kem.generateKeyPair();
    
    let ciphertext = null;
    socket.once('data', (chunk) => {
      ciphertext = chunk;
    });
    
    socket.write(Buffer.from(recipientPublicKey));
    
    await new Promise(resolve => setTimeout(resolve, 100));
    
    if (!ciphertext) {
      throw new Error('No ciphertext received from server');
    }
    
    const sharedSecret = kem.decaps(ciphertext, recipientSecretKey);
    const sessionKey = crypto.createHash('sha256').update(sharedSecret).digest();
    
    console.log('Post-quantum secure channel established');
    
    // Create encrypted stream wrapper
    const encryptStream = (key) => {
      let sequence = 0;
      return {
        write: (data, callback) => {
          const iv = Buffer.alloc(12);
          iv.writeUInt32BE(sequence++);
          const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
          const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
          const authTag = cipher.getAuthTag();
          const packet = Buffer.concat([iv, authTag, encrypted]);
          const length = Buffer.alloc(4);
          length.writeUInt32BE(packet.length);
          socket.write(Buffer.concat([length, packet]), callback);
        }
      };
    };
    
    const decryptStream = (key) => {
      let buffer = Buffer.alloc(0);
      return {
        onData: (chunk, callback) => {
          buffer = Buffer.concat([buffer, chunk]);
          while (buffer.length >= 4) {
            const packetLen = buffer.readUInt32BE(0);
            if (buffer.length >= 4 + packetLen) {
              const packet = buffer.slice(4, 4 + packetLen);
              const iv = packet.slice(0, 12);
              const authTag = packet.slice(12, 28);
              const ciphertext = packet.slice(28);
              const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
              decipher.setAuthTag(authTag);
              const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
              buffer = buffer.slice(4 + packetLen);
              callback(plaintext);
            } else {
              break;
            }
          }
        }
      };
    };
    
    const writer = encryptStream(sessionKey);
    const reader = decryptStream(sessionKey);
    
    socket.on('data', (chunk) => {
      reader.onData(chunk, (plaintext) => {
        if (onReady && onReady.onData) onReady.onData(plaintext);
      });
    });
    
    onReady({ writer, reader, socket });
    
  } catch (err) {
    console.error('Handshake failed:', err);
    socket.destroy();
  }
}

function startLocalProxy(proxyPort, tunnelWriter) {
  const server = net.createServer((localSocket) => {
    console.log('Local client connected');
    
    localSocket.on('data', (data) => {
      tunnelWriter.write(data, (err) => {
        if (err) localSocket.destroy();
      });
    });
    
    localSocket.on('error', () => {});
    localSocket.on('close', () => console.log('Local client disconnected'));
  });
  
  server.listen(proxyPort, '127.0.0.1', () => {
    console.log(`Local proxy listening on 127.0.0.1:${proxyPort}`);
    console.log('Point your applications to this proxy for encrypted tunneling');
  });
  
  return server;
}

async function main() {
  const uuid = randomUUID();
  console.log(`UUID: ${uuid}`);
  
  const ip = await getPublicIP();
  const timestamp = Date.now();
  const metadata = { 
    hostname: require('os').hostname(), 
    version: 1,
    platform: process.platform
  };
  
  const plaintext = JSON.stringify({ ip, timestamp, uuid, metadata });
  const rsaPub = await fetchPublicRSAKey();
  const encData = encryptWithRSA(plaintext, rsaPub);
  
  await createBranchAndPush(uuid, encData);
  const prNumber = await createPR(uuid, uuid);
  console.log(`PR #${prNumber} created at https://github.com/${MAIN_REPO_OWNER}/${MAIN_REPO_NAME}/pull/${prNumber}`);
  
  const upnp = await setupUPnP();
  
  const server = net.createServer((socket) => {
    console.log('Incoming connection from VPS');
    let tunnelWriter = null;
    let healthInterval = null;
    
    handleInboundConnection(socket, ({ writer, reader, socket: encryptedSocket }) => {
      tunnelWriter = writer;
      
      reader.onData = (plaintext) => {
        const msg = plaintext.toString();
        if (msg.includes('ping')) {
          writer.write(Buffer.from(JSON.stringify({ type: 'pong' }) + '\n'));
        } else {
          // Forward decrypted data to local proxy clients
          // In a full implementation, you'd have a queue of local clients
          console.log('Received data:', msg.slice(0, 100));
        }
      };
      
      healthInterval = setInterval(() => {
        writer.write(Buffer.from(JSON.stringify({ type: 'ping', ts: Date.now() }) + '\n'));
      }, 30000);
      
      startLocalProxy(LOCAL_PROXY_PORT, writer);
    });
    
    socket.on('close', () => {
      console.log('Tunnel closed, restarting signaling...');
      if (healthInterval) clearInterval(healthInterval);
      server.close();
      if (upnp) upnp.close();
      setTimeout(() => main(), 5000);
    });
  });
  
  server.listen(LISTEN_PORT, '0.0.0.0', () => {
    console.log(`Listening on port ${LISTEN_PORT} for VPS connection`);
    console.log('Waiting for scanner to connect...');
  });
}

main().catch(console.error);
