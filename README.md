# Sneaky-Git - Post-Quantum Secure Tunneling via GitHub Signaling

![Proxy](logo.jpg)

## Description

A sophisticated, zero-trust tunneling system that uses GitHub as a signaling channel to establish post-quantum encrypted connections through residential proxies. The system enables secure, DPI-resistant communication without any initial outbound connections from the client side.

### Core Innovation

Unlike traditional tunneling solutions that require outbound connections to signaling servers, Sneaky-Git uses **GitHub Pull Requests as a dead-drop signaling mechanism**. The user's machine never needs to know your server's IP address or make any outbound connections (except GitHub API) to initiate the tunnel - your server connects to them through residential proxies.

## Features

- **GitHub-Based Signaling**: Uses Pull Requests as a secure, asynchronous message queue
- **Zero Outbound Connections**: Client doesn't need to know server IP or connect outward
- **Post-Quantum Cryptography**: ML-KEM-768 + X25519 hybrid key exchange
- **Quantum-Resistant Encryption**: AES-256-GCM for data in transit
- **Residential Proxy Egress**: Server connects through rotating residential proxies
- **DPI Resistance**: Encrypted tunnel with no static protocol patterns
- **Automatic Failover**: Proxy rotation and connection retry logic
- **Health Monitoring**: Built-in ping/pong with automatic reconnection
- **Short-lived UUIDs**: Automatic expiration after configurable TTL
- **Zero Dependencies for Key Exchange**: Pure JavaScript ML-KEM implementation
- **Fully Automated**: One command to establish complete tunnel

## Architecture Overview

```
┌─────────────┐         GitHub PR (Signaling)           ┌─────────────┐
│             │  ─────────────────────────────────▶     │             │
│  User Node  │                                         │  VPS Server │
│  (Client)   │  ◀─────────────────────────────────     │  (Scanner)  │
│             │     Direct TCP via Residential Proxy    │             │
└─────────────┘                                         └─────────────┘
      │                                                         │
      │                                                    ┌────▼────┐
      │                                                    │Resident │
      │                                                    │ Proxies │
      │                                                    └───┬─────┘
      ▼                                                        │
┌─────────────┐                                                │
│ Local Proxy │                                                │
│ 127.0.0.1   │                                                │
│   :8080     │                                                │
└─────────────┘                                                │
      │                                                        │
      ▼                                                        ▼
┌─────────────┐                                         ┌─────────────┐
│  Browser/   │                                         │  Target     │
│  App        │                                         │  Website    │
└─────────────┘                                         └─────────────┘
```

## How It Works - Detailed Flow

### Phase 1: Signaling (GitHub as Control Channel)

1. **User Generates UUID**: Creates a version 4 UUID that serves as the unique branch name
2. **Collects Metadata**: Captures public IP, timestamp, hostname, platform info
3. **Hybrid RSA Encryption**: 
   - Generates random AES-256 key
   - Encrypts metadata with AES-256-GCM
   - Encrypts AES key with your RSA public key (4096-bit)
   - Creates single encrypted blob with format: `[encrypted_key_len][encrypted_key][iv][auth_tag][ciphertext]`
4. **GitHub Fork Operation**:
   - Creates new branch named exactly after the UUID
   - Writes encrypted blob to randomly named `.enc` file (e.g., `a1b2c3d4e5f6.enc`)
   - Commits and pushes branch to user's fork
   - Creates Pull Request from fork to your main repository
5. **Listener Activation**: 
   - Opens TCP port 44333 (attempts UPnP port forwarding)
   - Waits for inbound connection from your VPS

### Phase 2: Server Scanning & Connection

1. **Continuous Polling**: VPS scanner polls GitHub API every 10 seconds for new PRs
2. **UUID Validation**: Filters branches matching UUID pattern `^[0-9a-f]{8}-[0-9a-f]{4}-...$`
3. **Decryption**: 
   - Downloads `.enc` file from PR branch
   - Extracts and decrypts AES key using RSA private key
   - Decrypts metadata with AES-256-GCM
   - Validates timestamp (rejects if >20 minutes old)
4. **Proxy Selection**: Randomly picks a residential proxy from rotating pool
5. **Outbound Connection**: 
   - Connects through selected proxy to user's public IP:44333
   - Falls back to different proxies on timeout (30-60 seconds)
   - Rotates through entire proxy pool if needed

### Phase 3: Post-Quantum Handshake

The handshake combines classical and quantum-resistant cryptography:

```
Client (User)                    Server (VPS)
     │                                │
     │  ←─── ML-KEM Public Key ────   │
     │                                │
     │  ──── ML-KEM Ciphertext ────▶  │
     │                                │
     │  ←─── X25519 Public Key ────   │
     │                                │
     │  ──── X25519 Public Key ────▶  │
     │                                │
     ▼                                ▼
Both sides compute:
  shared_secret = H(ML-KEM_shared || X25519_shared)
  session_key = SHA256(shared_secret)
```

**Cryptographic Details**:
- **ML-KEM-768**: NIST FIPS 203 standard, quantum-resistant key encapsulation
- **X25519**: Elliptic curve Diffie-Hellman for classical security
- **Hybrid Construction**: Combines both for defense in depth
- **AES-256-GCM**: Authenticated encryption for data channel
- **Perfect Forward Secrecy**: Ephemeral keys for each session

### Phase 4: Encrypted Data Tunnel

1. **AES-256-GCM Channel**:
   - Each message has unique 12-byte IV with 32-bit sequence counter
   - 16-byte authentication tag prevents tampering
   - Length-prefixed framing prevents traffic analysis
2. **Health Monitoring**:
   - Bidirectional ping/pong every 30 seconds
   - Automatic reconnection on failure (creates new UUID, new PR)
3. **Local Proxy**:
   - SOCKS5/HTTP forwarder on `127.0.0.1:8080`
   - Routes all client traffic through encrypted tunnel
   - Works with any TCP-based application

## Installation

### Prerequisites
- Node.js 18.x or higher
- GitHub account with Personal Access Token (repo scope)
- Oxylabs or residential proxy account (for server side)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/sneaky-git.git
cd sneaky-git

# Generate keypair (commits public key automatically)
npm run generate-keypair

# Install dependencies
npm install

# Set GitHub token
export GITHUB_TOKEN=ghp_your_token_here

# Run the client
node signal.js
```

### Server Setup (VPS)

```bash
# Clone the repository on your VPS
git clone https://github.com/yourusername/sneaky-git.git
cd sneaky-git

# Transfer private.pem securely (e.g., via scp)
scp user@local:~/sneaky-git/private.pem .

# Set environment variables
export SCANNER_GITHUB_TOKEN=ghp_your_scanner_token
export PRIVATE_KEY_PEM="$(cat private.pem)"

# Update proxy list in scanner.js with your residential proxies

# Run scanner
node scanner.js
```

## Configuration

### Client Configuration (`signal.js`)

```javascript
const LISTEN_PORT = 44333;           // Port for VPS to connect
const LOCAL_PROXY_PORT = 8080;       // Local proxy port
const MAIN_REPO_OWNER = 'yourorg';   // Your GitHub username/org
const MAIN_REPO_NAME = 'main-repo';  // Your repository name
```

### Server Configuration (`scanner.js`)

```javascript
const PROXY_LIST = [
  'socks5://user:pass@proxy1:1080',   // Residential proxy 1
  'socks5://user:pass@proxy2:1080',   // Residential proxy 2
  'http://user:pass@proxy3:3128',     // HTTP proxy fallback
];
const CONNECTION_TIMEOUT_MS = 45000;   // 45 seconds timeout
const TTL_MS = 20 * 60 * 1000;        // 20 minute expiry
const POLL_INTERVAL_MS = 10000;       // Poll every 10 seconds
```

### GitHub Token Scopes

**Client Token** (`GITHUB_TOKEN`):
- `repo` - Create branches, push commits, create PRs
- `public_repo` - For public repositories

**Server Token** (`SCANNER_GITHUB_TOKEN`):
- `repo` - Read PRs, download files, close PRs, delete branches
- `public_repo` - For public repositories

## Usage Examples

### Browser Automation (Puppeteer)

```javascript
import puppeteer from 'puppeteer';

const browser = await puppeteer.launch({
  args: ['--proxy-server=socks5://127.0.0.1:8080']
});

const page = await browser.newPage();
await page.goto('https://httpbin.org/ip');
const ip = await page.evaluate(() => document.body.innerText);
console.log('Your exit IP:', ip); // Shows residential proxy IP
```

### HTTP Requests (Node.js)

```javascript
import { SocksProxyAgent } from 'socks-proxy-agent';

const agent = new SocksProxyAgent('socks5://127.0.0.1:8080');
const response = await fetch('https://api.ipify.org?format=json', { agent });
const data = await response.json();
console.log('Your IP:', data.ip);
```

### Python with Requests

```python
import requests

proxies = {
    'http': 'socks5://127.0.0.1:8080',
    'https': 'socks5://127.0.0.1:8080'
}

response = requests.get('https://httpbin.org/ip', proxies=proxies)
print(response.json())
```

### cURL

```bash
curl --socks5 127.0.0.1:8080 https://ip.oxylabs.io/location
```

## Security Architecture

### Encryption Layers

1. **Signaling Layer** (GitHub → Server):
   - RSA 4096-bit + AES-256-GCM hybrid encryption
   - Metadata includes timestamp to prevent replay attacks
   - Random filenames prevent pattern detection

2. **Handshake Layer** (Direct TCP):
   - ML-KEM-768 (post-quantum key encapsulation)
   - X25519 (classical ECDH)
   - Combined shared secret derivation

3. **Data Layer** (Encrypted Tunnel):
   - AES-256-GCM with per-message unique IVs
   - Sequence numbers prevent replay
   - Length-prefixed framing with authentication tags

### DPI Resistance

- **No Static Patterns**: Every connection has unique handshake
- **Randomized Filenames**: `.enc` files with unpredictable names
- **Variable Timing**: Randomized retry intervals
- **Encrypted Everything**: No plaintext metadata in transit

## Troubleshooting

### Common Issues

**"GITHUB_TOKEN environment variable not set"**
```bash
export GITHUB_TOKEN=ghp_your_token_here
```

**"private.pem already exists"**
```bash
rm private.pem  # Only if you want to regenerate
npm run generate-keys
```

**Connection timeout (30-60 seconds)**
- Check if port 44333 is reachable (UPnP or manual forwarding)
- Verify no firewall blocking inbound connections
- Scanner automatically retries with different proxies

**"No .enc file found in branch"**
- Ensure branch name is exactly the UUID
- Check that `.enc` file was committed properly
- Verify GitHub token has write access

**"Decryption failed"**
- Confirm public.pem matches private.pem
- Ensure private.pem is loaded correctly on VPS
- Check for corruption in encrypted blob

### Debug Mode

Enable detailed logging:

```bash
# Client side
DEBUG=signal* node signal.js

# Server side
DEBUG=scanner* node scanner.js
```

## Performance Characteristics

- **Connection Setup**: 5-15 seconds (GitHub API + proxy connection + handshake)
- **Throughput**: Limited by residential proxy (typically 10-50 Mbps)
- **Latency**: Proxy-dependent, typically 200-800ms added
- **Concurrent Connections**: Supports unlimited via local proxy
- **Memory Usage**: ~50MB baseline, scales with active connections

## Limitations

- UDP not supported (TCP only)
- Requires GitHub API access (rate limits apply)
- Residential proxies may have bandwidth limits
- Initial connection requires 5-15 seconds setup time
- UPnP may fail on some networks (manual port forwarding required)

V## Future Improvements

- [ ] Multiple simultaneous tunnel sessions
- [ ] Automatic proxy health checking and scoring
- [ ] Bandwidth aggregation across multiple proxies

## Repository Structure

```
sneaky-git/
├── signal.js              # Client-side tunneling tool
├── scanner.js             # Server-side scanner
├── generate-keypair.js    # Key generation with auto-commit
├── public.pem             # RSA public key (committed)
├── private.pem            # RSA private key (gitignored)
├── .gitignore            # Ignores private.pem and *.enc
├── package.json          # Dependencies and scripts
└── README.md             # This file
```

## Requirements

- Node.js 18.x or higher
- GitHub account with Personal Access Token
- Oxylabs or residential proxy subscription (server side)
- Network with outbound internet access

## License

MIT License - See LICENSE file for details.

## Contact & Support

For inquiries or support please send an e-mail.

**Email**: maskirovka3301@gmail.com  

---

**If this tool helps you to build unblockable services, please give the repository a star.**
