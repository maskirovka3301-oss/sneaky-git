# SNEAKY GIT

Build globally unblockable services (a post-VPN connection tool)

![SneakyGit](logo.jpg)

**GitHub-mediated covert signaling + residential proxy callback system**

A stealthy Node.js tool that uses public GitHub repositories as a signaling channel to establish resilient, post-quantum encrypted, DPI-resistant connections through rotating residential proxies.

## Overview

`sneaky-git` allows users to automatically signal their public IP and open a listening port to a remote service *without* making a direct outbound connection from the user. The service then initiates the connection **from a residential proxy**, creating a hard-to-block, hard-to-attribute tunnel.

This architecture is particularly useful in environments with strict outbound filtering, DPI, or where direct connections to known service IPs are undesirable.

The repository contains the **client-side tool** that users run after forking. The maintainer operates the server-side scanner, proxy pool, and connection handler separately.

## Features

- Fully automated GitHub signaling using forks, UUIDv4-named branches, and Pull Requests
- Strong hybrid encryption for signaling data (RSA + AES-GCM with frequently rotated public keys)
- Randomized encrypted payload filenames (e.g. `a1b2c3d4f9.enc`)
- Post-quantum secure session establishment (ML-KEM + X25519 + AES-256-GCM)
- DPI-resistant transport layer
- Server-side outbound connections sourced from a rotating residential proxy pool
- Automatic connection health monitoring and reconnection
- Short-lived signaling artifacts (UUIDs expire after 10–30 minutes)
- Built-in timeouts with proxy rotation (30–60 seconds)
- Automatic cleanup of GitHub artifacts (PR closure + branch deletion) upon successful connection

## How It Works

### 1. User Side (this tool)
- User forks this public repository and runs the Node.js tool.
- Tool generates a UUIDv4 (used as the branch name).
- Retrieves the user’s current public IP address.
- Encrypts the payload (IP + timestamp + UUID + metadata) using the maintainer’s public key (hybrid RSA + AES-GCM).
- Creates a new branch named exactly after the UUID on the user’s fork.
- Creates a file with a **randomized name** (e.g. `a1b2c3d4...f9.enc`) containing the encrypted data.
- Commits and pushes the branch to the user’s fork.
- Automatically creates a Pull Request from the fork to the main repository.
- Starts a TCP listener on a configured port (default: `44333`) on the user’s machine.

### 2. Server Side (VPS Scanner)
- Continuously polls the main repository for new Pull Requests / branches that match the UUID pattern.
- Reads the only `.enc` file in that branch.
- Decrypts the file using the maintainer’s private key and extracts the user’s IP address + metadata.
- Picks a random residential proxy from the rotating pool.
- Using the residential proxy as the source IP, the VPS actively connects to the user’s public IP on the listening port.
- Once the TCP connection is established, both sides perform a handshake.
- They negotiate a post-quantum hybrid encrypted session (ML-KEM + X25519 for key exchange + AES-256-GCM for data) through a DPI-resistant tunnel.
- After successful connection, the VPS closes the PR and deletes the branch for cleanup.

### 3. Data Exchange
All subsequent communication between the service and the user’s tool occurs over the established post-quantum encrypted, DPI-resistant channel.  
The user can now use the service through this resilient link that originated from a rotating residential IP.

## Security & Privacy

- **Signaling encryption**: Hybrid RSA + AES-GCM (public key rotated frequently)
- **Session encryption**: Post-quantum hybrid (ML-KEM + X25519 + AES-256-GCM)
- Ephemeral UUIDs and randomized filenames reduce pattern-based detection
- No direct connection between user and service infrastructure during initial signaling
- Outbound traffic from the service appears as ordinary residential connections
- Connection health monitoring with automatic reconnection
- Timeouts and short-lived artifacts limit exposure

## Prerequisites

- Node.js 20+
- Git installed and configured with GitHub credentials
- A GitHub account
- Fork of this repository

## Installation & Usage

```bash
# 1. Fork this repository on GitHub, then clone your fork
git clone https://github.com/YOURUSERNAME/sneaky-git.git
cd sneaky-git

# 2. Install dependencies
npm install
