# LibreSocial

A decentralized, encrypted, ad-free, recommendation-algorithm-free social network. The server cannot read your posts, your friends list, your messages, or even your username.

**Live instance:** [lsocial.org](https://lsocial.org)

## Why LibreSocial?

On Bluesky, Mastodon, and Diaspora, instance operators can read every post, every DM, and every friend connection — it's all plaintext on the server. LibreSocial is fundamentally different: the server stores only ciphertext it cannot decrypt. A compromised or subpoenaed server reveals nothing.

- Your posts are encrypted before they leave your browser
- Your friends list is hidden from the server
- Your feed requests use bloom filters so the server can't see exactly whose posts you're fetching
- Direct messages are end-to-end encrypted
- All keys derive from your password — no device-bound identity, log in from anywhere

## Features

- Encrypted posts with photos (up to 100) and videos (up to 10) per post
- End-to-end encrypted direct messages
- Chat requests for messaging non-friends
- Comments on posts (visible to all friends of the post author)
- Encrypted profile names and photos (only visible to friends)
- Clickable user profiles with post history
- Post and comment editing and deletion
- Server-opaque identity: client-side SHA-256 username hashing (plaintext domain retained for federation routing)
- Dynamic bloom filter sizing for feed privacy
- Password change with automatic feed key redistribution
- Feed key rotation with 1-month transition period
- Emergency key revocation
- Trusted device login (optional, persists across sessions)
- Proof-of-work CAPTCHA on registration ([Cap](https://altcha.org/cap))
- Federation support via WebFinger (early stage)
- Content-addressed storage with SHA-256 deduplication

## Security Model

### What the server cannot see

- Post content, photos, or videos
- Your friends list
- Display names or profile photos
- Direct message content
- Feed keys
- Plaintext usernames (only hashes)

### What the server can see

- Hashed usernames and plaintext domains (for federation routing)
- Public keys (signing and encryption)
- Encrypted blobs (posts, vault, media — all opaque ciphertext)
- Timing metadata (when posts are created, when users log in)
- Bloom filter per feed request (reveals a probabilistic superset of friends)

### What the server cannot do even if compromised

- Read any encrypted content
- Determine your exact friends list
- Decrypt direct messages
- Recover your password from your keys

### Threat model limitations

- A compromised server could replace a user's public keys to intercept future key exchanges (TOFU model)
- Traffic analysis could infer friendships from access patterns
- The bloom filter leaks some information about your friends (probabilistic, not exact)
- If you forget your password, your account is unrecoverable

## Tech Stack

- **Frontend:** React 18, Vite
- **Backend:** Node.js, Express
- **Database:** SQLite (better-sqlite3)
- **Crypto:** WebCrypto API (PBKDF2, HKDF, ECDSA P-256, ECDH P-256, AES-256-GCM)
- **CAPTCHA:** Cap (SHA-256 proof-of-work)
- **Storage:** Content-addressed filesystem (SHA-256 hashed)

## Self-Hosting

### Requirements

- Node.js 18+
- A domain with HTTPS (use Caddy, nginx, or similar as a reverse proxy)

### Setup

```bash
git clone https://github.com/rltvty2/libresocial.git
cd libresocial
npm install
cp .env.example .env
# Edit .env with your domain
npm run build
npm start
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `localhost` | Your instance domain |
| `PORT` | `3000` | Server port |
| `HOST` | `0.0.0.0` | Bind address |
| `DATA_DIR` | `./data` | Data storage directory |
| `DB_PATH` | `./data/friendsforum.db` | SQLite database path |

### Running as a Service

Create `/etc/systemd/system/libresocial.service`:

```ini
[Unit]
Description=LibreSocial
After=network.target

[Service]
User=libresocial
Group=libresocial
Type=simple
WorkingDirectory=/opt/libresocial
ExecStart=/usr/bin/node server/index.js
Restart=always
RestartSec=5
EnvironmentFile=/opt/libresocial/.env

[Install]
WantedBy=multi-user.target
```

Then:

```bash
useradd -r -s /bin/false libresocial
chown -R libresocial:libresocial /opt/libresocial
systemctl enable libresocial
systemctl start libresocial
```

### Reverse Proxy (Caddy)

```
lsocial.org {
    reverse_proxy localhost:3000
}
```

### Development

```bash
npm run dev
```

This starts both the Vite dev server (port 5173) and the backend (port 3000) with hot reload.

## License

[AGPL-3.0](LICENSE)

## Acknowledgements

Built with the help of [Claude](https://claude.ai) by Anthropic.
