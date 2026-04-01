# libresocial

A decentralized, end-to-end encrypted social network. No algorithms, no tracking — just a chronological feed from your friends.

## Features

- **End-to-end encryption** — Posts, messages, and media are encrypted client-side with AES-256-GCM. The server only stores ciphertext.
- **Chronological feed** — No algorithmic ranking. Posts from friends, in order.
- **Direct messages** — Private encrypted conversations.
- **Friend system** — Mutual friend requests with ECDH key exchange.
- **Bloom filter privacy** — Feed requests use bloom filters so the server never learns your friend list.
- **Encrypted vault** — Your friends list and keys are stored in a client-side encrypted vault the server cannot read.
- **Key rotation** — Rotate your feed encryption key at any time, with automatic redistribution to friends.
- **Self-hostable** — Run your own instance with a single command.

## Tech Stack

- **Frontend:** React, Vite
- **Backend:** Express, SQLite (better-sqlite3)
- **Crypto:** Web Crypto API (ECDH, ECDSA, AES-256-GCM, PBKDF2, HKDF)

## Quick Start

```bash
npm install
cp .env.example .env   # edit as needed
npm run dev             # starts server (port 3000) + client (port 5173)
```

## Production

```bash
npm run build
npm start
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `HOST` | `0.0.0.0` | Bind address |
| `DOMAIN` | `localhost` | Domain for CORS/CSP headers |
| `DB_PATH` | `./data/friendsforum.db` | SQLite database path |
| `DATA_DIR` | `./data` | Storage directory for uploads |

## Project Structure

```
libresocial/
├── server/
│   ├── index.js          # Express API server
│   ├── config.js          # Configuration
│   └── store/             # Database layer (users, sessions, notifications)
├── src/
│   └── ui/
│       └── App.jsx        # React app (all views)
├── vite.config.js
└── package.json
```

## License

AGPL-3.0
