// ============================================================================
// server/index.js - FriendsForum (self-hosted, federated)
// ============================================================================
//
// All content stored on local filesystem. Content-addressed by SHA-256.
// Feed filtered by client-supplied bloom filter for privacy.
// Friends list + feed keys stored in encrypted vault (server cannot read).
// Feed key exchange via ECDH-encrypted blobs.
//
// ============================================================================

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import compression from 'compression'
import multer from 'multer'
import rateLimit from 'express-rate-limit'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync, statSync, readdirSync } from 'fs'
import { createHash } from 'crypto'
import { config } from './config.js'
import { UserStore } from './store/users.js'
import { SessionStore } from './store/sessions.js'
import { NotificationQueue } from './store/notifications.js'
import Cap from '@cap.js/server'

const __dirname = dirname(fileURLToPath(import.meta.url))
const uploadDir = join(config.dataDir, 'uploads')
if (!existsSync(uploadDir)) mkdirSync(uploadDir, { recursive: true })
const upload = multer({ dest: uploadDir, limits: { fileSize: 500 * 1024 * 1024 } }) // 500 MB max per file

// ============================================================================
// Content-addressed storage on local filesystem
// ============================================================================
const CONTENT_DIR = join(config.dataDir, 'content')
if (!existsSync(CONTENT_DIR)) mkdirSync(CONTENT_DIR, { recursive: true })

function computeHash(data) {
  return createHash('sha256').update(data).digest('hex')
}

function contentPath(hash) {
  const dir = join(CONTENT_DIR, hash.slice(0, 2))
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return join(dir, hash)
}

function storeContent(data) {
  const buf = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data)
  const hash = computeHash(buf)
  const path = contentPath(hash)
  if (!existsSync(path)) writeFileSync(path, buf)
  return { hash, size: buf.length }
}

function getContent(hash) {
  const path = contentPath(hash)
  if (!existsSync(path)) return null
  return readFileSync(path)
}

function deleteContent(hash) {
  const path = contentPath(hash)
  if (existsSync(path)) unlinkSync(path)
}

function getContentSize(hash) {
  const path = contentPath(hash)
  if (!existsSync(path)) return 0
  return statSync(path).size
}

// ============================================================================
// Main Server
// ============================================================================
async function main() {
  console.log('============================================')
  console.log('  FriendsForum (self-hosted, federated)')
  console.log('============================================')
  console.log(`  Domain: ${config.domain}`)
  console.log(`  Port:   ${config.port}`)
  console.log(`  Data:   ${config.dataDir}`)
  console.log('')

  const userStore = new UserStore(config.db.path)
  const sessionStore = new SessionStore()
  const notifications = new NotificationQueue(join(config.dataDir, 'notifications.db'))
  await userStore.init()

  // Cap CAPTCHA — high difficulty for registration
  // In-memory storage for challenges and tokens
  const capChallenges = new Map()
  const capTokens = new Map()

  const cap = new Cap({
    storage: {
      challenges: {
        store: async (token, data) => { capChallenges.set(token, { challenge: data, expires: data.expires }) },
        read: async (token) => {
          const entry = capChallenges.get(token)
          if (!entry || entry.expires < Date.now()) { capChallenges.delete(token); return null }
          return entry
        },
        delete: async (token) => { capChallenges.delete(token) },
        deleteExpired: async () => {
          const now = Date.now()
          for (const [k, v] of capChallenges) { if (v.expires < now) capChallenges.delete(k) }
        },
      },
      tokens: {
        store: async (key, expires) => { capTokens.set(key, expires) },
        get: async (key) => {
          const exp = capTokens.get(key)
          if (!exp || exp < Date.now()) { capTokens.delete(key); return null }
          return exp
        },
        delete: async (key) => { capTokens.delete(key) },
        deleteExpired: async () => {
          const now = Date.now()
          for (const [k, v] of capTokens) { if (v < now) capTokens.delete(k) }
        },
      },
    },
  })

  const app = express()

  if (config.domain === 'localhost' || config.domain.match(/^\d/)) {
    app.use(helmet({ contentSecurityPolicy: false }))
    app.use(cors())
  } else {
    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          connectSrc: ["'self'", 'https://cdn.jsdelivr.net'],
          imgSrc: ["'self'", 'data:', 'blob:'],
          mediaSrc: ["'self'", 'blob:'],
          scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', "'wasm-unsafe-eval'"],
          workerSrc: ["'self'", 'blob:', 'https://cdn.jsdelivr.net'],
          childSrc: ["'self'", 'blob:'],
        },
      },
    }))
    app.use(cors({ origin: `https://${config.domain}`, credentials: true }))
  }

  app.use(compression())
  app.use(express.json({ limit: '10mb' }))
  app.use('/api/', rateLimit(config.rateLimit))
  app.use('/api/auth/', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }))

  app.use((req, res, next) => {
    const start = Date.now()
    res.on('finish', () => {
      if (!req.path.startsWith('/assets'))
        console.log(`[http] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`)
    })
    next()
  })

  function requireAuth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '')
    if (!token) return res.status(401).json({ error: 'Authentication required' })
    const session = sessionStore.get(token)
    if (!session) return res.status(401).json({ error: 'Invalid or expired session' })
    req.user = session.user; req.sessionToken = token; next()
  }

  // ========================================================================
  // CAPTCHA (Cap proof-of-work)
  // ========================================================================

  app.post('/api/captcha/challenge', async (req, res) => {
    try {
      const challenge = await cap.createChallenge({
        challengeCount: 256,
        challengeDifficulty: 5,
        expiresMs: 300000,
      })
      res.json(challenge)
    } catch (err) { console.error('[captcha]', err); res.status(500).json({ error: 'Challenge creation failed' }) }
  })

  app.post('/api/captcha/redeem', async (req, res) => {
    try {
      const { token, solutions } = req.body
      if (!token || !solutions) return res.status(400).json({ success: false })
      const result = await cap.redeemChallenge({ token, solutions })
      res.json(result)
    } catch (err) { console.error('[captcha]', err); res.status(400).json({ success: false, error: 'Verification failed' }) }
  })

  // ========================================================================
  // Auth Routes
  // ========================================================================

  app.post('/api/auth/register', async (req, res) => {
    try {
      const { usernameHash, signingPublicKey, encryptionPublicKey, fingerprint, captchaToken } = req.body
      if (!usernameHash || !/^[a-f0-9]{64}$/.test(usernameHash))
        return res.status(400).json({ error: 'Valid usernameHash required (SHA-256 hex)' })

      // Verify CAPTCHA token
      if (!captchaToken) return res.status(400).json({ error: 'CAPTCHA required' })
      const captchaResult = await cap.validateToken(captchaToken)
      if (!captchaResult.success) return res.status(403).json({ error: 'CAPTCHA verification failed. Please try again.' })

      // The hash IS the username — server never sees plaintext
      if (await userStore.getByUsername(usernameHash))
        return res.status(409).json({ error: 'Identity already registered' })
      if (!signingPublicKey || !encryptionPublicKey)
        return res.status(400).json({ error: 'Both public keys required' })
      const user = await userStore.create({
        username: usernameHash, domain: config.domain, signingPublicKey, encryptionPublicKey,
        fingerprint: fingerprint || null, usernameHash,
        profileCid: null, quotaUsed: 0, quotaLimit: config.userQuotaBytes,
        feedKeyVersion: 1, createdAt: Date.now(),
      })
      res.status(201).json({ user: sanitizeUser(user), token: sessionStore.create(user) })
    } catch (err) { console.error('[auth]', err); res.status(500).json({ error: 'Registration failed' }) }
  })

  // Resolve a user by hash or plaintext username (for backwards compat with unmigrated users)
  async function resolveUser(identifier) {
    // Try as direct username first (works for both hash-as-username and legacy plaintext)
    let user = await userStore.getByUsername(identifier)
    if (user) return user
    // Try hash lookup (for users whose username_hash column is set but username is still plaintext)
    user = await userStore.getByHash(identifier)
    return user
  }

  app.post('/api/auth/challenge', async (req, res) => {
    const user = await resolveUser(req.body.username)
    if (!user) return res.status(404).json({ error: 'User not found' })
    const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64')
    sessionStore.storeChallenge(user.username, nonce)
    res.json({ nonce, expiresIn: 300 })
  })

  app.post('/api/auth/verify', async (req, res) => {
    try {
      const { username, signature } = req.body
      const user = await resolveUser(username)
      if (!user) return res.status(404).json({ error: 'User not found' })
      const nonce = sessionStore.getChallenge(user.username)
      if (!nonce) return res.status(400).json({ error: 'No pending challenge' })
      const pubKey = await crypto.subtle.importKey(
        'raw', Uint8Array.from(atob(user.signingPublicKey), c => c.charCodeAt(0)),
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
      )
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, pubKey,
        Uint8Array.from(atob(signature), c => c.charCodeAt(0)),
        new TextEncoder().encode(nonce)
      )
      if (!valid) return res.status(401).json({ error: 'Invalid signature' })
      sessionStore.clearChallenge(user.username)
      res.json({ token: sessionStore.create(user), user: sanitizeUser(user) })
    } catch (err) { console.error('[auth]', err); res.status(500).json({ error: 'Auth failed' }) }
  })

  app.post('/api/auth/logout', requireAuth, (req, res) => {
    sessionStore.destroy(req.sessionToken); res.json({ ok: true })
  })

  // Update public keys (for password change / key rotation)
  app.put('/api/auth/keys', requireAuth, async (req, res) => {
    try {
      const { signingPublicKey, encryptionPublicKey, fingerprint, feedKeyVersion } = req.body
      if (!signingPublicKey || !encryptionPublicKey)
        return res.status(400).json({ error: 'Both public keys required' })
      await userStore.update(req.user.username, {
        signingPublicKey, encryptionPublicKey,
        fingerprint: fingerprint || null,
        feedKeyVersion: feedKeyVersion || req.user.feedKeyVersion,
      })
      res.json({ ok: true })
    } catch (err) { res.status(500).json({ error: 'Failed to update keys' }) }
  })

  // ========================================================================
  // Vault (encrypted friends list + feed keys)
  // ========================================================================

  app.get('/api/vault', requireAuth, async (req, res) => {
    try {
      const vault = await userStore.getVault(req.user.username)
      res.json({ vault })
    } catch { res.status(500).json({ error: 'Failed to get vault' }) }
  })

  app.put('/api/vault', requireAuth, async (req, res) => {
    try {
      const { vault } = req.body
      if (!vault) return res.status(400).json({ error: 'vault required' })
      await userStore.setVault(req.user.username, vault)
      res.json({ ok: true })
    } catch { res.status(500).json({ error: 'Failed to save vault' }) }
  })

  // ========================================================================
  // Feed Key Exchange
  // ========================================================================

  // Store an ECDH-encrypted feed key for a recipient
  app.post('/api/key-exchange', requireAuth, async (req, res) => {
    try {
      const { toUsername, encryptedPayload } = req.body
      if (!toUsername || !encryptedPayload)
        return res.status(400).json({ error: 'toUsername and encryptedPayload required' })
      await userStore.storePendingKeyExchange(
        req.user.username, config.domain, toUsername, encryptedPayload
      )
      res.json({ ok: true })
    } catch { res.status(500).json({ error: 'Failed' }) }
  })

  // Retrieve pending key exchanges for the current user
  app.get('/api/key-exchange', requireAuth, async (req, res) => {
    try {
      const pending = await userStore.getPendingKeyExchanges(req.user.username)
      res.json({ exchanges: pending.map(e => ({
        id: e.id,
        fromUser: e.from_user,
        fromDomain: e.from_domain,
        encryptedPayload: e.encrypted_payload,
        createdAt: e.created_at,
      })) })
    } catch { res.json({ exchanges: [] }) }
  })

  // Acknowledge / delete a processed key exchange
  app.delete('/api/key-exchange/:id', requireAuth, async (req, res) => {
    try {
      await userStore.removePendingKeyExchange(parseInt(req.params.id))
      res.json({ ok: true })
    } catch { res.status(500).json({ error: 'Failed' }) }
  })

  // ========================================================================
  // Content Routes (local filesystem)
  // ========================================================================

  app.post('/api/content/upload', requireAuth, upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file' })
      const fileData = readFileSync(req.file.path)
      // Clean up temp file
      try { unlinkSync(req.file.path) } catch {}
      if (req.user.quotaLimit > 0) {
        const newUsage = req.user.quotaUsed + fileData.length
        if (newUsage > req.user.quotaLimit) {
          return res.status(413).json({ error: 'Quota exceeded', remainingMB: ((req.user.quotaLimit - req.user.quotaUsed) / 1048576).toFixed(1) })
        }
        await userStore.update(req.user.username, { quotaUsed: newUsage })
      }
      const { hash, size } = storeContent(fileData)
      await userStore.addContent(req.user.username, hash, size, req.file.mimetype || 'unknown')

      res.json({ hash, size, url: `https://${config.domain}/content/${hash}` })
    } catch (err) { console.error('[upload]', err); if (req.file?.path) try { unlinkSync(req.file.path) } catch {}; res.status(500).json({ error: 'Upload failed' }) }
  })

  // Track last post time per user for rate limiting
  const lastPostTime = new Map()
  const POST_COOLDOWN_MS = 2 * 60 * 1000 // 2 minutes

  // Upload an encrypted post envelope + optional linked content
  app.post('/api/posts', requireAuth, async (req, res) => {
    try {
      const { envelope, contentBlob } = req.body
      if (!envelope) return res.status(400).json({ error: 'envelope required' })

      // Rate limit: one post every 2 minutes
      const lastTime = lastPostTime.get(req.user.username) || 0
      const elapsed = Date.now() - lastTime
      if (elapsed < POST_COOLDOWN_MS) {
        const waitSec = Math.ceil((POST_COOLDOWN_MS - elapsed) / 1000)
        return res.status(429).json({ error: `Please wait ${waitSec} seconds before posting again` })
      }

      let contentHash = null

      // If there's a linked content blob (> 200 bytes or attachment), store it
      if (contentBlob) {
        const buf = Buffer.from(contentBlob, 'base64')
        const newUsage = req.user.quotaUsed + buf.length
        if (newUsage > req.user.quotaLimit)
          return res.status(413).json({ error: 'Quota exceeded' })
        const stored = storeContent(buf)
        contentHash = stored.hash
        await userStore.update(req.user.username, { quotaUsed: newUsage })
        await userStore.addContent(req.user.username, contentHash, stored.size, 'application/octet-stream')
      }

      // Store the envelope (small, always < 1KB)
      const envelopeStr = typeof envelope === 'string' ? envelope : JSON.stringify(envelope)
      const envelopeSize = Buffer.byteLength(envelopeStr)
      const newUsage = req.user.quotaUsed + envelopeSize
      await userStore.update(req.user.username, { quotaUsed: newUsage })

      const postId = await userStore.addPost(
        req.user.username, config.domain,
        contentHash, envelopeStr, Date.now()
      )

      lastPostTime.set(req.user.username, Date.now())

      res.json({
        id: postId,
        contentHash,
        url: contentHash ? `https://${config.domain}/content/${contentHash}` : null,
      })
    } catch (err) { console.error('[post]', err); res.status(500).json({ error: 'Post failed' }) }
  })

  app.delete('/api/content/:hash', requireAuth, async (req, res) => {
    try {
      if (!/^[a-f0-9]{64}$/.test(req.params.hash)) return res.status(400).json({ error: 'Invalid hash' })
      const size = getContentSize(req.params.hash)
      if (!size) return res.status(404).json({ error: 'Not found' })
      deleteContent(req.params.hash)
      await userStore.removeContent(req.user.username, req.params.hash)
      const newUsage = Math.max(0, req.user.quotaUsed - size)
      await userStore.update(req.user.username, { quotaUsed: newUsage })
      res.json({ ok: true, hash: req.params.hash, reclaimedBytes: size })
    } catch (err) { console.error('[delete]', err); res.status(500).json({ error: 'Delete failed' }) }
  })

  app.get('/api/content/quota', requireAuth, (req, res) => {
    res.json({
      used: req.user.quotaUsed, limit: req.user.quotaLimit,
      remaining: req.user.quotaLimit - req.user.quotaUsed,
      usedMB: (req.user.quotaUsed / 1048576).toFixed(1),
      limitMB: (req.user.quotaLimit / 1048576).toFixed(0),
    })
  })

  // ========================================================================
  // Content serving (public, cacheable)
  // ========================================================================

  app.get('/content/:hash', (req, res) => {
    if (!/^[a-f0-9]{64}$/.test(req.params.hash)) return res.status(400).json({ error: 'Invalid hash' })
    const data = getContent(req.params.hash)
    if (!data) return res.status(404).json({ error: 'Not found' })
    // All content is encrypted, serve as opaque binary
    res.setHeader('Content-Type', 'application/octet-stream')
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
    res.setHeader('X-Content-Hash', req.params.hash)
    res.send(data)
  })

  // ========================================================================
  // Feed (bloom filter)
  // ========================================================================

  app.post('/api/feed', requireAuth, async (req, res) => {
    try {
      const { bloom, bloomHashCount, before, limit } = req.body
      const beforeTs = parseInt(before) || Date.now()
      const lim = Math.min(parseInt(limit) || 50, 100)

      if (!bloom || !bloomHashCount) {
        return res.status(400).json({ error: 'bloom filter required' })
      }

      const posts = await userStore.getFeedWithBloom(bloom, bloomHashCount, beforeTs, lim)

      // Get comment counts for all posts in this batch
      const postIds = posts.map(p => p.id)
      const commentCounts = await userStore.getCommentCounts(postIds)

      // Resolve username hashes for post authors
      const hashCache = {}
      for (const p of posts) {
        if (!hashCache[p.username]) {
          const u = await userStore.getByUsername(p.username)
          hashCache[p.username] = u?.usernameHash || null
        }
      }

      const result = posts.map(p => ({
        id: p.id,
        author: p.username,
        authorHash: hashCache[p.username] || null,
        domain: p.domain,
        envelope: p.envelope,
        contentHash: p.content_hash,
        createdAt: p.created_at,
        commentCount: commentCounts[p.id] || 0,
      }))

      const cursor = result.length ? result[result.length - 1].createdAt : null
      const userCount = await userStore.count()
      res.json({ posts: result, cursor, userCount })
    } catch (err) { console.error('[feed]', err); res.status(500).json({ error: 'Feed failed' }) }
  })

  // ========================================================================
  // Comments
  // ========================================================================

  // Post a comment (encrypted with the post author's feed key by the client)
  app.post('/api/posts/:postId/comments', requireAuth, async (req, res) => {
    try {
      const { encryptedContent, iv } = req.body
      if (!encryptedContent || !iv)
        return res.status(400).json({ error: 'encryptedContent and iv required' })

      // Verify the post exists
      const post = userStore.db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.postId)
      if (!post) return res.status(404).json({ error: 'Post not found' })

      const commentId = await userStore.addComment(
        req.params.postId, post.username,
        req.user.username, config.domain,
        encryptedContent, iv, Date.now()
      )

      res.json({ id: commentId, ok: true })
    } catch (err) { console.error('[comment]', err); res.status(500).json({ error: 'Comment failed' }) }
  })

  // Get comments for a post
  app.get('/api/posts/:postId/comments', requireAuth, async (req, res) => {
    try {
      const comments = await userStore.getComments(req.params.postId)
      // Resolve username hashes for comment authors
      const hashCache = {}
      for (const c of comments) {
        if (!hashCache[c.username]) {
          const u = await userStore.getByUsername(c.username)
          hashCache[c.username] = u?.usernameHash || null
        }
      }
      res.json({
        comments: comments.map(c => ({
          id: c.id,
          postId: c.post_id,
          author: c.username,
          authorHash: hashCache[c.username] || null,
          domain: c.domain,
          encryptedContent: c.encrypted_content,
          iv: c.iv,
          createdAt: c.created_at,
        }))
      })
    } catch (err) { res.status(500).json({ error: 'Failed to load comments' }) }
  })

  // Delete a comment (only the comment author can delete)
  app.delete('/api/posts/:postId/comments/:commentId', requireAuth, async (req, res) => {
    try {
      const deleted = await userStore.deleteComment(req.params.commentId, req.user.username)
      if (!deleted) return res.status(404).json({ error: 'Comment not found or not yours' })
      res.json({ ok: true })
    } catch (err) { console.error('[delete-comment]', err); res.status(500).json({ error: 'Delete failed' }) }
  })

  // Edit a post (only the author can edit)
  app.put('/api/posts/:postId', requireAuth, async (req, res) => {
    try {
      const { envelope } = req.body
      if (!envelope) return res.status(400).json({ error: 'envelope required' })
      const envelopeStr = typeof envelope === 'string' ? envelope : JSON.stringify(envelope)
      const updated = await userStore.updatePostEnvelope(req.params.postId, req.user.username, envelopeStr)
      if (!updated) return res.status(404).json({ error: 'Post not found or not yours' })
      res.json({ ok: true })
    } catch (err) { console.error('[edit-post]', err); res.status(500).json({ error: 'Edit failed' }) }
  })

  // Edit a comment (only the comment author can edit)
  app.put('/api/posts/:postId/comments/:commentId', requireAuth, async (req, res) => {
    try {
      const { encryptedContent, iv } = req.body
      if (!encryptedContent || !iv) return res.status(400).json({ error: 'encryptedContent and iv required' })
      const updated = await userStore.updateComment(req.params.commentId, req.user.username, encryptedContent, iv)
      if (!updated) return res.status(404).json({ error: 'Comment not found or not yours' })
      res.json({ ok: true })
    } catch (err) { console.error('[edit-comment]', err); res.status(500).json({ error: 'Edit failed' }) }
  })

  // Delete a post (only the author can delete)
  app.delete('/api/posts/:postId', requireAuth, async (req, res) => {
    try {
      const contentHash = await userStore.deletePost(req.params.postId, req.user.username)
      if (contentHash === null) return res.status(404).json({ error: 'Post not found or not yours' })
      // Delete content blob if it exists
      if (contentHash) {
        deleteContent(contentHash)
        await userStore.removeContent(req.user.username, contentHash)
      }
      res.json({ ok: true })
    } catch (err) { console.error('[delete-post]', err); res.status(500).json({ error: 'Delete failed' }) }
  })

  // ========================================================================
  // Friends & Notifications
  // ========================================================================

  // Friend request — server only relays, doesn't store friendship
  app.post('/api/friends/request', requireAuth, async (req, res) => {
    try {
      const [username, domain] = (req.body.address || '').split('@')
      if (!username || !domain) return res.status(400).json({ error: 'Use username@domain' })

      let target
      if (domain === config.domain) {
        target = await resolveUser(username)
      } else {
        target = await resolveRemoteUser(username, domain)
      }
      if (!target) return res.status(404).json({ error: 'User not found' })

      await notifications.push(`${username}@${domain}`, {
        type: 'friend_request',
        from: `${req.user.username}@${config.domain}`,
        fromKeys: {
          signing: req.user.signingPublicKey,
          encryption: req.user.encryptionPublicKey,
          fingerprint: req.user.fingerprint,
        },
        timestamp: Date.now(),
      }, { deduplicateBy: 'from' })

      if (domain !== config.domain) {
        try {
          await fetch(`https://${domain}/.well-known/friendsforum/notify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 'friend_request', to: username,
              from: `${req.user.username}@${config.domain}`,
              fromKeys: {
                signing: req.user.signingPublicKey,
                encryption: req.user.encryptionPublicKey,
                fingerprint: req.user.fingerprint,
              },
            }),
            signal: AbortSignal.timeout(10000),
          })
        } catch (err) { console.warn(`[federation] Notify ${domain} failed: ${err.message}`) }
      }

      res.json({ ok: true, sent: req.body.address })
    } catch { res.status(500).json({ error: 'Failed' }) }
  })

  // Accept friend — the actual friendship is managed client-side in the vault.
  // Server just relays notifications and key exchange blobs.
  app.post('/api/friends/accept', requireAuth, async (req, res) => {
    try {
      const { from, notificationId, keyExchangePayload } = req.body
      if (!from) return res.status(400).json({ error: 'from address required' })

      const [fromUsername, fromDomain] = from.split('@')
      if (!fromUsername || !fromDomain) return res.status(400).json({ error: 'Invalid from address' })

      // Store the ECDH-encrypted feed key for the requester to pick up
      if (keyExchangePayload) {
        if (fromDomain === config.domain) {
          await userStore.storePendingKeyExchange(
            req.user.username, config.domain, fromUsername, keyExchangePayload
          )
        } else {
          try {
            await fetch(`https://${fromDomain}/.well-known/friendsforum/key-exchange`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                fromUser: req.user.username,
                fromDomain: config.domain,
                toUser: fromUsername,
                encryptedPayload: keyExchangePayload,
              }),
              signal: AbortSignal.timeout(10000),
            })
          } catch {}
        }
      }

      // Notify the requester that their request was accepted
      await notifications.push(`${fromUsername}@${fromDomain}`, {
        type: 'friend_accepted',
        from: `${req.user.username}@${config.domain}`,
        fromKeys: {
          signing: req.user.signingPublicKey,
          encryption: req.user.encryptionPublicKey,
          fingerprint: req.user.fingerprint,
        },
        timestamp: Date.now(),
      })

      // Dismiss the original notification
      if (notificationId) {
        await notifications.remove(`${req.user.username}@${config.domain}`, notificationId)
      }

      res.json({ ok: true })
    } catch (err) { console.error('[friends]', err); res.status(500).json({ error: 'Accept failed' }) }
  })

  app.get('/api/notifications', requireAuth, async (req, res) => {
    res.json({ notifications: await notifications.getAll(`${req.user.username}@${config.domain}`) })
  })

  app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
    await notifications.remove(`${req.user.username}@${config.domain}`, req.params.id)
    res.json({ ok: true })
  })

  // ========================================================================
  // Chats (E2E encrypted DMs)
  // ========================================================================

  // Send a message (friends can send directly, non-friends need accepted chat request)
  app.post('/api/chats/:username/messages', requireAuth, async (req, res) => {
    try {
      const { encryptedContent, iv } = req.body
      if (!encryptedContent || !iv) return res.status(400).json({ error: 'encryptedContent and iv required' })
      const target = await resolveUser(req.params.username)
      if (!target) return res.status(404).json({ error: 'User not found' })
      const id = await userStore.addMessage(req.user.username, req.params.username, encryptedContent, iv)
      res.json({ id, ok: true })
    } catch (err) { console.error('[chat]', err); res.status(500).json({ error: 'Send failed' }) }
  })

  // Send a chat request to a non-friend
  app.post('/api/chats/:username/request', requireAuth, async (req, res) => {
    try {
      const target = await resolveUser(req.params.username)
      if (!target) return res.status(404).json({ error: 'User not found' })
      await notifications.push(`${req.params.username}@${config.domain}`, {
        type: 'chat_request',
        from: `${req.user.username}@${config.domain}`,
        fromKeys: {
          signing: req.user.signingPublicKey,
          encryption: req.user.encryptionPublicKey,
        },
        timestamp: Date.now(),
      }, { deduplicateBy: 'from' })
      res.json({ ok: true })
    } catch (err) { console.error('[chat-request]', err); res.status(500).json({ error: 'Failed' }) }
  })

  // Get messages in a conversation
  app.get('/api/chats/:username/messages', requireAuth, async (req, res) => {
    try {
      const before = parseInt(req.query.before) || Date.now()
      const limit = Math.min(parseInt(req.query.limit) || 50, 100)
      const messages = await userStore.getConversation(req.user.username, req.params.username, before, limit)
      res.json({
        messages: messages.map(m => ({
          id: m.id,
          from: m.from_user,
          to: m.to_user,
          encryptedContent: m.encrypted_content,
          iv: m.iv,
          createdAt: m.created_at,
        }))
      })
    } catch (err) { res.status(500).json({ error: 'Failed to load messages' }) }
  })

  // Get conversation list
  app.get('/api/chats', requireAuth, async (req, res) => {
    try {
      const conversations = await userStore.getConversationList(req.user.username)
      res.json({ conversations })
    } catch (err) { res.status(500).json({ error: 'Failed' }) }
  })

  // ========================================================================
  // Group Chats (E2E encrypted)
  // ========================================================================

  // Create a group chat
  app.post('/api/groups', requireAuth, async (req, res) => {
    try {
      const { nameEncrypted, nameIv, members } = req.body
      if (!nameEncrypted || !nameIv || !members || !Array.isArray(members) || members.length === 0)
        return res.status(400).json({ error: 'nameEncrypted, nameIv, and members required' })
      // Validate all members exist
      for (const m of members) {
        if (!m.username || !m.encryptedKey || !m.keyIv) return res.status(400).json({ error: 'Each member needs username, encryptedKey, keyIv' })
      }
      // Ensure creator is in members — auto-fix if client sent plaintext username
      if (!members.find(m => m.username === req.user.username)) {
        const creatorEntry = members.find(m => createHash('sha256').update(m.username).digest('hex') === req.user.username)
        if (creatorEntry) creatorEntry.username = req.user.username
        else return res.status(400).json({ error: 'Creator must be a member' })
      }
      const id = `g-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
      await userStore.createGroupChat(id, nameEncrypted, nameIv, req.user.username, members)
      res.json({ id, ok: true })
    } catch (err) { console.error('[group-create]', err); res.status(500).json({ error: 'Failed to create group' }) }
  })

  // List groups the user is in
  app.get('/api/groups', requireAuth, async (req, res) => {
    try {
      const groups = await userStore.getGroupsForUser(req.user.username)
      res.json({ groups: groups.map(g => ({ id: g.id, nameEncrypted: g.name_encrypted, nameIv: g.name_iv, creator: g.creator, encryptedKey: g.encrypted_key, keyIv: g.key_iv, createdAt: g.created_at, updatedAt: g.updated_at })) })
    } catch (err) { res.status(500).json({ error: 'Failed' }) }
  })

  // Get group details + members
  app.get('/api/groups/:id', requireAuth, async (req, res) => {
    try {
      if (!await userStore.isGroupMember(req.params.id, req.user.username)) return res.status(403).json({ error: 'Not a member' })
      const group = await userStore.getGroupChat(req.params.id)
      if (!group) return res.status(404).json({ error: 'Group not found' })
      const members = await userStore.getGroupMembers(req.params.id)
      const myKey = await userStore.getGroupMemberKey(req.params.id, req.user.username)
      res.json({
        id: group.id, nameEncrypted: group.name_encrypted, nameIv: group.name_iv, creator: group.creator,
        encryptedKey: myKey?.encrypted_key, keyIv: myKey?.key_iv,
        members: members.map(m => ({ username: m.username, addedAt: m.added_at })),
        createdAt: group.created_at, updatedAt: group.updated_at,
      })
    } catch (err) { res.status(500).json({ error: 'Failed' }) }
  })

  // Add members to group (creator only)
  app.post('/api/groups/:id/members', requireAuth, async (req, res) => {
    try {
      const group = await userStore.getGroupChat(req.params.id)
      if (!group) return res.status(404).json({ error: 'Group not found' })
      if (group.creator !== req.user.username) return res.status(403).json({ error: 'Only creator can add members' })
      const { members } = req.body
      if (!members || !Array.isArray(members)) return res.status(400).json({ error: 'members array required' })
      await userStore.addGroupMembers(req.params.id, members)
      res.json({ ok: true })
    } catch (err) { res.status(500).json({ error: 'Failed' }) }
  })

  // Send message to group
  app.post('/api/groups/:id/messages', requireAuth, async (req, res) => {
    try {
      if (!await userStore.isGroupMember(req.params.id, req.user.username)) return res.status(403).json({ error: 'Not a member' })
      const { encryptedContent, iv } = req.body
      if (!encryptedContent || !iv) return res.status(400).json({ error: 'encryptedContent and iv required' })
      const id = `gm-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
      await userStore.addGroupMessage(id, req.params.id, req.user.username, encryptedContent, iv)
      res.json({ id, ok: true })
    } catch (err) { console.error('[group-msg]', err); res.status(500).json({ error: 'Send failed' }) }
  })

  // Get group messages
  app.get('/api/groups/:id/messages', requireAuth, async (req, res) => {
    try {
      if (!await userStore.isGroupMember(req.params.id, req.user.username)) return res.status(403).json({ error: 'Not a member' })
      const before = parseInt(req.query.before) || Date.now()
      const limit = Math.min(parseInt(req.query.limit) || 50, 100)
      const messages = await userStore.getGroupMessages(req.params.id, before, limit)
      res.json({
        messages: messages.map(m => ({
          id: m.id, groupId: m.group_id, from: m.from_user,
          encryptedContent: m.encrypted_content, iv: m.iv, createdAt: m.created_at,
        }))
      })
    } catch (err) { res.status(500).json({ error: 'Failed' }) }
  })

  // ========================================================================
  // Profile (public keys are public, everything else encrypted)
  // ========================================================================

  app.get('/api/profile/:username', async (req, res) => {
    try {
      const user = await resolveUser(req.params.username)
      if (!user) return res.status(404).json({ error: 'User not found' })
      res.json({
        username: user.username,
        usernameHash: user.usernameHash || null,
        domain: user.domain,
        signingPublicKey: user.signingPublicKey,
        encryptionPublicKey: user.encryptionPublicKey,
        fingerprint: user.fingerprint,
        feedKeyVersion: user.feedKeyVersion,
      })
    } catch (err) { res.status(500).json({ error: err.message }) }
  })

  // ========================================================================
  // Password Change & Key Revocation
  // ========================================================================

  const KEY_TRANSITION_MS = 30 * 24 * 60 * 60 * 1000 // 1 month

  app.post('/api/auth/change-password', requireAuth, async (req, res) => {
    try {
      const { newSigningPublicKey, newEncryptionPublicKey, newFingerprint, newFeedKeyVersion, newVault } = req.body
      if (!newSigningPublicKey || !newEncryptionPublicKey)
        return res.status(400).json({ error: 'New public keys required' })

      // Store current keys in history with 1-month expiry
      await userStore.addKeyHistory(
        req.user.username,
        req.user.signingPublicKey,
        req.user.encryptionPublicKey,
        req.user.fingerprint,
        req.user.feedKeyVersion || 1,
        Date.now() + KEY_TRANSITION_MS
      )

      // Update to new keys
      await userStore.update(req.user.username, {
        signingPublicKey: newSigningPublicKey,
        encryptionPublicKey: newEncryptionPublicKey,
        fingerprint: newFingerprint,
        feedKeyVersion: newFeedKeyVersion || (req.user.feedKeyVersion || 1) + 1,
        encryptedVault: newVault || null,
      })

      // Invalidate old session, create new one
      sessionStore.destroy(req.sessionToken)
      const updatedUser = await userStore.getByUsername(req.user.username)
      const newToken = sessionStore.create(updatedUser)

      res.json({ ok: true, token: newToken, user: sanitizeUser(updatedUser), transitionExpiresAt: Date.now() + KEY_TRANSITION_MS })
    } catch (err) { console.error('[password-change]', err); res.status(500).json({ error: 'Failed' }) }
  })

  // Emergency revoke — immediately invalidates all old keys
  app.post('/api/auth/revoke-keys', requireAuth, async (req, res) => {
    try {
      await userStore.revokeAllKeyHistory(req.user.username)
      res.json({ ok: true, message: 'All previous keys revoked. Friends who haven\'t updated will need to re-friend.' })
    } catch (err) { console.error('[revoke]', err); res.status(500).json({ error: 'Revoke failed' }) }
  })

  // Get key history for a user (public — needed for friends to verify key changes)
  app.get('/api/profile/:username/keys', async (req, res) => {
    try {
      const user = await resolveUser(req.params.username)
      if (!user) return res.status(404).json({ error: 'User not found' })
      const history = await userStore.getActiveKeyHistory(user.username)
      res.json({
        current: {
          signingPublicKey: user.signingPublicKey,
          encryptionPublicKey: user.encryptionPublicKey,
          fingerprint: user.fingerprint,
          feedKeyVersion: user.feedKeyVersion,
        },
        previous: history,
      })
    } catch { res.status(500).json({ error: 'Failed' }) }
  })

  // ========================================================================
  // Federation: .well-known
  // ========================================================================

  app.get('/.well-known/webfinger', async (req, res) => {
    const resource = req.query.resource
    if (!resource?.startsWith('acct:')) return res.status(400).json({ error: 'Invalid resource' })
    const [username, domain] = resource.slice(5).split('@')
    if (domain !== config.domain) return res.status(404).json({ error: 'Wrong domain' })
    const user = await resolveUser(username)
    if (!user) return res.status(404).json({ error: 'Not found' })
    res.setHeader('Content-Type', 'application/jrd+json')
    res.json({
      subject: resource,
      links: [{
        rel: 'https://friendsforum.net/ns/profile',
        type: 'application/json',
        href: `https://${config.domain}/.well-known/friendsforum/users/${user.username}`,
      }],
    })
  })

  app.get('/.well-known/friendsforum/users/:username', async (req, res) => {
    const user = await resolveUser(req.params.username)
    if (!user) return res.status(404).json({ error: 'Not found' })
    res.json({
      username: user.username, domain: config.domain,
      signingPublicKey: user.signingPublicKey,
      encryptionPublicKey: user.encryptionPublicKey,
      fingerprint: user.fingerprint,
      feedKeyVersion: user.feedKeyVersion,
    })
  })

  app.get('/.well-known/friendsforum/content/:hash', (req, res) => {
    if (!/^[a-f0-9]{64}$/.test(req.params.hash)) return res.status(400).json({ error: 'Invalid hash' })
    const data = getContent(req.params.hash)
    if (!data) return res.status(404).json({ error: 'Not found' })
    res.setHeader('Content-Type', 'application/octet-stream')
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
    res.send(data)
  })

  app.post('/.well-known/friendsforum/notify', async (req, res) => {
    const { type, to, from, fromKeys } = req.body
    const target = await resolveUser(to)
    if (!target) return res.status(404).json({ error: 'Not found' })
    await notifications.push(`${to}@${config.domain}`, { type, from, fromKeys, timestamp: Date.now() })
    res.status(202).json({ accepted: true })
  })

  app.post('/.well-known/friendsforum/key-exchange', async (req, res) => {
    const { fromUser, fromDomain, toUser, encryptedPayload } = req.body
    const target = await resolveUser(toUser)
    if (!target) return res.status(404).json({ error: 'Not found' })
    await userStore.storePendingKeyExchange(fromUser, fromDomain, toUser, encryptedPayload)
    res.status(202).json({ accepted: true })
  })

  app.get('/.well-known/friendsforum/nodeinfo', async (req, res) => {
    res.json({
      software: { name: 'friendsforum', version: '0.2.0', repository: 'https://codeberg.org/rltvty2/friendsforum' },
      domain: config.domain,
      protocols: ['friendsforum/1.0', 'webfinger'],
      storage: { backend: 'local' },
      usage: { users: await userStore.count() },
      openRegistrations: true,
    })
  })

  // ========================================================================
  // Friend Requests (hash-based)
  // ========================================================================

  // Send a friend request to a hashed identity
  app.post('/api/friend-request', requireAuth, async (req, res) => {
    try {
      const { toHash, toDomain, payload } = req.body
      if (!toHash || !/^[a-f0-9]{64}$/.test(toHash))
        return res.status(400).json({ error: 'Valid toHash required' })
      if (!payload)
        return res.status(400).json({ error: 'payload required' })

      const senderHash = req.user.usernameHash
      if (!senderHash) return res.status(400).json({ error: 'Sender has not migrated to hashed identity' })

      const targetDomain = toDomain || config.domain

      if (targetDomain === config.domain) {
        // Local: verify target exists
        if (!await userStore.hashExists(toHash))
          return res.status(404).json({ error: 'User not found' })
        const id = await userStore.createFriendRequest(
          senderHash, config.domain, toHash,
          typeof payload === 'string' ? payload : JSON.stringify(payload)
        )
        res.json({ ok: true, id })
      } else {
        // Federated: forward to target domain
        try {
          const r = await fetch(`https://${targetDomain}/.well-known/friendsforum/friend-request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              fromHash: senderHash, fromDomain: config.domain,
              toHash, payload,
            }),
            signal: AbortSignal.timeout(10000),
          })
          if (!r.ok) return res.status(502).json({ error: 'Remote server rejected request' })
          res.json({ ok: true, federated: true })
        } catch (err) {
          console.warn(`[federation] Friend request to ${targetDomain} failed: ${err.message}`)
          res.status(502).json({ error: 'Could not reach remote server' })
        }
      }
    } catch (err) { console.error('[friend-request]', err); res.status(500).json({ error: 'Failed' }) }
  })

  // Get pending incoming friend requests for the authenticated user
  app.get('/api/friend-requests', requireAuth, async (req, res) => {
    try {
      const userHash = req.user.usernameHash
      if (!userHash) return res.json({ requests: [] })
      const requests = await userStore.getPendingFriendRequests(userHash)
      res.json({
        requests: requests.map(r => ({
          id: r.id,
          fromHash: r.from_hash,
          fromDomain: r.from_domain,
          payload: r.payload,
          createdAt: r.created_at,
        }))
      })
    } catch (err) { console.error('[friend-requests]', err); res.status(500).json({ error: 'Failed' }) }
  })

  // Accept a friend request
  app.post('/api/friend-request/:id/accept', requireAuth, async (req, res) => {
    try {
      const fr = await userStore.getFriendRequest(parseInt(req.params.id))
      if (!fr) return res.status(404).json({ error: 'Friend request not found' })
      if (fr.to_hash !== req.user.usernameHash)
        return res.status(403).json({ error: 'Not your friend request' })
      if (fr.status !== 'pending')
        return res.status(400).json({ error: 'Already processed' })

      await userStore.updateFriendRequestStatus(fr.id, 'accepted')

      // If the requester provided a key exchange payload in acceptance, store it
      const { keyExchangePayload } = req.body || {}
      if (keyExchangePayload) {
        if (fr.from_domain === config.domain) {
          // Local: store key exchange for the requester to pick up
          const fromUser = await userStore.getByHash(fr.from_hash)
          if (fromUser) {
            await userStore.storePendingKeyExchange(
              req.user.username, config.domain, fromUser.username, keyExchangePayload
            )
          }
        } else {
          // Federated: forward key exchange
          try {
            await fetch(`https://${fr.from_domain}/.well-known/friendsforum/key-exchange`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                fromUser: req.user.username,
                fromDomain: config.domain,
                toHash: fr.from_hash,
                encryptedPayload: keyExchangePayload,
              }),
              signal: AbortSignal.timeout(10000),
            })
          } catch {}
        }
      }

      // Notify the requester that their request was accepted (triggers them to send their feed key back)
      if (fr.from_domain === config.domain) {
        const fromUser = await userStore.getByHash(fr.from_hash) || await userStore.getByUsername(fr.from_hash)
        if (fromUser) {
          await notifications.push(`${fromUser.username}@${config.domain}`, {
            type: 'friend_accepted',
            from: `${req.user.username}@${config.domain}`,
            fromKeys: {
              signing: req.user.signingPublicKey,
              encryption: req.user.encryptionPublicKey,
              fingerprint: req.user.fingerprint,
            },
            timestamp: Date.now(),
          })
        }
      }

      res.json({ ok: true })
    } catch (err) { console.error('[friend-request-accept]', err); res.status(500).json({ error: 'Failed' }) }
  })

  // Reject a friend request
  app.post('/api/friend-request/:id/reject', requireAuth, async (req, res) => {
    try {
      const fr = await userStore.getFriendRequest(parseInt(req.params.id))
      if (!fr) return res.status(404).json({ error: 'Friend request not found' })
      if (fr.to_hash !== req.user.usernameHash)
        return res.status(403).json({ error: 'Not your friend request' })
      if (fr.status !== 'pending')
        return res.status(400).json({ error: 'Already processed' })
      await userStore.updateFriendRequestStatus(fr.id, 'rejected')
      res.json({ ok: true })
    } catch (err) { console.error('[friend-request-reject]', err); res.status(500).json({ error: 'Failed' }) }
  })

  // ========================================================================
  // Identity Migration (hash association for existing users)
  // ========================================================================

  app.post('/api/migrate-identity', requireAuth, async (req, res) => {
    try {
      const { usernameHash } = req.body
      if (!usernameHash || !/^[a-f0-9]{64}$/.test(usernameHash))
        return res.status(400).json({ error: 'Valid usernameHash required (64 hex chars)' })

      const oldUsername = req.user.username

      // Already migrated: only if the username column itself IS the hash
      if (oldUsername === usernameHash)
        return res.json({ ok: true, alreadyMigrated: true })

      // Check for collision
      if (await userStore.getByUsername(usernameHash))
        return res.status(409).json({ error: 'Hash collision' })

      // Replace plaintext username with hash across ALL tables
      await userStore.migrateUsername(oldUsername, usernameHash)

      // Migrate notifications from old address to new hash-based address
      try {
        const oldAddr = `${oldUsername}@${config.domain}`
        const newAddr = `${usernameHash}@${config.domain}`
        notifications.db.prepare('UPDATE notifications SET user_addr = ? WHERE user_addr = ?').run(newAddr, oldAddr)
      } catch {}

      // Invalidate old session, create new one with updated user
      sessionStore.destroy(req.sessionToken)
      const updatedUser = await userStore.getByUsername(usernameHash)
      const newToken = sessionStore.create(updatedUser)

      res.json({ ok: true, token: newToken, user: sanitizeUser(updatedUser) })
    } catch (err) { console.error('[migrate]', err); res.status(500).json({ error: 'Migration failed' }) }
  })

  // ========================================================================
  // Federation: hash-based lookup and friend request relay
  // ========================================================================

  app.post('/api/federation/lookup', async (req, res) => {
    try {
      const { hash } = req.body
      if (!hash || !/^[a-f0-9]{64}$/.test(hash))
        return res.status(400).json({ error: 'Valid hash required' })
      const exists = await userStore.hashExists(hash)
      res.json({ exists })
    } catch { res.status(500).json({ error: 'Lookup failed' }) }
  })

  // Federation endpoint: receive friend requests from remote servers
  app.post('/.well-known/friendsforum/friend-request', async (req, res) => {
    try {
      const { fromHash, fromDomain, toHash, payload } = req.body
      if (!fromHash || !fromDomain || !toHash || !payload)
        return res.status(400).json({ error: 'Missing fields' })
      if (!await userStore.hashExists(toHash))
        return res.status(404).json({ error: 'User not found' })
      await userStore.createFriendRequest(
        fromHash, fromDomain, toHash,
        typeof payload === 'string' ? payload : JSON.stringify(payload)
      )
      res.status(202).json({ accepted: true })
    } catch (err) { console.error('[federation-fr]', err); res.status(500).json({ error: 'Failed' }) }
  })

  // ========================================================================
  // Profile by hash (public keys lookup)
  // ========================================================================

  app.get('/api/profile/by-hash/:hash', async (req, res) => {
    try {
      if (!/^[a-f0-9]{64}$/.test(req.params.hash))
        return res.status(400).json({ error: 'Invalid hash' })
      const user = await userStore.getByHash(req.params.hash)
      if (!user) return res.status(404).json({ error: 'User not found' })
      res.json({
        usernameHash: user.usernameHash,
        domain: user.domain,
        signingPublicKey: user.signingPublicKey,
        encryptionPublicKey: user.encryptionPublicKey,
        fingerprint: user.fingerprint,
        feedKeyVersion: user.feedKeyVersion,
      })
    } catch (err) { res.status(500).json({ error: err.message }) }
  })

  // ========================================================================
  // Health
  // ========================================================================

  app.get('/api/health', async (req, res) => {
    const contentFiles = countContentFiles()
    res.json({
      status: 'ok', uptime: process.uptime(),
      domain: config.domain,
      storage: { backend: 'local', contentFiles },
      users: await userStore.count(),
    })
  })

  app.get('/api/node-info', (req, res) => {
    res.json({ domain: config.domain, storage: 'local', version: '0.2.0' })
  })

  // ========================================================================
  // Static / SPA
  // ========================================================================

  const staticPath = join(__dirname, '..', 'dist')
  app.use(express.static(staticPath, { maxAge: '1h' }))
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/') || req.path.startsWith('/.well-known/') || req.path.startsWith('/content/'))
      return res.status(404).json({ error: 'Not found' })
    res.sendFile(join(staticPath, 'index.html'))
  })

  // ========================================================================
  // Start
  // ========================================================================

  const http = await import('http')
  http.createServer(app).listen(config.port, config.host, () => {
    console.log(`\n[server] http://${config.host}:${config.port}`)
    console.log('[server] Ready.\n')
  })

  // Periodic cleanup of expired key history
  setInterval(() => { userStore.cleanExpiredKeyHistory().catch(() => {}) }, 3600000)

  process.on('SIGINT', async () => { await userStore.close(); process.exit(0) })
  process.on('SIGTERM', async () => { await userStore.close(); process.exit(0) })
}

// ============================================================================
// Helpers
// ============================================================================

function sanitizeUser(u) {
  return {
    username: u.username, domain: u.domain,
    usernameHash: u.usernameHash || null,
    signingPublicKey: u.signingPublicKey,
    encryptionPublicKey: u.encryptionPublicKey,
    fingerprint: u.fingerprint,
    feedKeyVersion: u.feedKeyVersion,
    quotaUsed: u.quotaUsed, quotaLimit: u.quotaLimit,
    createdAt: u.createdAt,
  }
}

async function resolveRemoteUser(username, domain) {
  try {
    const r = await fetch(`https://${domain}/.well-known/friendsforum/users/${username}`, { signal: AbortSignal.timeout(10000) })
    return r.ok ? r.json() : null
  } catch { return null }
}

function countContentFiles() {
  try {
    let count = 0
    for (const dir of readdirSync(CONTENT_DIR)) {
      const sub = join(CONTENT_DIR, dir)
      try { count += readdirSync(sub).length } catch {}
    }
    return count
  } catch { return 0 }
}

main().catch(err => { console.error('[server] Fatal:', err); process.exit(1) })
