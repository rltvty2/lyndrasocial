import Database from 'better-sqlite3'

export class UserStore {
  constructor(dbPath) { this.dbPath = dbPath; this.db = null }

  async init() {
    this.db = new Database(this.dbPath)
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('foreign_keys = ON')
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        display_name TEXT,
        bio TEXT DEFAULT '',
        signing_key TEXT NOT NULL,
        encryption_key TEXT NOT NULL,
        profile_cid TEXT,
        fingerprint TEXT,
        feed_key_version INTEGER DEFAULT 1,
        encrypted_vault TEXT,
        quota_used INTEGER DEFAULT 0,
        quota_limit INTEGER DEFAULT 524288000,
        created_at INTEGER NOT NULL,
        updated_at INTEGER,
        wrapped_keys TEXT
      );

      CREATE TABLE IF NOT EXISTS content_manifest (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL REFERENCES users(username),
        cid TEXT NOT NULL,
        size INTEGER NOT NULL,
        type TEXT DEFAULT 'unknown',
        label TEXT DEFAULT '',
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL REFERENCES users(username),
        domain TEXT NOT NULL,
        content_hash TEXT,
        envelope TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_manifest_user ON content_manifest(username);
      CREATE INDEX IF NOT EXISTS idx_manifest_cid ON content_manifest(cid);
      CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(username);
      CREATE INDEX IF NOT EXISTS idx_posts_time ON posts(created_at);

      CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        post_id TEXT NOT NULL,
        post_author TEXT NOT NULL,
        username TEXT NOT NULL,
        domain TEXT NOT NULL,
        encrypted_content TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
      CREATE INDEX IF NOT EXISTS idx_comments_time ON comments(created_at);

      CREATE TABLE IF NOT EXISTS key_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL REFERENCES users(username),
        signing_key TEXT NOT NULL,
        encryption_key TEXT NOT NULL,
        fingerprint TEXT,
        feed_key_version INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_key_history_user ON key_history(username);
      CREATE INDEX IF NOT EXISTS idx_key_history_expires ON key_history(expires_at);

      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        from_user TEXT NOT NULL,
        to_user TEXT NOT NULL,
        encrypted_content TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(from_user, to_user);
      CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_user);
      CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(created_at);

      CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_hash TEXT NOT NULL,
        from_domain TEXT NOT NULL,
        to_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
      );
      CREATE INDEX IF NOT EXISTS idx_fr_to_hash ON friend_requests(to_hash, status);
      CREATE INDEX IF NOT EXISTS idx_fr_from_hash ON friend_requests(from_hash);
    `)

    // Migrate: add columns if they don't exist (safe for existing DBs)
    try { this.db.exec('ALTER TABLE users ADD COLUMN feed_key_version INTEGER DEFAULT 1') } catch {}
    try { this.db.exec('ALTER TABLE users ADD COLUMN encrypted_vault TEXT') } catch {}
    try { this.db.exec('ALTER TABLE posts ADD COLUMN envelope TEXT') } catch {}
    try { this.db.exec(`CREATE TABLE IF NOT EXISTS key_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL REFERENCES users(username),
      signing_key TEXT NOT NULL, encryption_key TEXT NOT NULL,
      fingerprint TEXT, feed_key_version INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      revoked INTEGER DEFAULT 0
    )`) } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_key_history_user ON key_history(username)') } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_key_history_expires ON key_history(expires_at)') } catch {}
    try { this.db.exec(`CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY, from_user TEXT NOT NULL, to_user TEXT NOT NULL,
      encrypted_content TEXT NOT NULL, iv TEXT NOT NULL, created_at INTEGER NOT NULL
    )`) } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(from_user, to_user)') } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_user)') } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(created_at)') } catch {}
    // Migrate: add username_hash column
    try { this.db.exec('ALTER TABLE users ADD COLUMN username_hash TEXT') } catch {}
    try { this.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_hash ON users(username_hash)') } catch {}
    // Migrate: friend_requests table
    try { this.db.exec(`CREATE TABLE IF NOT EXISTS friend_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT, from_hash TEXT NOT NULL, from_domain TEXT NOT NULL,
      to_hash TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
    )`) } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_fr_to_hash ON friend_requests(to_hash, status)') } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_fr_from_hash ON friend_requests(from_hash)') } catch {}

    // Migrate: group chats
    try { this.db.exec(`CREATE TABLE IF NOT EXISTS group_chats (
      id TEXT PRIMARY KEY, name_encrypted TEXT NOT NULL, name_iv TEXT NOT NULL,
      creator TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    )`) } catch {}
    try { this.db.exec(`CREATE TABLE IF NOT EXISTS group_members (
      group_id TEXT NOT NULL REFERENCES group_chats(id) ON DELETE CASCADE,
      username TEXT NOT NULL, encrypted_key TEXT NOT NULL, key_iv TEXT NOT NULL,
      added_at INTEGER NOT NULL, PRIMARY KEY (group_id, username)
    )`) } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_gm_user ON group_members(username)') } catch {}
    try { this.db.exec(`CREATE TABLE IF NOT EXISTS group_messages (
      id TEXT PRIMARY KEY, group_id TEXT NOT NULL REFERENCES group_chats(id) ON DELETE CASCADE,
      from_user TEXT NOT NULL, encrypted_content TEXT NOT NULL, iv TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )`) } catch {}
    try { this.db.exec('CREATE INDEX IF NOT EXISTS idx_gmsg_group ON group_messages(group_id, created_at)') } catch {}

    this._stmts = {
      create: this.db.prepare(`INSERT INTO users (username,domain,display_name,signing_key,encryption_key,profile_cid,fingerprint,feed_key_version,quota_used,quota_limit,created_at,updated_at,username_hash) VALUES (@username,@domain,@displayName,@signingPublicKey,@encryptionPublicKey,@profileCid,@fingerprint,@feedKeyVersion,@quotaUsed,@quotaLimit,@createdAt,@updatedAt,@usernameHash)`),
      getByUsername: this.db.prepare('SELECT * FROM users WHERE username = ?'),
      getByHash: this.db.prepare('SELECT * FROM users WHERE username_hash = ?'),
      count: this.db.prepare('SELECT COUNT(*) as count FROM users'),
      addContent: this.db.prepare('INSERT INTO content_manifest (username,cid,size,type,label,created_at) VALUES (?,?,?,?,?,?)'),
      removeContent: this.db.prepare('DELETE FROM content_manifest WHERE username=? AND cid=?'),
      getContent: this.db.prepare('SELECT * FROM content_manifest WHERE username=?'),
    }
  }

  async create(user) {
    this._stmts.create.run({
      username: user.username,
      domain: user.domain,
      displayName: user.displayName || user.username,
      signingPublicKey: user.signingPublicKey,
      encryptionPublicKey: user.encryptionPublicKey,
      profileCid: user.profileCid || null,
      fingerprint: user.fingerprint || null,
      feedKeyVersion: user.feedKeyVersion || 1,
      quotaUsed: user.quotaUsed || 0,
      quotaLimit: user.quotaLimit || 524288000,
      createdAt: user.createdAt || Date.now(),
      updatedAt: Date.now(),
      usernameHash: user.usernameHash || null,
    })
    return this.getByUsername(user.username)
  }

  _rowToUser(row) {
    if (!row) return null
    return {
      username: row.username,
      domain: row.domain,
      displayName: row.display_name,
      bio: row.bio,
      signingPublicKey: row.signing_key,
      encryptionPublicKey: row.encryption_key,
      profileCid: row.profile_cid,
      fingerprint: row.fingerprint,
      feedKeyVersion: row.feed_key_version || 1,
      encryptedVault: row.encrypted_vault,
      quotaUsed: row.quota_used,
      quotaLimit: row.quota_limit,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      usernameHash: row.username_hash || null,
    }
  }

  async getByUsername(username) {
    return this._rowToUser(this._stmts.getByUsername.get(username))
  }

  async getByHash(hash) {
    return this._rowToUser(this._stmts.getByHash.get(hash))
  }

  async setUsernameHash(username, hash) {
    this.db.prepare('UPDATE users SET username_hash = ?, updated_at = ? WHERE username = ?')
      .run(hash, Date.now(), username)
  }

  async migrateUsername(oldUsername, newHash) {
    // PRAGMA foreign_keys must be set OUTSIDE a transaction (SQLite ignores it inside)
    this.db.pragma('foreign_keys = OFF')

    const migrate = this.db.transaction(() => {
      // Update all referencing tables
      this.db.prepare('UPDATE posts SET username = ? WHERE username = ?').run(newHash, oldUsername)
      this.db.prepare('UPDATE comments SET username = ? WHERE username = ?').run(newHash, oldUsername)
      this.db.prepare('UPDATE comments SET post_author = ? WHERE post_author = ?').run(newHash, oldUsername)
      this.db.prepare('UPDATE content_manifest SET username = ? WHERE username = ?').run(newHash, oldUsername)
      this.db.prepare('UPDATE key_history SET username = ? WHERE username = ?').run(newHash, oldUsername)
      this.db.prepare('UPDATE messages SET from_user = ? WHERE from_user = ?').run(newHash, oldUsername)
      this.db.prepare('UPDATE messages SET to_user = ? WHERE to_user = ?').run(newHash, oldUsername)

      // Update key_exchanges if table exists
      try {
        this.db.prepare('UPDATE key_exchanges SET from_user = ? WHERE from_user = ?').run(newHash, oldUsername)
        this.db.prepare('UPDATE key_exchanges SET to_user = ? WHERE to_user = ?').run(newHash, oldUsername)
      } catch {}

      // Update the users table primary key
      this.db.prepare('UPDATE users SET username = ?, username_hash = ?, updated_at = ? WHERE username = ?')
        .run(newHash, newHash, Date.now(), oldUsername)
    })
    migrate()

    // Re-enable foreign key checks
    this.db.pragma('foreign_keys = ON')
  }

  async update(username, fields) {
    const sets = []
    const params = { username }
    if (fields.profileCid !== undefined) { sets.push('profile_cid = @profileCid'); params.profileCid = fields.profileCid }
    if (fields.quotaUsed !== undefined) { sets.push('quota_used = @quotaUsed'); params.quotaUsed = fields.quotaUsed }
    if (fields.feedKeyVersion !== undefined) { sets.push('feed_key_version = @feedKeyVersion'); params.feedKeyVersion = fields.feedKeyVersion }
    if (fields.encryptedVault !== undefined) { sets.push('encrypted_vault = @encryptedVault'); params.encryptedVault = fields.encryptedVault }
    if (fields.signingPublicKey !== undefined) { sets.push('signing_key = @signingPublicKey'); params.signingPublicKey = fields.signingPublicKey }
    if (fields.encryptionPublicKey !== undefined) { sets.push('encryption_key = @encryptionPublicKey'); params.encryptionPublicKey = fields.encryptionPublicKey }
    if (fields.fingerprint !== undefined) { sets.push('fingerprint = @fingerprint'); params.fingerprint = fields.fingerprint }
    if (fields.usernameHash !== undefined) { sets.push('username_hash = @usernameHash'); params.usernameHash = fields.usernameHash }
    sets.push('updated_at = @updatedAt')
    params.updatedAt = fields.updatedAt || Date.now()
    if (sets.length > 1) {
      this.db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE username = @username`).run(params)
    }
    return this.getByUsername(username)
  }

  async addContent(username, cid, size, type = 'unknown', label = '') {
    this._stmts.addContent.run(username, cid, size, type, label, Date.now())
  }

  async removeContent(username, cid) { this._stmts.removeContent.run(username, cid) }
  async getUserContent(username) { return this._stmts.getContent.all(username) }
  async count() { return this._stmts.count.get().count }

  // ── Posts ──

  async addPost(username, domain, contentHash, envelope, createdAt) {
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
    this.db.prepare(
      'INSERT INTO posts (id, username, domain, content_hash, envelope, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, username, domain, contentHash || null, envelope || null, createdAt || Date.now())
    return id
  }

  async getPostsByUser(username, before = Date.now(), limit = 20) {
    return this.db.prepare(
      'SELECT * FROM posts WHERE username = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?'
    ).all(username, before, limit)
  }

  // Feed: returns posts filtered by bloom filter
  // The bloom filter is a base64-encoded bit array sent by the client.
  // We test each post's author against it server-side.
  async getFeedWithBloom(bloomB64, bloomHashCount, before = Date.now(), limit = 50) {
    if (!bloomB64) {
      // No bloom filter = return own posts only (shouldn't normally happen)
      return []
    }

    const bloomBits = Buffer.from(bloomB64, 'base64')
    const bloomSize = bloomBits.length * 8

    // Scan posts in reverse chronological order, test bloom, collect matches
    const batchSize = 200
    let cursor = before
    const results = []

    while (results.length < limit) {
      const batch = this.db.prepare(
        'SELECT id, username, domain, content_hash, envelope, created_at FROM posts WHERE created_at < ? ORDER BY created_at DESC LIMIT ?'
      ).all(cursor, batchSize)

      if (batch.length === 0) break

      for (const post of batch) {
        if (testBloom(post.username, bloomBits, bloomSize, bloomHashCount)) {
          results.push(post)
          if (results.length >= limit) break
        }
      }

      cursor = batch[batch.length - 1].created_at
      if (batch.length < batchSize) break // no more posts
    }

    return results
  }

  // ── Vault ──

  async setVault(username, encryptedVault) {
    this.db.prepare('UPDATE users SET encrypted_vault = ?, updated_at = ? WHERE username = ?')
      .run(encryptedVault, Date.now(), username)
  }

  async getVault(username) {
    const row = this.db.prepare('SELECT encrypted_vault FROM users WHERE username = ?').get(username)
    return row?.encrypted_vault || null
  }

  // ── Feed key exchange (temporary storage for pending key exchanges) ──
  // These are ECDH-encrypted blobs that only the recipient can decrypt

  async storePendingKeyExchange(fromUser, fromDomain, toUser, encryptedPayload) {
    this.db.exec(`CREATE TABLE IF NOT EXISTS key_exchanges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user TEXT NOT NULL,
      from_domain TEXT NOT NULL,
      to_user TEXT NOT NULL,
      encrypted_payload TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )`)
    this.db.prepare(
      'INSERT INTO key_exchanges (from_user, from_domain, to_user, encrypted_payload, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(fromUser, fromDomain, toUser, encryptedPayload, Date.now())
  }

  async getPendingKeyExchanges(username) {
    try {
      return this.db.prepare(
        'SELECT * FROM key_exchanges WHERE to_user = ? ORDER BY created_at ASC'
      ).all(username)
    } catch { return [] }
  }

  async removePendingKeyExchange(id) {
    try {
      this.db.prepare('DELETE FROM key_exchanges WHERE id = ?').run(id)
    } catch {}
  }

  async setWrappedKeys(username, wrappedKeys) {
    this.db.prepare('UPDATE users SET wrapped_keys = ? WHERE username = ?').run(JSON.stringify(wrappedKeys), username)
  }

  async getWrappedKeys(username) {
    const row = this.db.prepare('SELECT wrapped_keys FROM users WHERE username = ?').get(username)
    return row?.wrapped_keys ? JSON.parse(row.wrapped_keys) : null
  }

  async getUserPosts(username) {
    return this.db.prepare('SELECT * FROM posts WHERE username = ? ORDER BY created_at DESC').all(username)
  }

  async deleteUser(username) {
    this.db.prepare('DELETE FROM comments WHERE username = ?').run(username)
    this.db.prepare('DELETE FROM posts WHERE username = ?').run(username)
    this.db.prepare('DELETE FROM content_manifest WHERE username = ?').run(username)
    this.db.prepare('DELETE FROM users WHERE username = ?').run(username)
  }

  // ── Comments ──

  async addComment(postId, postAuthor, username, domain, encryptedContent, iv, createdAt) {
    const id = `c-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
    this.db.prepare(
      'INSERT INTO comments (id, post_id, post_author, username, domain, encrypted_content, iv, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(id, postId, postAuthor, username, domain, encryptedContent, iv, createdAt || Date.now())
    return id
  }

  async getComments(postId) {
    return this.db.prepare(
      'SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC'
    ).all(postId)
  }

  async getCommentCount(postId) {
    return this.db.prepare('SELECT COUNT(*) as count FROM comments WHERE post_id = ?').get(postId).count
  }

  async getCommentCounts(postIds) {
    if (!postIds.length) return {}
    const placeholders = postIds.map(() => '?').join(',')
    const rows = this.db.prepare(
      `SELECT post_id, COUNT(*) as count FROM comments WHERE post_id IN (${placeholders}) GROUP BY post_id`
    ).all(...postIds)
    const counts = {}
    for (const r of rows) counts[r.post_id] = r.count
    return counts
  }

  async updatePostEnvelope(postId, username, envelope) {
    const post = this.db.prepare('SELECT * FROM posts WHERE id = ? AND username = ?').get(postId, username)
    if (!post) return false
    this.db.prepare('UPDATE posts SET envelope = ? WHERE id = ?').run(envelope, postId)
    return true
  }

  async updateComment(commentId, username, encryptedContent, iv) {
    const comment = this.db.prepare('SELECT * FROM comments WHERE id = ? AND username = ?').get(commentId, username)
    if (!comment) return false
    this.db.prepare('UPDATE comments SET encrypted_content = ?, iv = ? WHERE id = ?').run(encryptedContent, iv, commentId)
    return true
  }

  async deleteComment(commentId, username) {
    const comment = this.db.prepare('SELECT * FROM comments WHERE id = ? AND username = ?').get(commentId, username)
    if (!comment) return false
    this.db.prepare('DELETE FROM comments WHERE id = ?').run(commentId)
    return true
  }

  // ── Key History ──

  async addKeyHistory(username, signingKey, encryptionKey, fingerprint, feedKeyVersion, expiresAt) {
    this.db.prepare(
      'INSERT INTO key_history (username, signing_key, encryption_key, fingerprint, feed_key_version, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, 0)'
    ).run(username, signingKey, encryptionKey, fingerprint, feedKeyVersion, Date.now(), expiresAt)
  }

  async getActiveKeyHistory(username) {
    return this.db.prepare(
      'SELECT * FROM key_history WHERE username = ? AND revoked = 0 AND expires_at > ? ORDER BY created_at DESC'
    ).all(username, Date.now()).map(r => ({
      id: r.id,
      signingPublicKey: r.signing_key,
      encryptionPublicKey: r.encryption_key,
      fingerprint: r.fingerprint,
      feedKeyVersion: r.feed_key_version,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
    }))
  }

  async getAllKeyHistory(username) {
    return this.db.prepare(
      'SELECT * FROM key_history WHERE username = ? ORDER BY created_at DESC'
    ).all(username).map(r => ({
      id: r.id,
      signingPublicKey: r.signing_key,
      encryptionPublicKey: r.encryption_key,
      fingerprint: r.fingerprint,
      feedKeyVersion: r.feed_key_version,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      revoked: !!r.revoked,
    }))
  }

  async revokeAllKeyHistory(username) {
    this.db.prepare('UPDATE key_history SET revoked = 1 WHERE username = ?').run(username)
  }

  async cleanExpiredKeyHistory() {
    this.db.prepare('DELETE FROM key_history WHERE expires_at < ? AND revoked = 0').run(Date.now())
  }

  // ── Messages ──

  async addMessage(fromUser, toUser, encryptedContent, iv) {
    const id = `m-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
    this.db.prepare(
      'INSERT INTO messages (id, from_user, to_user, encrypted_content, iv, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, fromUser, toUser, encryptedContent, iv, Date.now())
    return id
  }

  async getConversation(user1, user2, before = Date.now(), limit = 50) {
    return this.db.prepare(
      `SELECT * FROM messages
       WHERE ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?))
       AND created_at < ? ORDER BY created_at DESC LIMIT ?`
    ).all(user1, user2, user2, user1, before, limit).reverse()
  }

  async getConversationList(username) {
    const rows = this.db.prepare(`
      SELECT
        CASE WHEN from_user = ? THEN to_user ELSE from_user END as partner,
        MAX(created_at) as last_msg
      FROM messages
      WHERE from_user = ? OR to_user = ?
      GROUP BY partner
      ORDER BY last_msg DESC
    `).all(username, username, username)
    // Get the last message sender for each conversation
    return rows.map(r => {
      const lastMsg = this.db.prepare(
        `SELECT from_user FROM messages
         WHERE ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?))
         ORDER BY created_at DESC LIMIT 1`
      ).get(username, r.partner, r.partner, username)
      return {
        partner: r.partner,
        lastMessageAt: r.last_msg,
        lastMessageFrom: lastMsg?.from_user || null,
      }
    })
  }

  async getUnreadCount(username, partner, lastReadAt = 0) {
    return this.db.prepare(
      'SELECT COUNT(*) as count FROM messages WHERE from_user = ? AND to_user = ? AND created_at > ?'
    ).get(partner, username, lastReadAt).count
  }

  async deletePost(postId, username) {
    const post = this.db.prepare('SELECT * FROM posts WHERE id = ? AND username = ?').get(postId, username)
    if (!post) return null
    // Delete associated comments
    this.db.prepare('DELETE FROM comments WHERE post_id = ?').run(postId)
    // Delete the post
    this.db.prepare('DELETE FROM posts WHERE id = ?').run(postId)
    // Delete content blob if exists
    return post.content_hash
  }

  // ── Group Chats ──

  async createGroupChat(id, nameEncrypted, nameIv, creator, members) {
    const now = Date.now()
    this.db.prepare('INSERT INTO group_chats (id, name_encrypted, name_iv, creator, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, nameEncrypted, nameIv, creator, now, now)
    const insertMember = this.db.prepare('INSERT INTO group_members (group_id, username, encrypted_key, key_iv, added_at) VALUES (?, ?, ?, ?, ?)')
    for (const m of members) {
      insertMember.run(id, m.username, m.encryptedKey, m.keyIv, now)
    }
    return id
  }

  async getGroupsForUser(username) {
    return this.db.prepare(`
      SELECT g.*, gm.encrypted_key, gm.key_iv FROM group_chats g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.username = ? ORDER BY g.updated_at DESC
    `).all(username)
  }

  async getGroupChat(groupId) {
    return this.db.prepare('SELECT * FROM group_chats WHERE id = ?').get(groupId)
  }

  async getGroupMembers(groupId) {
    return this.db.prepare('SELECT * FROM group_members WHERE group_id = ?').all(groupId)
  }

  async isGroupMember(groupId, username) {
    return !!this.db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND username = ?').get(groupId, username)
  }

  async addGroupMembers(groupId, members) {
    const now = Date.now()
    const insert = this.db.prepare('INSERT OR IGNORE INTO group_members (group_id, username, encrypted_key, key_iv, added_at) VALUES (?, ?, ?, ?, ?)')
    for (const m of members) insert.run(groupId, m.username, m.encryptedKey, m.keyIv, now)
    this.db.prepare('UPDATE group_chats SET updated_at = ? WHERE id = ?').run(now, groupId)
  }

  async removeGroupMember(groupId, username) {
    this.db.prepare('DELETE FROM group_members WHERE group_id = ? AND username = ?').run(groupId, username)
    this.db.prepare('UPDATE group_chats SET updated_at = ? WHERE id = ?').run(Date.now(), groupId)
  }

  async addGroupMessage(id, groupId, fromUser, encryptedContent, iv) {
    const now = Date.now()
    this.db.prepare('INSERT INTO group_messages (id, group_id, from_user, encrypted_content, iv, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, groupId, fromUser, encryptedContent, iv, now)
    this.db.prepare('UPDATE group_chats SET updated_at = ? WHERE id = ?').run(now, groupId)
    return id
  }

  async getGroupMessages(groupId, before = Date.now(), limit = 50) {
    return this.db.prepare(
      'SELECT * FROM group_messages WHERE group_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?'
    ).all(groupId, before, limit).reverse()
  }

  async getGroupMemberKey(groupId, username) {
    return this.db.prepare('SELECT encrypted_key, key_iv FROM group_members WHERE group_id = ? AND username = ?').get(groupId, username)
  }

  // ── Friend Requests ──

  async createFriendRequest(fromHash, fromDomain, toHash, payload) {
    const result = this.db.prepare(
      'INSERT INTO friend_requests (from_hash, from_domain, to_hash, payload, created_at, status) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(fromHash, fromDomain, toHash, typeof payload === 'string' ? payload : JSON.stringify(payload), Date.now(), 'pending')
    return result.lastInsertRowid
  }

  async getPendingFriendRequests(toHash) {
    return this.db.prepare(
      'SELECT * FROM friend_requests WHERE to_hash = ? AND status = ? ORDER BY created_at DESC'
    ).all(toHash, 'pending')
  }

  async getFriendRequest(id) {
    return this.db.prepare('SELECT * FROM friend_requests WHERE id = ?').get(id)
  }

  async updateFriendRequestStatus(id, status) {
    this.db.prepare('UPDATE friend_requests SET status = ? WHERE id = ?').run(status, id)
  }

  async hashExists(hash) {
    const row = this.db.prepare('SELECT 1 FROM users WHERE username_hash = ?').get(hash)
    return !!row
  }

  async close() { this.db?.close() }
}

// ============================================================================
// Bloom filter utilities (server-side)
// ============================================================================

function murmurhash3(key, seed) {
  let h = seed >>> 0
  const len = key.length
  const nblocks = len >> 2
  const c1 = 0xcc9e2d51, c2 = 0x1b873593

  for (let i = 0; i < nblocks; i++) {
    let k = (key.charCodeAt(i * 4) & 0xff) |
            ((key.charCodeAt(i * 4 + 1) & 0xff) << 8) |
            ((key.charCodeAt(i * 4 + 2) & 0xff) << 16) |
            ((key.charCodeAt(i * 4 + 3) & 0xff) << 24)
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2)
    h ^= k; h = (h << 13) | (h >>> 19); h = Math.imul(h, 5) + 0xe6546b64
  }

  let k = 0
  const tail = nblocks * 4
  switch (len & 3) {
    case 3: k ^= (key.charCodeAt(tail + 2) & 0xff) << 16
    case 2: k ^= (key.charCodeAt(tail + 1) & 0xff) << 8
    case 1: k ^= (key.charCodeAt(tail) & 0xff)
      k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k
  }

  h ^= len
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b)
  h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35)
  h ^= h >>> 16
  return h >>> 0
}

function testBloom(username, bloomBits, bloomSize, hashCount) {
  for (let i = 0; i < hashCount; i++) {
    const hash = murmurhash3(username, i) % bloomSize
    const byteIdx = hash >> 3
    const bitIdx = hash & 7
    if (!(bloomBits[byteIdx] & (1 << bitIdx))) return false
  }
  return true
}
