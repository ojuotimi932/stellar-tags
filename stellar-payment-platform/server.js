const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { createClient } = require('redis');
const { prisma } = require('./prismaClient');
const { scheduleCleanupJob } = require('./src/cleanup-cron');
const { correlationId } = require('./middleware/correlation');
const { idempotencyMiddleware } = require('./middleware/idempotency');
const Filter = require('bad-words');
const dotenv = require('dotenv');
const timeout = require('connect-timeout');
const compression = require('compression');
const v1Router = require('./src/routes/v1');
const {verifyMultiSignerThreshold,} = require('./src/multisigner-verifier');
const { poolGet, poolRun, poolAll } = require('./src/db');
const { logger } = require('./src/logger');
const xss = require('xss');
const { Keypair, StrKey } = require('@stellar/stellar-sdk');
const { metricsMiddleware, getMetrics, getContentType } = require('./src/metrics');
const { registerValidator } = require('./src/validators/registerValidator');
const { validate } = require('./src/middleware/validate');
const { validationResult } = require('express-validator');
const Sentry = require('@sentry/node');

dotenv.config();

// #295 — Only report to Sentry when a DSN is configured, so local/dev/test
// runs without SENTRY_DSN never try to reach out to Sentry.
if (process.env.SENTRY_DSN) {
  Sentry.init({ dsn: process.env.SENTRY_DSN });
}

const app = express();

// #31 — Attach a correlation ID to every request before anything else runs so
// all downstream middleware, handlers and logs can reference the same trace.
app.use(correlationId);

app.use(timeout('10s'));
app.use((err, req, res, next) => {
  if (req.timedout) {
    logger.error(`[Correlation ID: ${req.correlationId}] Request Timeout`, err);
    return res.status(503).json({ error: 'Service Unavailable', correlation_id: req.correlationId });
  }
  next(err);
});

app.set('query parser', 'simple');
const PORT = process.env.PORT || 5000;
const STELLAR_TAG_DOMAIN = process.env.STELLAR_TAG_DOMAIN;

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://stellar-tags.vercel.app',
  STELLAR_TAG_DOMAIN,
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204,
};

// Apply metrics middleware to track all HTTP requests
app.use(metricsMiddleware);

const REDIS_RETRY_MAX = 5;
const REDIS_RETRY_BASE_DELAY_MS = 500;

const redisClient = process.env.REDIS_URL ? createClient({
  url: process.env.REDIS_URL,
  socket: {
    reconnectStrategy(retries, cause) {
      if (retries >= REDIS_RETRY_MAX) {
        logger.error(`Redis connection failed after ${REDIS_RETRY_MAX} retries`, { cause });
        return new Error(`Redis connection failed after ${REDIS_RETRY_MAX} retries`);
      }
      const delay = Math.min(2 ** retries * REDIS_RETRY_BASE_DELAY_MS, 10000);
      logger.warn(`Redis connection attempt ${retries + 1} failed, retrying in ${delay}ms...`, { cause });
      return delay;
    }
  }
}) : null;
if (redisClient) {
  redisClient.on('error', (err) => logger.error('Redis client error:', err));
  redisClient.connect().catch((err) => logger.error('Redis connection error:', err));
}

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  store: redisClient ? new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args),
  }) : undefined,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

app.use(cors(corsOptions));
app.use(limiter);
app.use(express.json({ limit: '10kb' }));
app.use((err, _req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed JSON payload' });
  }
  next(err);
});

const isPrimitive = (v) => v === null || v === undefined || typeof v !== 'object';

const rejectNestedObjects = (req, res, next) => {
  const sources = [req.query, req.body];
  for (const source of sources) {
    if (source && typeof source === 'object') {
      for (const val of Object.values(source)) {
        if (!isPrimitive(val)) {
          return res
            .status(400)
            .json({ detail: 'Invalid parameter type: nested objects and arrays are not allowed.' });
        }
      }
    }
  }
  next();
};

app.use(rejectNestedObjects);

// Enable HTTP response compression for responses exceeding 1KB (1024 bytes)
app.use(compression({ threshold: 1024 }));

const USER_DATABASE = {
  'client*localhost': 'GAPUQZH3WZUXHEMUGZN5ZYU4D4GHCFEMOGUINU6MF345GBD2QXNYYIEQ',
  'lekan*localhost': 'GAPUQZH3WZUXHEMUGZN5ZYU4D4GHCFEMOGUINU6MF345GBD2QXNYYIEQ',
};

const DEFAULT_FEDERATION_DOMAIN = 'localhost';

const normalizeNameTag = (value) => {
  const trimmed = typeof value === 'string' ? value.trim() : '';
  if (!trimmed) {
    return '';
  }
  return trimmed.includes('*') ? trimmed : `${trimmed}*${DEFAULT_FEDERATION_DOMAIN}`;
};

// ---------------------------------------------------------------------------
// #51 — ETag Caching Middleware for Federation Endpoint
// ---------------------------------------------------------------------------
const etagCache = (req, res, next) => {
  const originalJson = res.json.bind(res);

  res.json = (body) => {
    const bodyString = JSON.stringify(body);
    const hash = crypto.createHash('sha256').update(bodyString).digest('hex');
    const etag = `"${hash}"`;

    res.set('ETag', etag);

    const clientEtag = req.get('If-None-Match');
    if (clientEtag && clientEtag === etag) {
      return res.status(304).end();
    }

    return originalJson(body);
  };

  next();
};

const shouldFallbackToLocalRegistry = (error) => {
  const code = typeof error?.code === 'string' ? error.code : '';
  const message = typeof error?.message === 'string' ? error.message : '';

  return (
    code.startsWith('P10') ||
    ['P2021', 'P2023', 'P2028', 'P2001'].includes(code) ||
    /DATABASE_URL|connect|relation|table|timeout/i.test(message)
  );
};

const getLocalUserByAddress = async (address) =>
  poolGet(
    'SELECT username, address FROM username_registry WHERE address = ? LIMIT 1',
    [address],
  );

const getLocalUserByUsername = async (username) =>
  poolGet(
    'SELECT username, address FROM username_registry WHERE username = ? LIMIT 1',
    [username],
  );

const listLocalUsers = async (search, page, limit) => {
  const searchPattern = `%${search}%`;
  const skip = (page - 1) * limit;
  const rows = await poolAll(
    `SELECT username, address, created_at
     FROM username_registry
     WHERE username LIKE ? COLLATE NOCASE OR address LIKE ? COLLATE NOCASE
     ORDER BY created_at DESC
     LIMIT ? OFFSET ?`,
    [searchPattern, searchPattern, limit, skip],
  );

  const countRow = await poolGet(
    `SELECT COUNT(*) AS totalCount
     FROM username_registry
     WHERE username LIKE ? COLLATE NOCASE OR address LIKE ? COLLATE NOCASE`,
    [searchPattern, searchPattern],
  );

  const totalCount = Number(countRow?.totalCount || 0);

  return {
    data: rows.map((user) => ({
      username: user.username,
      address: user.address,
      created_at: user.created_at,
    })),
    meta: {
      total: totalCount,
      totalCount,
      page,
      currentPage: page,
      limit,
      totalPages: Math.ceil(totalCount / limit),
    },
    totalCount,
    totalPages: Math.ceil(totalCount / limit),
    currentPage: page,
  };
};

const registerLocalUser = async ({ username, address }) => {
  const existingByAddress = await getLocalUserByAddress(address);
  if (existingByAddress) {
    const conflictError = new Error('Address already registered');
    conflictError.statusCode = 409;
    throw conflictError;
  }

  const existingByUsername = await getLocalUserByUsername(username);
  if (existingByUsername) {
    const conflictError = new Error('Username is already taken. Please choose another.');
    conflictError.statusCode = 409;
    throw conflictError;
  }

  await poolRun(
    `INSERT INTO username_registry (username, address, created_at)
     VALUES (?, ?, ?)`,
    [username, address, new Date().toISOString()],
  );
};

// Expose /metrics endpoint for Prometheus to scrape
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', getContentType());
    const metrics = await getMetrics();
    res.end(metrics);
  } catch (err) {
    logger.error(`[Correlation ID: ${req.correlationId}] Metrics error`, err);
    res.status(500).end(err.message);
  }
});

app.get('/federation', etagCache, async (req, res, next) => {
  const { q, type } = req.query;
  const queryValue = typeof q === 'string' ? q.trim() : '';

  if (!queryValue) {
    const error = new Error("Missing 'q' parameter");
    error.statusCode = 400;
    return next(error);
  }

  try {
    if (type === 'id') {
      const row = await prisma.user.findFirst({
        where: { address: { equals: queryValue, mode: 'insensitive' } },
        select: { username: true, address: true, memoType: true, memo: true },
      });

      if (!row) {
        const notFoundError = new Error('Address not found');
        notFoundError.statusCode = 404;
        return next(notFoundError);
      }
      const response = {
        stellar_address: `${row.username}*${process.env.DOMAIN || 'localhost'}`,
        account_id: row.address,
      };
      if (row.memoType) {
        response.memo_type = row.memoType;
        response.memo = row.memo;
      }
      return res.json(response);
    } else if (type === 'name' || !type) {
      const nameTag = normalizeNameTag(queryValue);
      const queryName = nameTag.toLowerCase();

      let row = null;
      try {
        row = await prisma.user.findUnique({
          where: { username: queryName },
          select: { address: true, memoType: true, memo: true },
        });
      } catch (error) {
        if (!shouldFallbackToLocalRegistry(error)) {
          throw error;
        }

        const localRow = await getLocalUserByUsername(queryName);
        row = localRow
          ? { address: localRow.address, memoType: null, memo: null }
          : null;
      }

      const address = row?.address || USER_DATABASE[queryName];

      if (!address) {
        const notFoundError = new Error('Name tag not found');
        notFoundError.statusCode = 404;
        return next(notFoundError);
      }

      const response = {
        stellar_address: address,
        account_id: address,
      };
      if (row?.memoType) {
        response.memo_type = row.memoType;
        response.memo = row.memo;
      }
      return res.json(response);
    } else {
      return res.status(400).json({
        error: "Unsupported query type. Supported types: 'id', 'name'",
      });
    }
  } catch {
    const dbError = new Error('Database lookup failed');
    dbError.statusCode = 500;
    return next(dbError);
  }
});

// Initialise profanity filter once at module load (reused across requests).
const profanityFilter = new Filter();
const VALID_MEMO_TYPES = ['text', 'id', 'hash'];
const MEMO_ID_RE = /^\d+$/;
const MEMO_HASH_RE = /^[0-9a-fA-F]{64}$/;

const validateMemo = (memoType, memo) => {
  if (!memoType && !memo) return null;
  if (memoType && !memo) return 'memo is required when memo_type is provided.';
  if (!memoType && memo) return 'memo_type is required when memo is provided.';
  if (!VALID_MEMO_TYPES.includes(memoType)) {
    return `memo_type must be one of: ${VALID_MEMO_TYPES.join(', ')}.`;
  }
  if (memoType === 'text' && Buffer.byteLength(memo, 'utf8') > 28) {
    return 'memo of type text must not exceed 28 bytes.';
  }
  if (memoType === 'id') {
    if (!MEMO_ID_RE.test(memo) || BigInt(memo) > 18446744073709551615n) {
      return 'memo of type id must be a valid 64-bit unsigned integer.';
    }
  }
  if (memoType === 'hash' && !MEMO_HASH_RE.test(memo)) {
    return 'memo of type hash must be a 64-character hex string (32 bytes).';
  }
  return null;
};

const verifyFreighterRegistrationSignature = ({
  username,
  address,
  signature,
  signerAddress,
}) => {
  const message = `register:${username}:${address}`;
  const claimedSigner = signerAddress || address;

  if (!StrKey.isValidEd25519PublicKey(claimedSigner)) {
    const error = new Error('Invalid signer address format.');
    error.statusCode = 400;
    throw error;
  }

  const keypair = Keypair.fromPublicKey(claimedSigner);

  let signatureBuffer;
  if (Buffer.isBuffer(signature)) {
    signatureBuffer = signature;
  } else if (typeof signature === 'string') {
    signatureBuffer = Buffer.from(signature, 'base64');
  } else {
    throw new Error('Invalid message signature format.');
  }

  // --- SEP-0053 Verification Logic ---
  // Freighter adds a specific prefix and hashes the payload before signing
  const prefix = Buffer.from('Stellar Signed Message:\n', 'utf8');
  const messageBytes = Buffer.from(message, 'utf8');
  const payload = Buffer.concat([prefix, messageBytes]);
  const messageHash = crypto.createHash('sha256').update(payload).digest();

  // Verify against the hashed payload, not the raw string!
  if (!keypair.verify(messageHash, signatureBuffer)) {
    const error = new Error('Signature verification failed.');
    error.statusCode = 401;
    throw error;
  }

  if (claimedSigner !== address) {
    const error = new Error('Signer address does not match the connected wallet.');
    error.statusCode = 401;
    throw error;
  }

  return claimedSigner;
};

/**
 * Registration endpoint with multi-signer threshold verification
 * 
 * For single-signer accounts:
 * - Signature must be the account's public key or a registered signer
 * - Basic validation of address format
 * 
 * For multi-signer accounts (enterprise):
 * - Fetches account signers and thresholds from Horizon
 * - Validates that provided signature(s) meet minimum threshold
 * - Ensures authorization requirements are satisfied
 */
app.post('/register', idempotencyMiddleware(redisClient), async (req, res, next) => {
  if (!req.is('application/json')) {
    return res.status(415).json({ error: "Unsupported Media Type. Please send application/json" });
  }

  // Run express-validator chains manually
  for (const validator of registerValidator) {
    await validator.run(req);
  }
  
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      errors: errors.array().map(err => ({
        field: err.path,
        message: err.msg,
      })),
    });
  }

  const safeUsername = xss(req.body.username);
  const username = normalizeNameTag(safeUsername);
  const address = typeof req.body.address === 'string' ? req.body.address.trim() : '';
  const memoType = typeof req.body.memo_type === 'string' ? req.body.memo_type.trim() : undefined;
  const memo = typeof req.body.memo === 'string' ? req.body.memo.trim() : undefined;
  const signature = typeof req.body.signature === 'string' ? req.body.signature.trim() : '';
  const signerAddress = typeof req.body.signerAddress === 'string' ? req.body.signerAddress.trim() : '';

  if (address.toUpperCase().startsWith('S')) {
    return res.status(400).json({ error: "Never share your Secret Key. Please register using your Public Key (starts with G)." });
  }

  if (!username || !address) {
    return res.status(400).json({ error: 'Missing required fields: username and address are both required.' });
  }

  // Extract the username part before the * for profanity check and length validation
  const usernameLocalPart = username.includes('*') ? username.split('*')[0] : username;

  if (usernameLocalPart.length < 3) {
    return res.status(400).json({ error: "Username must be at least 3 characters long." });
  }

  // Reject usernames containing profanity or offensive words.
  if (profanityFilter.isProfane(usernameLocalPart)) {
    return res.status(400).json({ error: 'Username contains restricted words' });
  }

  if (!StrKey.isValidEd25519PublicKey(address)) {
    const error = new Error('Invalid Stellar Public Key format.');
    error.statusCode = 400;
    return next(error);
  }

  const memoError = validateMemo(memoType, memo);
  if (memoError) {
    return res.status(400).json({ error: memoError });
  }

  const normalizedUsername = username.toLowerCase();

  const RESERVED_NAMES = ['admin', 'root', 'support', 'system', 'stellar', 'api', 'help'];
  if (RESERVED_NAMES.includes(normalizedUsername)) {
    return res.status(403).json({ error: "This username is reserved and cannot be registered." });
  }

  try {
    let existing = null;
    try {
      existing = await prisma.user.findUnique({
        where: { address },
      });
    } catch (error) {
      if (!shouldFallbackToLocalRegistry(error)) {
        throw error;
      }

      existing = await getLocalUserByAddress(address);
    }

    if (existing) {
      const conflictError = new Error('Address already registered');
      conflictError.statusCode = 409;
      return next(conflictError);
    }

    let verificationResult = null;
    if (signature) {
      const isLegacyPublicKeyFlow =
        StrKey.isValidEd25519PublicKey(signature) && !signerAddress;

      if (isLegacyPublicKeyFlow) {
        verificationResult = await verifyMultiSignerThreshold(address, [signature], {
          operationType: 'management',
        });

        if (!verificationResult.success) {
          const verificationError = new Error(
            verificationResult.errorMessage || 'Signature verification failed'
          );
          verificationError.statusCode = 401;
          throw verificationError;
        }
      } else {
        const claimedSigner = verifyFreighterRegistrationSignature({
          username: req.body.username,
          address: req.body.address, // Make sure this is using the raw body too!
          signature,
          signerAddress,
        });

        verificationResult = {
          success: true,
          accountId: claimedSigner,
          operationType: 'message',
          requiredThreshold: 1,
          totalWeight: 1,
          signatureCount: 1,
          uniqueSignerCount: 1,
          signatures: [
            {
              publicKey: claimedSigner,
              weight: 1,
              isValid: true,
            },
          ],
          thresholds: {
            low_threshold: 1,
            med_threshold: 1,
            high_threshold: 1,
          },
          signerCount: 1,
          errorMessage: null,
        };
      }
    }

    try {
      await prisma.user.create({
        data: {
          username: normalizedUsername,
          address,
          ...(memoType && { memoType, memo }),
        },
      });
    } catch (error) {
      if (!shouldFallbackToLocalRegistry(error)) {
        throw error;
      }

      await registerLocalUser({ username: normalizedUsername, address });
    }

    return res.status(201).json({
      ok: true,
      username: normalizedUsername,
      address,
      federation_address: `${normalizedUsername}*${process.env.DOMAIN || 'localhost'}`,
      ...(verificationResult && {
        verification: {
          accountId: verificationResult.accountId,
          signerCount: verificationResult.signerCount,
          thresholdMet: verificationResult.success,
          requiredThreshold: verificationResult.requiredThreshold,
          providedWeight: verificationResult.totalWeight,
        },
      }),
      ...(memoType && { memo_type: memoType, memo }),
    });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT' || (error.message && error.message.includes('UNIQUE'))) {
      return res.status(409).json({ error: 'Username is already taken. Please choose another.' });
    }
    
    // Handle verification errors
    if (error.message && error.message.includes('Account not found')) {
      const notFoundError = new Error(`Account not found on Horizon: ${address}`);
      notFoundError.statusCode = 404;
      return next(notFoundError);
    }

    // Handle signature verification errors
    if (error.statusCode === 401) {
      return next(error);
    }

    // Handle other errors
    logger.error('Registration error:', error.message);
    const registrationError = new Error(`Registration verification failed: ${error.message}`);
    registrationError.statusCode = 500;
    return next(registrationError);
  }
});

app.all('/register', (req, res) => res.status(405).json({ error: "Method Not Allowed" }));

app.get('/lookup', async (req, res, next) => {
  const address = typeof req.query.address === 'string' ? req.query.address.trim() : '';
  const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';

  if (!address && !search) {
    const error = new Error("Missing required parameter: provide 'address' for exact lookup or 'search' for paginated search");
    error.statusCode = 400;
    return next(error);
  }

  if (address) {
    try {
      let row = null;
      try {
        row = await prisma.user.findUnique({
          where: { address },
          select: { username: true },
        });
      } catch (error) {
        if (!shouldFallbackToLocalRegistry(error)) {
          throw error;
        }

        row = await getLocalUserByAddress(address);
      }

      if (!row) {
        const notFoundError = new Error('Username not found for this address');
        notFoundError.statusCode = 404;
        return next(notFoundError);
      }

      return res.json({ username: row.username, address });
    } catch (err) {  // <-- 1. Add (err) here
      // 2. Add this console.log to print the exact reason Prisma is failing
      logger.error("🚨 ACTUAL PRISMA ERROR:", err); 
      
      const dbError = new Error('Database lookup failed');
      dbError.statusCode = 500;
      return next(dbError);
    }
  }

  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
  const skip = (page - 1) * limit;

  const where = {
    OR: [
      { username: { contains: search, mode: 'insensitive' } },
      { address: { contains: search, mode: 'insensitive' } },
    ],
  };

  try {
    let response = null;
    try {
      const [totalCount, rows] = await prisma.$transaction([
        prisma.user.count({ where }),
        prisma.user.findMany({
          where,
          orderBy: { createdAt: 'desc' },
          skip,
          take: limit,
        }),
      ]);

      response = {
        data: rows.map((user) => ({
          username: user.username,
          address: user.address,
          created_at: user.createdAt.toISOString(),
        })),
        totalCount,
        totalPages: Math.ceil(totalCount / limit),
        currentPage: page,
      };
    } catch (error) {
      if (!shouldFallbackToLocalRegistry(error)) {
        throw error;
      }

      response = await listLocalUsers(search, page, limit);
    }

    return res.json(response);
  } catch {
    const dbError = new Error('Database lookup failed');
    dbError.statusCode = 500;
    return next(dbError);
  }
});

app.get('/users', async (req, res, next) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
  const search = typeof req.query.search === 'string' ? req.query.search : null;
  const skip = (page - 1) * limit;

  const where = search
    ? {
        OR: [
          { username: { contains: search, mode: 'insensitive' } },
          { address: { contains: search, mode: 'insensitive' } },
        ],
      }
    : {};

  try {
    const [totalCount, rows] = await prisma.$transaction([
      prisma.user.count({ where }),
      prisma.user.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
    ]);

    const totalPages = Math.ceil(totalCount / limit);
    const data = rows.map((user) => ({
      username: user.username,
      address: user.address,
      created_at: user.createdAt ? user.createdAt.toISOString() : undefined,
    }));

    res.json({
      data,
      meta: {
        total: totalCount,
        totalCount,
        page,
        currentPage: page,
        limit,
        totalPages,
      },
      totalCount,
      totalPages,
      currentPage: page,
    });
  } catch {
    const dbError = new Error('Database error');
    dbError.statusCode = 500;
    return next(dbError);
  }
});
// Mount v1 router for both legacy paths and explicit API versioning
app.use('/', v1Router);
app.use('/api/v1', v1Router);

app.get('/.well-known/stellar.toml', (_req, res) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.setHeader('Content-Type', 'text/plain');
  res.send('FEDERATION_SERVER="https://stellar-tags-production.up.railway.app/federation"\n');
});

app.get('/api/v1/time', (_req, res) => {
  res.status(200).json({ time: new Date().toISOString() });
});

app.get('/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    logger.error(`[Correlation ID: ${req.correlationId}] Database unavailable`, err);
    res.status(503).json({ status: 'error', database: 'disconnected', correlation_id: req.correlationId });

  }
});

app.use((err, _req, _res, next) => {
  if (err.type === 'entity.too.large') {
    const error = new Error('Payload too large. Maximum allowed size is 10kb.');
    error.statusCode = 413;
    return next(error);
  }
  next(err);
});

// #295 — Report 5xx errors to Sentry (via defaultShouldHandleError) before
// they reach our own JSON error handler below.
if (process.env.SENTRY_DSN) {
  Sentry.setupExpressErrorHandler(app);
}

// Global error handling middleware
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  const statusCode = err.statusCode || 500;
  const errorMessage = err.message || 'Internal server error';

  if (statusCode >= 500) {
    const errorId = crypto.randomUUID();
    // #31 — Prefix error logs with the correlation ID so a single API call can
    // be traced across every log line it produced.
    logger.error(`[Correlation ID: ${req.correlationId}] [Error ID: ${errorId}]`, err);
    return res.status(statusCode).json({
      success: false,
      error: statusCode === 500 ? 'Internal Server Error' : errorMessage,
      reference_id: errorId,
      correlation_id: req.correlationId,
      ...(statusCode !== 500 ? { statusCode } : {})
    });
  }

  return res.status(statusCode).json({
    success: false,
    error: errorMessage,
    statusCode: statusCode,
  });
});

const SHUTDOWN_TIMEOUT_MS = parseInt(process.env.SHUTDOWN_TIMEOUT_MS, 10) || 10_000;
let isShuttingDown = false;

const gracefulShutdown = (server, prismaClient, signal) => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info(`\nReceived ${signal}. Shutting down gracefully...`);

  const timer = setTimeout(() => {
    logger.error(`Graceful shutdown timed out after ${SHUTDOWN_TIMEOUT_MS / 1000}s, forcing exit.`);
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);

  server.close(async () => {
    clearTimeout(timer);
    try {
      await prismaClient.$disconnect();
    } catch (err) {
      console.error('Error disconnecting Prisma during shutdown:', err);
      logger.error('Error draining DB pool during shutdown:', err);
    }
    process.exit(0);
  });
};


if (require.main === module) {
  // Schedule the stale-account cleanup job only when running as the main process.
  // This prevents background timers from leaking when the app is imported in tests.
  scheduleCleanupJob(prisma);

  const server = app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Server successfully initialized on port ${PORT}`);
  });

  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
      logger.error(`Port ${PORT} is in use, forcing shutdown so Railway can restart cleanly.`);
      process.exit(1);
    }
  });

  process.on('SIGTERM', (sig) => gracefulShutdown(server, prisma, sig));
  process.on('SIGINT', (sig) => gracefulShutdown(server, prisma, sig));
}

module.exports = { app, gracefulShutdown, rejectNestedObjects, validateMemo };
