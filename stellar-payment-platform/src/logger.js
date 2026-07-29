const path = require('path');
const fs = require('fs');
const winston = require('winston');
require('winston-daily-rotate-file');

// #294 — Centralised Winston logger with rotating file transports.
// Writing to a single ever-growing file eventually exhausts disk space, so every
// file transport rotates daily *and* whenever the active file passes MAX_SIZE,
// keeping only MAX_FILES worth of history (older archives are gzipped/deleted).

// Logs live in <stellar-payment-platform>/logs by default. LOG_DIR can point the
// transports somewhere else (e.g. a mounted volume in Docker).
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '..', 'logs');

// Ensure the log directory exists before opening any file transports.
// In CI environments the directory may not be pre-created, so mkdirSync with
// { recursive: true } guarantees the path exists without error when already present.
fs.mkdirSync(LOG_DIR, { recursive: true });
const LOG_LEVEL = process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug');
const MAX_SIZE = process.env.LOG_MAX_SIZE || '20m';
const MAX_FILES = process.env.LOG_MAX_FILES || '14d';

// Test runs should not litter the working tree with log files or console noise.
const IS_TEST = process.env.NODE_ENV === 'test';

// The transport creates LOG_DIR on demand, so no bootstrap mkdir is needed.
const rotateOptions = (filename, level) => ({
  filename: path.join(LOG_DIR, filename),
  datePattern: 'YYYY-MM-DD',
  maxSize: MAX_SIZE,
  maxFiles: MAX_FILES,
  zippedArchive: true,
  ...(level ? { level } : {}),
});

const redactKeys = winston.format((info) => {
  const S_KEY_REGEX = /S[A-Z2-7]{55}/g;
  if (typeof info.message === 'string') {
    info.message = info.message.replace(S_KEY_REGEX, '[REDACTED_SECRET_KEY]');
  }
  if (info.stack && typeof info.stack === 'string') {
    info.stack = info.stack.replace(S_KEY_REGEX, '[REDACTED_SECRET_KEY]');
  }
  return info;
});

const fileFormat = winston.format.combine(
  redactKeys(),
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const consoleFormat = winston.format.combine(
  redactKeys(),
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, correlationId, stack }) => {
    const trace = correlationId ? ` [Correlation ID: ${correlationId}]` : '';
    return `${timestamp} ${level}:${trace} ${stack || message}`;
  })
);

const fileTransports = IS_TEST
  ? []
  : [
    // Everything at LOG_LEVEL and above.
    new winston.transports.DailyRotateFile(rotateOptions('application-%DATE%.log')),
    // Errors again on their own, so incidents are easy to find.
    new winston.transports.DailyRotateFile(rotateOptions('error-%DATE%.log', 'error')),
  ];

const transports = [
  new winston.transports.Console({
    format: consoleFormat,
    silent: IS_TEST,
  }),
  ...fileTransports,
];

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: fileFormat,
  defaultMeta: { service: 'stellar-payment-platform' },
  transports,
  exitOnError: false,
});

// Surface rotation problems (permissions, full disk) instead of failing silently.
fileTransports.forEach((transport) => {
  transport.on('error', (error) => {
    console.error('[logger] rotating file transport error:', error.message);
  });
});

module.exports = { logger, fileTransports, LOG_DIR, MAX_SIZE, MAX_FILES };
