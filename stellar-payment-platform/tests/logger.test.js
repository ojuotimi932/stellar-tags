const fs = require('fs');
const os = require('os');
const path = require('path');

// Load the logger with a specific environment applied, isolated from the module
// cache so each case gets a freshly configured instance.
const loadLogger = (env) => {
  const previous = { ...process.env };
  Object.assign(process.env, env);

  let mod;
  jest.isolateModules(() => {
    mod = require('../src/logger');
  });

  // Object.keys(process.env) is safer than process.env = previous
  // because process.env in Node 20+ is a Proxy and assignment can leak.
  const added = Object.keys(env);
  for (const key of added) {
    if (key in previous) {
      process.env[key] = previous[key];
    } else {
      delete process.env[key];
    }
  }

  return mod;
};

describe('Rotating file logger (#294)', () => {
  const tmpDir = path.join(os.tmpdir(), `stellar-tags-logs-${process.pid}`);
  const loaded = [];

  afterAll(async () => {
    loaded.forEach((logger) => logger.close());
    // Give winston-daily-rotate-file time to close its file streams
    await new Promise(resolve => setTimeout(resolve, 500));
    // Intentionally NOT deleting tmpDir here.
    // winston-daily-rotate-file closes streams asynchronously and trying to
    // delete the folder while a background flush is happening causes unhandled
    // ENOENT crashes in Jest. The OS will clean up os.tmpdir() eventually.
  });

  describe('in test mode', () => {
    it('does not write files so the working tree stays clean', () => {
      const { logger, fileTransports } = loadLogger({ NODE_ENV: 'test' });
      loaded.push(logger);

      expect(fileTransports).toHaveLength(0);
    });
  });

  describe('outside test mode', () => {
    let fileTransports;
    let LOG_DIR;

    beforeAll(() => {
      const mod = loadLogger({ NODE_ENV: 'production', LOG_DIR: tmpDir });
      ({ fileTransports, LOG_DIR } = mod);
      loaded.push(mod.logger);
    });

    it('writes an application log and a dedicated error log', () => {
      expect(fileTransports).toHaveLength(2);
      expect(fileTransports.map((t) => t.filename)).toEqual([
        'application-%DATE%.log',
        'error-%DATE%.log',
      ]);
      expect(fileTransports.find((t) => t.filename.startsWith('error')).level).toBe('error');
    });

    it('rotates daily and once a file passes 20MB', () => {
      fileTransports.forEach((transport) => {
        expect(transport.options.datePattern).toBe('YYYY-MM-DD');
        expect(transport.options.maxSize).toBe('20m');
        expect(transport.options.maxFiles).toBe('14d');
        expect(transport.options.zippedArchive).toBe(true);
      });
    });

    it('creates the configured log directory', () => {
      expect(LOG_DIR).toBe(tmpDir);
      expect(fs.existsSync(tmpDir)).toBe(true);
    });
  });

  describe('default configuration', () => {
    it('stores logs in the platform logs directory', () => {
      const { LOG_DIR, MAX_SIZE, MAX_FILES } = loadLogger({ NODE_ENV: 'test', LOG_DIR: '' });

      expect(path.basename(LOG_DIR)).toBe('logs');
      expect(MAX_SIZE).toBe('20m');
      expect(MAX_FILES).toBe('14d');
    });
  });
});
