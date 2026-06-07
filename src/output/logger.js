const ANSI = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    gray: '\x1b[90m',
};

function createLogger(options = {}) {
    const stdout = options.stdout || process.stdout;
    const stderr = options.stderr || process.stderr;
    const quiet = Boolean(options.quiet);
    const json = Boolean(options.json);
    const colorEnabled = !json && !process.env.NO_COLOR && Boolean(stdout.isTTY);

    function colorize(color, value) {
        if (!colorEnabled || !ANSI[color]) return value;
        return `${ANSI[color]}${value}${ANSI.reset}`;
    }

    function write(stream, value) {
        stream.write(`${value}\n`);
    }

    function jsonEvent(stream, type, payload) {
        write(stream, JSON.stringify({ type, ...payload }));
    }

    return {
        info(message) {
            if (quiet || json) return;
            write(stdout, message);
        },

        debug(message) {
            if (!process.env.VSG_DEBUG || quiet || json) return;
            write(stderr, colorize('gray', `[debug] ${message}`));
        },

        warn(message, details = {}) {
            if (quiet) return;
            if (json) {
                jsonEvent(stderr, 'warning', { message, details });
                return;
            }
            write(stderr, colorize('yellow', `Warning: ${message}`));
        },

        error(message, details = {}) {
            if (json) {
                jsonEvent(stderr, 'error', { message, details });
                return;
            }
            write(stderr, colorize('red', `Error: ${message}`));
        },

        colorize,
    };
}

module.exports = { createLogger };
