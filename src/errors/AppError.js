class AppError extends Error {
    constructor(code, message, options = {}) {
        super(message);
        this.name = 'AppError';
        this.code = code;
        this.cause = options.cause;
        this.details = options.details || {};
        this.recoverable = Boolean(options.recoverable);

        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, AppError);
        }
    }
}

module.exports = { AppError };
