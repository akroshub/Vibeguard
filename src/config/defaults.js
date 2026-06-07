const WATCHED_EXTENSIONS = new Set([
    '.py',
    '.js',
    '.ts',
    '.jsx',
    '.tsx',
    '.json',
    '.yaml',
    '.yml',
    '.toml',
    '.sh',
    '.txt',
]);

const IGNORED_DIRS = new Set([
    '.git',
    'node_modules',
    '__pycache__',
    '.venv',
    'dist',
    'build',
]);

const IGNORED_FILE_NAMES = new Set(['.env']);
const IGNORED_FILE_SUFFIXES = ['.example', '.template'];

module.exports = {
    WATCHED_EXTENSIONS,
    IGNORED_DIRS,
    IGNORED_FILE_NAMES,
    IGNORED_FILE_SUFFIXES,
};
