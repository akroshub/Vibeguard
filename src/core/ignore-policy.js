const path = require('node:path');
const {
    WATCHED_EXTENSIONS,
    IGNORED_DIRS,
    IGNORED_FILE_NAMES,
    IGNORED_FILE_SUFFIXES,
} = require('../config/defaults');

function pathParts(filepath) {
    return filepath.split(/[\\/]+/).filter(Boolean);
}

function isIgnoredPath(filepath) {
    const name = path.basename(filepath);

    if (IGNORED_FILE_NAMES.has(name)) return true;
    if (IGNORED_FILE_SUFFIXES.some((suffix) => name.endsWith(suffix))) return true;

    return pathParts(filepath).some((part) => IGNORED_DIRS.has(part));
}

function isIgnoredDirectoryName(name) {
    return IGNORED_DIRS.has(name);
}

function hasWatchedExtension(filepath) {
    return WATCHED_EXTENSIONS.has(path.extname(filepath).toLowerCase());
}

function shouldScanFile(filepath) {
    return !isIgnoredPath(filepath) && hasWatchedExtension(filepath);
}

function getWatchIgnoredPatterns() {
    return Array.from(IGNORED_DIRS).map((dir) => `**/${dir}/**`);
}

module.exports = {
    isIgnoredPath,
    isIgnoredDirectoryName,
    hasWatchedExtension,
    shouldScanFile,
    getWatchIgnoredPatterns,
};
