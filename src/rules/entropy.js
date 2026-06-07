const { shannonEntropy } = require('../utils/entropy');

const ENTROPY_THRESHOLD = 4.5;
const ENTROPY_MIN_LENGTH = 32;
const ASSIGNED_STRING_RE = /(?:^|[\s,{])(?:(?:const|let|var|export\s+const)\s+)?["']?([A-Za-z0-9_.-]{3,80})["']?\s*(?:=|:)\s*(['"])([^'"]{32,})\2/g;
const SECRETISH_NAME_RE = /(?:secret|token|api[_-]?key|apikey|password|passwd|private[_-]?key|client[_-]?secret|credential|auth)/i;
const FALSE_POSITIVE_NAMES = new Set([
    'description',
    'integrity',
    'license',
    'name',
    'resolved',
    'url',
    'version',
]);

function isUuid(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isPackageIntegrity(value) {
    return /^(sha1|sha256|sha384|sha512)-[A-Za-z0-9+/=]+$/i.test(value);
}

function looksLikeEnglishSentence(value) {
    const words = value.trim().split(/\s+/);
    if (words.length < 5) return false;

    const sentenceChars = value.replace(/[A-Za-z0-9\s.,;:'"!?()[\]-]/g, '');
    const spaceRatio = (value.match(/\s/g) || []).length / value.length;
    return sentenceChars.length === 0 && spaceRatio > 0.08;
}

function isFalsePositive(name, value) {
    const normalizedName = name.toLowerCase();
    if (FALSE_POSITIVE_NAMES.has(normalizedName)) return true;
    if (isUuid(value)) return true;
    if (isPackageIntegrity(value)) return true;
    if (/^https?:\/\//i.test(value)) return true;
    if (looksLikeEnglishSentence(value)) return true;
    return false;
}

const entropyRules = [
    {
        id: 'GENERIC_SECRET',
        description: 'High-entropy secret string',
        severity: 'medium',
        envVarName: 'SECRET_KEY',
        detect(context) {
            const findings = [];
            ASSIGNED_STRING_RE.lastIndex = 0;

            let match;
            while ((match = ASSIGNED_STRING_RE.exec(context.line)) !== null) {
                const name = match[1];
                const value = match[3];
                if (context.isPlaceholder(value) || value.length < ENTROPY_MIN_LENGTH) continue;
                if (!SECRETISH_NAME_RE.test(name) && shannonEntropy(value) < 5.0) continue;
                if (isFalsePositive(name, value)) continue;
                if (shannonEntropy(value) <= ENTROPY_THRESHOLD) continue;

                const alreadyCaught = context.existingFindings.some((finding) => {
                    return finding.match.includes(value) || value.includes(finding.match);
                });

                if (!alreadyCaught) {
                    findings.push({ match: value });
                }
            }

            return findings;
        },
    },
];

module.exports = { entropyRules };
