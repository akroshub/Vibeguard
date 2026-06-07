function shannonEntropy(input) {
    const value = String(input || '');
    if (!value) return 0;

    const frequencies = {};
    for (const char of value) {
        frequencies[char] = (frequencies[char] || 0) + 1;
    }

    const length = value.length;
    return Object.values(frequencies).reduce((total, count) => {
        const probability = count / length;
        return total - probability * Math.log2(probability);
    }, 0);
}

module.exports = { shannonEntropy };
