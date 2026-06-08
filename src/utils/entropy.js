export function shannonEntropy(input) {
  const value = String(input ?? '');

  if (value.length === 0) {
    return 0;
  }

  const frequencies = new Map();
  for (const symbol of value) {
    frequencies.set(symbol, (frequencies.get(symbol) ?? 0) + 1);
  }

  return [...frequencies.values()].reduce((entropy, count) => {
    const probability = count / value.length;
    return entropy - probability * Math.log2(probability);
  }, 0);
}

export function isHighEntropy(value, threshold = 4.0) {
  return shannonEntropy(value) > threshold;
}
