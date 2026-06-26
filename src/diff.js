function diffSets(prevValues, curValues) {
  const prevSet = new Set(prevValues);
  const curSet = new Set(curValues);
  const added = [...curSet].filter((x) => !prevSet.has(x));
  const removed = [...prevSet].filter((x) => !curSet.has(x));
  return { added, removed };
}

module.exports = { diffSets };
