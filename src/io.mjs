// @ts-check

/** @returns {Promise<Record<string, unknown>|null>} */
export async function readJsonFromStdin() {
  /** @type {Buffer[]} */
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? /** @type {Record<string, unknown>} */ (value)
      : null;
  } catch {
    return null;
  }
}

/** @param {unknown} value */
export function writeJson(value) {
  process.stdout.write(JSON.stringify(value));
}
