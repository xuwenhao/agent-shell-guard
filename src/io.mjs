// @ts-check

export const MAX_HOOK_INPUT_BYTES = 1024 * 1024;

export class HookInputError extends Error {
  /** @param {'input-too-large'|'input-invalid'} code @param {string} message */
  constructor(code, message) {
    super(message);
    this.name = 'HookInputError';
    this.code = code;
  }
}

/**
 * @param {AsyncIterable<Uint8Array|string>} stream
 * @param {number} [maxBytes]
 * @returns {Promise<Record<string, unknown>>}
 */
export async function readJsonStream(stream, maxBytes = MAX_HOOK_INPUT_BYTES) {
  /** @type {Buffer[]} */
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of stream) {
    const data = Buffer.from(chunk);
    totalBytes += data.length;
    if (totalBytes > maxBytes) {
      throw new HookInputError('input-too-large', `hook input exceeds ${maxBytes} bytes`);
    }
    chunks.push(data);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new HookInputError('input-invalid', 'hook input must be a JSON object');
    }
    return /** @type {Record<string, unknown>} */ (value);
  } catch (error) {
    if (error instanceof HookInputError) throw error;
    throw new HookInputError('input-invalid', 'hook input is not valid JSON');
  }
}

/** @returns {Promise<Record<string, unknown>>} */
export function readJsonFromStdin() {
  return readJsonStream(process.stdin);
}

/** @param {unknown} value */
export function writeJson(value) {
  process.stdout.write(JSON.stringify(value));
}
