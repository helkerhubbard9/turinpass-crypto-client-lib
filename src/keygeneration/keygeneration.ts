
export async function generateRandomKey(length: 128 | 192 | 256 = 256): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      { name: "AES-GCM", length },
      true,
      ["encrypt", "decrypt"]
    );
}

export async function deriveKeyFromPass(
password: string,
salt: Uint8Array,
iterations = 100_000,
length: 256
): Promise<CryptoKey> {
const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return await crypto.subtle.deriveKey(
        {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length },
        true,
        ["encrypt", "decrypt"]
    );
}

export async function wrapKey(
  keyToWrap: CryptoKey,
  wrappingKey: CryptoKey
): Promise<ArrayBuffer> {
  return await crypto.subtle.wrapKey(
    "raw",
    keyToWrap,
    wrappingKey,
    "AES-KW"
  );
}

export async function unwrapKey(
  wrappedKey: ArrayBuffer,
  unwrappingKey: CryptoKey
): Promise<CryptoKey> {
  return await crypto.subtle.unwrapKey(
    "raw",
    wrappedKey,
    unwrappingKey,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}