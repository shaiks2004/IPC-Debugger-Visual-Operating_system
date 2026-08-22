LESSONS = {
    "hmac_failure": "If ciphertext is altered, integrity verification fails and decryption is blocked.",
    "shared_memory_leak": "Shared memory exposes plaintext risk unless data is encrypted before writing.",
    "replay_attack": "Replay attacks resend old valid ciphertext; nonce or sequence validation is required.",
    "key_mismatch": "If sender and receiver keys differ, decryption fails and authenticity cannot be established.",
    "race_condition": "Race conditions can make consumers read too early; synchronization avoids flaky behavior.",
}
