LESSONS = {
    "hmac_failure": "Goal: observe integrity enforcement. Tampered ciphertext should trigger auth failure before decryption.",
    "shared_memory_leak": "Goal: reason about memory exposure. Shared memory can leak sensitive data unless payloads are encrypted before write.",
    "replay_attack": "Goal: detect replay behavior. Replayed ciphertext can look valid unless sequence/nonce checks are enforced.",
    "key_mismatch": "Goal: diagnose key drift. Sender/receiver key mismatch causes decrypt failure even if transport succeeds.",
    "race_condition": "Goal: study timing hazards. Unsynchronized startup can cause flaky reads and inconsistent IPC behavior.",
    "drop_packet": "Goal: assess availability impact. Dropped packets reduce delivery completeness and can mask downstream faults.",
}
