# RFC 8785 Canonical JSON Serialization

Vouch requires bit-for-bit reproducible JSON serialization to ensure signatures remain valid across different programming languages and runtimes.

## Key Rules
1. **Key Sorting**: Object keys are sorted lexicographically by UTF-16 code units.
2. **Whitespace**: No whitespace between tokens (no indent, no space after colon/comma).
3. **Numbers**: IEEE 754 floats serialized without trailing zeros or exponential notation when not needed.
4. **Strings**: Standard JSON escape sequences strictly applied.
