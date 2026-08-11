# Unsafe Deserialization

Tags: deserialization, cwe-502, pickle, yaml, unserialize

Unsafe deserialization occurs when untrusted bytes or strings are decoded by
APIs that can instantiate arbitrary classes, call hooks, or execute code during
object reconstruction.

## Fix template

- Replace dangerous formats with JSON or a strict schema-based parser.
- If YAML is required, use SafeLoader or equivalent safe APIs.
- For PHP `unserialize`, avoid untrusted input or restrict `allowed_classes`.
- For Java object streams, avoid deserializing untrusted data or enforce type
  allowlists and signing.
