# Path Traversal

Tags: path-traversal, cwe-22, files, uploads

Path traversal happens when user-controlled path segments reach file APIs such
as open, read, copy, rename, download, or upload destination paths.

## Fix template

- Resolve the final path and prove it remains inside an allowed base directory.
- Use allowlisted file identifiers instead of direct paths when possible.
- Strip or reject separators, drive prefixes, absolute paths, and traversal
  segments for filename-only inputs.
- Path normalization alone is not enough; it must be paired with a safe root
  containment check.
