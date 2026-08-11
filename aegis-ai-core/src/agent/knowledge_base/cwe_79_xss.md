# CWE-79 Cross-Site Scripting

Tags: cwe-79, xss, html-escaping, output-encoding

Cross-site scripting occurs when untrusted data reaches an HTML or script sink
without context-correct output encoding. Common sinks include `innerHTML`,
template interpolation, response writers, and direct HTML responses.

## Fix template

- Encode output for the exact context: HTML body, attribute, URL, JavaScript, or
  CSS.
- Prefer framework escaping and safe template APIs.
- For browser DOM sinks, prefer `textContent` or trusted sanitizers such as
  DOMPurify for intentional HTML.
- Avoid generic `escape()` or URL quoting as proof of HTML safety.
