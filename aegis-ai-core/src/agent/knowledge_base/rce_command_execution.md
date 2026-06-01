# Command Execution and RCE

Tags: rce, command-execution, cwe-78, shell

Command execution vulnerabilities appear when user input controls executable
paths, shell command strings, interpreter eval flags, or dynamic code
evaluation.

## Fix template

- Avoid shell invocation for user-controlled operations.
- Use fixed executable names and pass user input only as data arguments when the
  target command treats them as data.
- Prefer allowlisted operations over raw commands.
- Validate interpreter flags such as `-c`, `-e`, or script snippets carefully.
- Use language-native APIs instead of invoking shell utilities.
