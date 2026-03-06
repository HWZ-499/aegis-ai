"""Guard Clause 修复验证脚本"""
from src.analysis.rule_engine import analyze_javascript

CASES = [
    (
        "Guard is_numeric → 0 findings",
        """function handler(req, res) {
  if (!is_numeric(req.body.id)) {
    return res.status(400).send('Bad');
  }
  db.query('SELECT * FROM t WHERE id = ' + req.body.id);
}""",
        True,  # expect_zero
    ),
    (
        "No Guard → SQL finding",
        """function handler(req, res) {
  db.query('SELECT * FROM t WHERE id = ' + req.body.id);
}""",
        False,
    ),
    (
        "validateInput guard → 0 findings",
        """function handler(req, res) {
  if (!validateInput(req.body.name)) return;
  db.query('SELECT * FROM t WHERE name = ' + req.body.name);
}""",
        True,
    ),
    (
        "Guard on id, query uses different field name → SQL finding",
        """function handler(req, res) {
  if (!is_numeric(req.body.id)) return;
  db.query('SELECT * FROM t WHERE name = ' + req.body.name);
}""",
        False,
    ),
    (
        "parseInt sanitize → 0 findings",
        """function handler(req, res) {
  const id = parseInt(req.body.id, 10);
  db.query('SELECT * FROM t WHERE id = ' + id);
}""",
        True,
    ),
]

passed = 0
failed = 0
for label, code, expect_zero in CASES:
    findings = analyze_javascript(code, "test.js")
    ok = (len(findings) == 0) == expect_zero
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"{status}  {label}: {len(findings)} findings (expected {'0' if expect_zero else '>=1'})")

print(f"\n{passed}/{passed + failed} tests passed")
