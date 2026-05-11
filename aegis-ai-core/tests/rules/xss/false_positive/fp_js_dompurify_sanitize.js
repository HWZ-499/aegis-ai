/**
 * FP: DOMPurify.sanitize() is a known HTML sanitizer before innerHTML.
 * Expected: no XSS_RISK
 */
function renderSafe(req, target) {
    target.innerHTML = DOMPurify.sanitize(req.query.html);
}
