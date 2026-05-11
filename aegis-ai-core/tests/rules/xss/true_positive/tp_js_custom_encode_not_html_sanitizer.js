/**
 * TP: generic encode() is not proof of HTML escaping before innerHTML.
 * Expected: XSS_RISK
 */
function renderName(req, target) {
    target.innerHTML = encode(req.query.name);
}
