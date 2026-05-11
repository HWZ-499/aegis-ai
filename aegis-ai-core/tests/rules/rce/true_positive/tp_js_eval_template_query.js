/**
 * TP: dynamic template string passed to eval() is code injection risk.
 * Expected: RCE_COMMAND_EXEC
 */
function runTemplate(req) {
    return eval(`${req.query.code}`);
}
