/**
 * TP: JSON.parse() on request body data is unsafe deserialization.
 * Expected: DESERIALIZATION
 */
function parsePayload(req) {
    return JSON.parse(req.body.payload);
}
