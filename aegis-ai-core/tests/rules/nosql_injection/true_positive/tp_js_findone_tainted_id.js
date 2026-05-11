/**
 * TP: single-key _id query is unsafe when the id variable is tainted.
 * Expected: NOSQL_INJECTION
 */
function findUser(req, users) {
    const id = req.query.id;
    return users.findOne({ _id: id });
}
