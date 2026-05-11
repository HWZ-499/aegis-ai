/**
 * FP: single-key _id lookup with a local constant should stay quiet.
 * Expected: no NOSQL_INJECTION
 */
function findSystemUser(users) {
    const id = "507f1f77bcf86cd799439011";
    return users.findOne({ _id: id });
}
