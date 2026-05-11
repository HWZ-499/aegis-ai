/**
 * TP: child_process alias still invokes command execution with user input.
 * Expected: RCE_COMMAND_EXEC
 */
const cp = require("child_process");

function runCommand(req) {
    cp.exec(req.query.cmd);
}
