/**
 * TP: destructured child_process exec() is command execution.
 * Expected: RCE_COMMAND_EXEC
 */
const { exec } = require("child_process");

function runCommand(req) {
    exec(req.query.cmd);
}
