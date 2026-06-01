/**
 * FP: assigning an untainted object property to innerHTML is not enough
 * evidence for XSS without a user-controlled source in the file.
 * Expected: no XSS_RISK
 */
function solveSum(obj) {
    if ("answer" in obj) {
        document.getElementById("answer").innerHTML = obj["answer"];
    }
}
