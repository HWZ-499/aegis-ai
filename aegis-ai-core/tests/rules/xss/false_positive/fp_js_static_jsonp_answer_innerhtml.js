/*
 * FP: A fixed same-origin JSONP endpoint returns a numeric answer object to a
 * fixed callback. This is not the same as assigning arbitrary user input to
 * innerHTML.
 */
function clickButton() {
    var s = document.createElement("script");
    s.src = "source/jsonp_impossible.php";
    document.body.appendChild(s);
}

function solveSum(obj) {
    if ("answer" in obj) {
        document.getElementById("answer").innerHTML = obj['answer'];
    }
}

clickButton();
