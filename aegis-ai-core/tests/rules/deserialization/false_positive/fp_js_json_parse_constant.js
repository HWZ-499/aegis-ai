// FP: Parsing a fixed local JSON string is not untrusted deserialization.
const config = JSON.parse('{"enabled":true}');
