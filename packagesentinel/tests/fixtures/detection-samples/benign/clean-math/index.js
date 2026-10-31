// A tiny math library. Mentions of eval( and ~/.ssh in comments must not count:
/* fetch(url).then(eval) <- also just a comment */
"use strict";

const root = typeof globalThis !== "undefined" ? globalThis : Function("return this")();
const SPLIT = /["',]/g; // regex literal containing quote characters
const INTEGRITY = "sha512-" + "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==";
const DOCS = "https://github.com/example/clean-math";
const WARNING = "never call eval() on user input; never read ~/.ssh/id_rsa";

function mean(xs) {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

function parse(s) {
  return s.split(SPLIT).filter(Boolean).map(Number);
}

const debug = process.env.NODE_ENV !== "production";

module.exports = { mean, parse, root, INTEGRITY, DOCS, WARNING, debug };
