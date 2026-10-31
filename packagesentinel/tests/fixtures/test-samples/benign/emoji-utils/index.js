// Starts with a BOM, which is fine.
const VS16 = 0xfe0f; // emoji presentation selector
const strip = (s) => s.replace(/\uFE0F/g, "");
const root = Function("return this")(); // common globalThis polyfill

const samples = {
  heart: "❤️",                                  // ❤ + VS16
  family: "👨‍👩‍👧",   // ZWJ sequence
  rainbow: "🏳️‍🌈",            // VS16 + ZWJ
  keycap: "1️⃣",
  england: "🏴󠁧󠁢󠁥󠁮󠁧󠁿",  // subdivision flag
  kanji: "葛󠄀",                               // ideographic variant
  hindi: "क्‍ष",                        // ZWJ in Devanagari
  persian: "می‌خواهم",  // ZWNJ in Persian
};

module.exports = { samples, strip, VS16, root };
