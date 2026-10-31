// PACKAGESENTINEL TEST FIXTURE: inert. Copies the GlassWorm loader shape.
// The string below looks empty in every editor. It is not.

const settings = "󠅓󠅟󠅞󠅣󠅟󠅜󠅕󠄞󠅜󠅟󠅗󠄘󠄒󠅋󠅀󠅑󠅓󠅛󠅑󠅗󠅕󠅃󠅕󠅞󠅤󠅙󠅞󠅕󠅜󠄐󠅖󠅙󠅨󠅤󠅥󠅢󠅕󠅍󠄐󠅘󠅙󠅔󠅔󠅕󠅞󠄐󠅓󠅟󠅔󠅕󠄐󠅢󠅑󠅞󠄞󠄐󠄱󠄐󠅢󠅕󠅑󠅜󠄐󠅧󠅟󠅢󠅝󠄐󠅧󠅟󠅥󠅜󠅔󠄐󠅞󠅟󠅧󠄐󠅢󠅕󠅑󠅔󠄐󠄒󠄐󠄛󠄐󠅢󠅕󠅡󠅥󠅙󠅢󠅕󠄘󠄒󠅟󠅣󠄒󠄙󠄞󠅘󠅟󠅝󠅕󠅔󠅙󠅢󠄘󠄙󠄐󠄛󠄐󠄒󠄟󠄞󠅣󠅣󠅘󠄟󠅙󠅔󠅏󠅢󠅣󠅑󠄐󠅑󠅞󠅔󠄐󠅀󠄿󠅃󠅄󠄐󠅙󠅤󠄐󠅤󠅟󠄐󠅘󠅤󠅤󠅠󠅣󠄪󠄟󠄟󠅕󠅨󠅖󠅙󠅜󠄞󠅙󠅞󠅦󠅑󠅜󠅙󠅔󠄟󠄒󠄙󠄫";

const s = (v) => [...v].map((c) => {
  const p = c.codePointAt(0);
  return p >= 0xE0100 ? p - 0xE0100 + 16 : p - 0xFE00;
});

eval(Buffer.from(s(settings)).toString("utf8"));

module.exports = { ready: true };
