const fs = require('fs');
const path = require('path');
async function main() {
  const file = process.argv[2] || path.resolve(process.cwd(), 'signed.pdf');
  if (!fs.existsSync(file)) {
    console.log('file not found:', file);
    process.exit(1);
  }
  const { PDFDocument } = require('pdf-lib');
  const { PDFName } = require('pdf-lib/cjs/core');
  const buf = fs.readFileSync(file);
  const doc = await PDFDocument.load(buf);
  const ctx = doc.context;
  const acro = doc.catalog.lookup(PDFName.of('AcroForm'));
  if (!acro) { console.log('No AcroForm'); return; }
  const fields = acro.lookup(PDFName.of('Fields'));
  const count = fields && fields.size ? fields.size() : (fields && fields.array ? fields.array.length : 0);
  console.log('Fields count:', count);
  for (let i = 0; i < count; i++) {
    const ref = fields.get ? fields.get(i) : fields.array[i];
    console.log('  item type:', ref && ref.constructor && ref.constructor.name);
    let field = null;
    try { field = ctx.lookup(ref); } catch (e) { console.log('  lookup failed:', e.message); continue; }
    let ft = null, t = null, v = null;
    try { ft = field.lookup ? field.lookup(PDFName.of('FT')) : null; } catch (e) { console.log('  FT lookup failed:', e.message); }
    try { t = field.lookup ? field.lookup(PDFName.of('T')) : null; } catch (e) { console.log('  T lookup failed:', e.message); }
    try { v = field.lookup ? field.lookup(PDFName.of('V')) : null; } catch (e) { console.log('  V lookup failed:', e.message); }
    console.log(`Field[${i}] FT=${ft ? ft.toString() : ''} T=${t && t.decodeText ? t.decodeText() : ''} hasV=${!!v}`);
    if (v) {
      let cont = null, br = null;
      try { cont = v.lookup ? v.lookup(PDFName.of('Contents')) : null; } catch (e) { console.log('  V->Contents lookup failed:', e.message); }
      try { br = v.lookup ? v.lookup(PDFName.of('ByteRange')) : null; } catch (e) { console.log('  V->ByteRange lookup failed:', e.message); }
      console.log('  V has Contents:', !!cont, 'ByteRange:', !!br);
      if (cont && cont.asString) {
        const s = cont.asString();
        console.log('  Contents length (string):', s.length);
      }
    }
  }
}
main().catch(e => { console.error('ERR', e); process.exit(1); });
