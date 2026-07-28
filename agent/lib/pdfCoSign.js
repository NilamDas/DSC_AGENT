const { PDFDocument } = require('pdf-lib');
const {
  ANNOTATION_FLAGS,
  DEFAULT_BYTE_RANGE_PLACEHOLDER,
  DEFAULT_SIGNATURE_LENGTH,
  PDFKitReferenceMock,
  PDFObject,
  SIG_FLAGS,
  SUBFILTER_ADOBE_PKCS7_DETACHED,
} = require('@signpdf/utils');
const readPdf = require('@signpdf/placeholder-plain/dist/readPdf').default;
const findObject = require('@signpdf/placeholder-plain/dist/findObject').default;
const getIndexFromRef = require('@signpdf/placeholder-plain/dist/getIndexFromRef').default;
const createBufferPageWithAnnotation = require('@signpdf/placeholder-plain/dist/createBufferPageWithAnnotation').default;
const createBufferTrailer = require('@signpdf/placeholder-plain/dist/createBufferTrailer').default;

function countPdfSignatures(pdfBytes) {
  return (Buffer.from(pdfBytes).toString('binary').match(/\/ByteRange\s*\[/g) || []).length;
}

function assertCoSignablePdf(pdfBytes) {
  const source = Buffer.from(pdfBytes);
  const text = source.toString('binary');
  if (!text.startsWith('%PDF-')) throw new Error('Input is not a PDF document.');
  if (countPdfSignatures(source) < 1) {
    throw new Error('Co-signing requires a PDF that already contains a digital signature.');
  }
  if (/\/ByteRange\s*\[\s*0\s+\/\*{10}/.test(text)) {
    throw new Error('Input PDF contains an unsigned signature placeholder.');
  }
  if (/\/TransformMethod\s*\/DocMDP[\s\S]{0,500}\/P\s+1\b/.test(text)) {
    throw new Error('The existing certification signature does not permit additional signatures.');
  }
}

function escapePdfText(value) {
  return String(value || '')
    .replace(/[^\x20-\x7e]/g, '?')
    .replace(/([\\()])/g, '\\$1');
}

function formatAppearanceTime(value) {
  const date = value instanceof Date && !Number.isNaN(value.getTime()) ? value : new Date();
  const pad = (number) => String(number).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function parseRefs(value) {
  const refs = [];
  const regex = /(\d+)\s+(\d+)\s+R/g;
  let match;
  while ((match = regex.exec(String(value || ''))) !== null) {
    refs.push(`${match[1]} ${match[2]} R`);
  }
  return refs;
}

function updateDictionaryEntry(dictionary, key, value, pattern) {
  const source = String(dictionary || '');
  if (pattern.test(source)) return source.replace(pattern, `/${key} ${value}`);
  return `${source.trim()}\n/${key} ${value}\n`;
}

function appendObject(pdf, addedReferences, objectNumber, body) {
  addedReferences.set(objectNumber, pdf.length + 1);
  return Buffer.concat([
    pdf,
    Buffer.from(`\n${objectNumber} 0 obj\n${body}\nendobj\n`, 'binary'),
  ]);
}

function normalizePageRequest(pageRequest, pageCount) {
  if (pageRequest === undefined || pageRequest === null || pageRequest === '' || pageRequest === 'last') {
    return pageCount - 1;
  }
  const pageNumber = Number.parseInt(pageRequest, 10);
  if (!Number.isFinite(pageNumber) || pageNumber < 1 || pageNumber > pageCount) {
    throw new Error(`page must be between 1 and ${pageCount}, or "last".`);
  }
  return pageNumber - 1;
}

function normalizeWidgetRect(rect, rectMode, pageSize, existingSignatureCount) {
  const defaultWidth = Math.min(250, Math.max(80, pageSize.width - 72));
  const defaultHeight = 50;
  if (!Array.isArray(rect) || (rect.length !== 2 && rect.length !== 4)) {
    const gap = 8;
    const usableWidth = Math.max(defaultWidth, pageSize.width - 72);
    const columns = Math.max(1, Math.floor((usableWidth + gap) / (defaultWidth + gap)));
    const slot = Math.max(0, existingSignatureCount);
    const column = slot % columns;
    const row = Math.floor(slot / columns);
    const x2 = Math.max(defaultWidth, pageSize.width - 36 - (column * (defaultWidth + gap)));
    const y1 = Math.min(
      Math.max(0, pageSize.height - defaultHeight),
      36 + (row * (defaultHeight + gap)),
    );
    return [
      Math.max(0, x2 - defaultWidth),
      y1,
      Math.min(pageSize.width, x2),
      Math.min(pageSize.height, y1 + defaultHeight),
    ];
  }

  const values = rect.map(Number);
  if (values.some((value) => !Number.isFinite(value))) throw new Error('rect must contain numeric values.');
  if (String(rectMode || '').toLowerCase() === 'top-left' || rect.length === 2) {
    const width = rect.length === 4 ? Math.max(1, values[2]) : defaultWidth;
    const height = rect.length === 4 ? Math.max(1, values[3]) : defaultHeight;
    const x1 = Math.max(0, values[0]);
    const y2 = Math.min(pageSize.height, pageSize.height - Math.max(0, values[1]));
    return [x1, Math.max(0, y2 - height), Math.min(pageSize.width, x1 + width), y2];
  }

  const x1 = Math.max(0, Math.min(pageSize.width, values[0]));
  const y1 = Math.max(0, Math.min(pageSize.height, values[1]));
  const x2 = Math.max(x1 + 1, Math.min(pageSize.width, values[2]));
  const y2 = Math.max(y1 + 1, Math.min(pageSize.height, values[3]));
  return [x1, y1, x2, y2];
}

async function addIncrementalSignaturePlaceholder(pdfBytes, options = {}) {
  const original = Buffer.from(pdfBytes);
  assertCoSignablePdf(original);

  const parsedDocument = await PDFDocument.load(original, { updateMetadata: false });
  const pages = parsedDocument.getPages();
  const pageIndex = normalizePageRequest(options.page, pages.length);
  const targetPage = pages[pageIndex];
  const targetPageRef = `${targetPage.ref.objectNumber} ${targetPage.ref.generationNumber} R`;
  const pageSize = targetPage.getSize();
  const existingSignatureCount = countPdfSignatures(original);
  const widgetRect = normalizeWidgetRect(options.rect, options.rectMode, pageSize, existingSignatureCount);
  const width = Math.max(1, widgetRect[2] - widgetRect[0]);
  const height = Math.max(1, widgetRect[3] - widgetRect[1]);

  const info = readPdf(original);
  const pageObjectNumber = getIndexFromRef(info.xref, targetPageRef);
  const rootObjectNumber = getIndexFromRef(info.xref, info.rootRef);
  const addedReferences = new Map();
  let pdf = Buffer.from(original);
  let nextObjectNumber = info.xref.maxIndex + 1;

  const signatureObjectNumber = nextObjectNumber++;
  const fontObjectNumber = nextObjectNumber++;
  const appearanceObjectNumber = nextObjectNumber++;
  const widgetObjectNumber = nextObjectNumber++;

  const signatureRef = new PDFKitReferenceMock(signatureObjectNumber);
  const fontRef = new PDFKitReferenceMock(fontObjectNumber);
  const appearanceRef = new PDFKitReferenceMock(appearanceObjectNumber);
  const widgetRef = new PDFKitReferenceMock(widgetObjectNumber);
  const signatureLength = Number.isFinite(options.signatureLength)
    ? Math.max(8192, Math.floor(options.signatureLength))
    : DEFAULT_SIGNATURE_LENGTH;

  const signatureDictionary = PDFObject.convert({
    Type: 'Sig',
    Filter: 'Adobe.PPKLite',
    SubFilter: options.subFilter || SUBFILTER_ADOBE_PKCS7_DETACHED,
    ByteRange: [0, DEFAULT_BYTE_RANGE_PLACEHOLDER, DEFAULT_BYTE_RANGE_PLACEHOLDER, DEFAULT_BYTE_RANGE_PLACEHOLDER],
    Contents: Buffer.alloc(signatureLength),
    Reason: new String(options.reason || 'Co-signed via DSC Agent'),
    M: options.signingTime instanceof Date ? options.signingTime : new Date(),
    ContactInfo: new String(options.contactInfo || ''),
    Name: new String(options.name || ''),
    Location: new String(options.location || ''),
    Prop_Build: { Filter: { Name: 'Adobe.PPKLite' }, App: { Name: new String('DSC Agent') } },
  });
  pdf = appendObject(pdf, addedReferences, signatureObjectNumber, signatureDictionary);

  const fontDictionary = PDFObject.convert({ Type: 'Font', Subtype: 'Type1', BaseFont: 'Helvetica' });
  pdf = appendObject(pdf, addedReferences, fontObjectNumber, fontDictionary);

  const maxCharacters = Math.max(8, Math.floor((width - 12) / 5.2));
  const fitText = (value) => {
    const text = String(value || '');
    return text.length <= maxCharacters ? text : `${text.slice(0, Math.max(1, maxCharacters - 3))}...`;
  };
  const line1 = escapePdfText(fitText(`Digitally signed by ${options.name || 'Unknown'}`));
  const line2 = escapePdfText(fitText(`Date: ${formatAppearanceTime(options.signingTime)}`));
  const textTop = Math.max(12, height - 17);
  const textBottom = Math.max(3, textTop - 14);
  const appearanceStream = [
    'q',
    `1 1 1 rg 0 0 ${width.toFixed(2)} ${height.toFixed(2)} re f`,
    '0 0 0 rg',
    'BT',
    `/F1 10 Tf 6 ${textTop.toFixed(2)} Td (${line1}) Tj`,
    `0 -14 Td (${line2}) Tj`,
    'ET',
    'Q',
  ].join('\n');
  const appearanceDictionary = PDFObject.convert({
    Type: 'XObject',
    Subtype: 'Form',
    FormType: 1,
    BBox: [0, 0, width, height],
    Resources: { Font: { F1: fontRef } },
    Length: Buffer.byteLength(appearanceStream, 'binary'),
    stream: appearanceStream,
  });
  pdf = appendObject(pdf, addedReferences, appearanceObjectNumber, appearanceDictionary);

  const rootDictionary = findObject(original, info.xref, info.rootRef).toString('binary');
  const acroFormMatch = /\/AcroForm\s+(\d+)\s+(\d+)\s+R/.exec(rootDictionary);
  let acroFormObjectNumber;
  let existingFieldRefs = [];
  if (acroFormMatch) {
    acroFormObjectNumber = Number.parseInt(acroFormMatch[1], 10);
    const acroFormRef = `${acroFormMatch[1]} ${acroFormMatch[2]} R`;
    const acroFormDictionary = findObject(original, info.xref, acroFormRef).toString('binary');
    const fieldsMatch = /\/Fields\s*\[([\s\S]*?)\]/.exec(acroFormDictionary);
    if (!fieldsMatch) throw new Error('Existing AcroForm uses an unsupported Fields structure.');
    existingFieldRefs = parseRefs(fieldsMatch[1]);
  } else {
    acroFormObjectNumber = nextObjectNumber++;
  }

  const signatureName = `Signature${existingFieldRefs.length + 1}`;
  const widgetDictionary = PDFObject.convert({
    Type: 'Annot',
    Subtype: 'Widget',
    FT: 'Sig',
    Rect: widgetRect,
    V: signatureRef,
    T: new String(signatureName),
    F: ANNOTATION_FLAGS.PRINT,
    P: new PDFKitReferenceMock(pageObjectNumber),
    AP: { N: appearanceRef },
  });
  pdf = appendObject(pdf, addedReferences, widgetObjectNumber, widgetDictionary);

  if (acroFormMatch) {
    const acroFormRef = `${acroFormMatch[1]} ${acroFormMatch[2]} R`;
    const originalAcroForm = findObject(original, info.xref, acroFormRef).toString('binary');
    let updatedAcroForm = updateDictionaryEntry(
      originalAcroForm,
      'Fields',
      `[${[...existingFieldRefs, widgetRef.toString()].join(' ')}]`,
      /\/Fields\s*\[[\s\S]*?\]/,
    );
    updatedAcroForm = updateDictionaryEntry(
      updatedAcroForm,
      'SigFlags',
      String(SIG_FLAGS.SIGNATURES_EXIST | SIG_FLAGS.APPEND_ONLY),
      /\/SigFlags\s+\d+/,
    );
    pdf = appendObject(pdf, addedReferences, acroFormObjectNumber, `<<\n${updatedAcroForm.trim()}\n>>`);
  } else {
    const acroFormDictionary = PDFObject.convert({
      Type: 'AcroForm',
      SigFlags: SIG_FLAGS.SIGNATURES_EXIST | SIG_FLAGS.APPEND_ONLY,
      Fields: [widgetRef],
    });
    pdf = appendObject(pdf, addedReferences, acroFormObjectNumber, acroFormDictionary);
    const updatedRoot = updateDictionaryEntry(
      rootDictionary,
      'AcroForm',
      `${acroFormObjectNumber} 0 R`,
      /\/AcroForm\s+\d+\s+\d+\s+R/,
    );
    pdf = appendObject(pdf, addedReferences, rootObjectNumber, `<<\n${updatedRoot.trim()}\n>>`);
  }

  const pageUpdate = createBufferPageWithAnnotation(pdf, info, targetPageRef, widgetRef);
  addedReferences.set(pageObjectNumber, pdf.length + 1);
  pdf = Buffer.concat([pdf, Buffer.from('\n'), pageUpdate]);

  info.xref.maxIndex = Math.max(info.xref.maxIndex, nextObjectNumber - 1);
  pdf = Buffer.concat([pdf, Buffer.from('\n'), createBufferTrailer(pdf, info, addedReferences)]);
  if (!pdf.subarray(0, original.length).equals(original)) {
    throw new Error('Incremental co-sign preparation changed existing PDF bytes.');
  }
  return { pdf, page: pageIndex + 1, rect: widgetRect, signatureCount: countPdfSignatures(pdf) };
}

module.exports = {
  addIncrementalSignaturePlaceholder,
  assertCoSignablePdf,
  countPdfSignatures,
};
