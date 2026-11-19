import PDFDocument from 'pdfkit';
import QRCode from 'qrcode';
import crypto from 'crypto';

function fmtNum(n) {
  return new Intl.NumberFormat('es-CO', { maximumFractionDigits: 0 }).format(n || 0);
}
function padRight(str, n) {
  return String(str).substring(0, n).padEnd(n, ' ');
}
function padLeft(str, n) {
  return String(str).substring(0, n).padStart(n, ' ');
}

export async function generarFacturaPDF(venta, lineas, res) {
  const FERRETERIA = {
    nombre:       process.env.FERRETERIA_NOMBRE || 'FerreStock Demo S.A.S.',
    nit:          process.env.FERRETERIA_NIT    || '900.123.456-7',
    dir:          process.env.FERRETERIA_DIR    || 'Calle 10 #20-30, Bogota',
    tel:          process.env.FERRETERIA_TEL    || '300 123 4567',
    resolucion:   process.env.FERRETERIA_RESOLUCION || 'Resolucion DIAN 165 de 2023',
    rango:        process.env.FERRETERIA_RANGO  || 'POS-000001 al POS-999999',
    claveTecnica: process.env.FERRETERIA_CLAVE_TECNICA || 'fc8eac422eba16e22ffd8c6f94b3f40a6e38162c',
  };

  // ===== CUFE (SHA-384) =====
  const cufe = crypto.createHash('sha384')
    .update([
      FERRETERIA.nit,
      `POS-${String(venta.id_venta).padStart(6, '0')}`,
      venta.fecha_hora,
      venta.total,
      venta.iva,
      venta.subtotal,
      FERRETERIA.claveTecnica,
    ].join('|'))
    .digest('hex')
    .substring(0, 96);

  const qrContent = `https://catalogo-vpfe.dian.gov.co/document/searchqr?documentkey=${cufe}`;

  const qrBuffer = await QRCode.toBuffer(qrContent, {
    width: 200,
    margin: 0,
    errorCorrectionLevel: 'M',
    color: { dark: '#000000', light: '#FFFFFF' },
  });

  // ===== 58mm = 170pt de ancho, altura dinámica =====
  const numLineas = 15 + lineas.length * 1.5;
  const altura = Math.min(1800, Math.max(750, Math.round(numLineas * 11 + 60 + 180)));

  const doc = new PDFDocument({
    size: [170, altura],  // 58mm
    margins: { top: 6, bottom: 6, left: 6, right: 6 },
    info: {
      Title: `POS-${venta.id_venta}`,
      Author: FERRETERIA.nombre,
      Subject: `CUFE: ${cufe}`,
    },
  });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="POS-${String(venta.id_venta).padStart(6, '0')}.pdf"`
  );
  doc.pipe(res);

  const ANCHO = 158;      // 170 - márgenes (6*2)
  const CHARS = 43;       // caracteres que caben a Courier 6
  const SEP  = '-'.repeat(CHARS);
  const SEP2 = '='.repeat(CHARS);
  const GAP  = 3;

  // ===== Helpers =====
  const linea = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier').text(txt, 6, y, { width: ANCHO, lineBreak: false });
    doc.y = y + size + 2;
  };
  const centro = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier').text(txt, 6, y, { width: ANCHO, align: 'center', lineBreak: false });
    doc.y = y + size + 2;
  };
  const negrita = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier-Bold').text(txt, 6, y, { width: ANCHO, lineBreak: false });
    doc.y = y + size + 2;
  };
  const negritaCentro = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier-Bold').text(txt, 6, y, { width: ANCHO, align: 'center', lineBreak: false });
    doc.y = y + size + 2;
  };
  // Para textos que pueden ser largos y necesitan wrapping
  const wrapCentro = (txt, size = 6) => {
    doc.fontSize(size).font('Courier').text(txt, 6, doc.y, { width: ANCHO, align: 'center' });
  };

  // ===== ENCABEZADO =====
  negritaCentro(FERRETERIA.nombre.toUpperCase(), 7);
  wrapCentro(`NIT: ${FERRETERIA.nit}`, 6);
  wrapCentro(FERRETERIA.dir, 6);
  centro(`Tel: ${FERRETERIA.tel}`, 6);
  doc.y += GAP;
  centro(SEP2, 6);
  negritaCentro('DOCUMENTO EQUIVALENTE', 6);
  negritaCentro('TIQUETE POS ELECTRONICO', 6);
  centro(SEP2, 6);
  doc.y += GAP;

  // ===== DATOS DEL TIQUETE =====
  linea(`Tiquete: POS-${String(venta.id_venta).padStart(6, '0')}`, 6);
  linea(`Fecha: ${String(venta.fecha_hora).slice(0, 16)}`, 6);
  linea(`Cajero: ${venta.cajero || 'admin'}`, 6);
  doc.y += GAP;
  linea(SEP, 6);
  doc.y += GAP;

  // ===== CLIENTE =====
  linea(`Cliente: ${venta.cliente}`, 6);
  if (venta.numero_documento) {
    linea(`${venta.tipo_documento || 'CC'}: ${venta.numero_documento}`, 6);
  }
  doc.y += GAP;
  linea(SEP, 6);
  doc.y += GAP;

  // ===== CABECERA PRODUCTOS =====
  // CANT(3) + SP + DESC(24) + SP + TOTAL(14) = 43
  negrita(`${padRight('CANT', 3)} ${padRight('DESCRIPCION', 24)} ${padLeft('TOTAL', 14)}`, 6);
  linea(SEP, 6);

  // ===== PRODUCTOS =====
  lineas.forEach(l => {
    const cant  = padLeft(String(Number(l.cantidad)), 3);
    const desc  = padRight(String(l.nombre), 24);
    const total = padLeft(fmtNum(l.subtotal_linea), 14);
    linea(`${cant} ${desc} ${total}`, 6);
    if (Number(l.cantidad) > 1) {
      const sub = `      ${padLeft(String(Number(l.cantidad)), 3)} x ${padLeft(fmtNum(l.precio_unitario), 10)} c/u`;
      linea(sub, 5);
    }
  });

  doc.y += GAP;
  linea(SEP, 6);
  doc.y += GAP;

  // ===== TOTALES =====
  linea(`${padRight('Subtotal:', 28)} ${padLeft(fmtNum(venta.subtotal), 14)}`, 6);
  linea(`${padRight('IVA 19%:', 28)} ${padLeft(fmtNum(venta.iva), 14)}`, 6);
  doc.y += GAP;
  negrita(`${padRight('TOTAL:', 28)} ${padLeft(fmtNum(venta.total), 14)}`, 7);
  doc.y += GAP;
  linea(SEP2, 6);
  doc.y += GAP;

  // ===== FORMA DE PAGO =====
  const formaPago = venta.estado === 'PAGADA' ? 'CONTADO'
                  : venta.estado === 'CREDITO' ? 'CREDITO'
                  : venta.estado === 'ANULADA' ? 'ANULADA'
                  : 'PENDIENTE';
  linea(`Forma pago: ${formaPago}`, 6);
  if (venta.estado === 'CREDITO') {
    linea('(saldo pendiente)', 6);
  }
  doc.y += GAP;
  linea(SEP2, 6);
  doc.y += GAP;

  // ===== QR =====
  negritaCentro('Consulte en la DIAN:', 6);
  doc.y += GAP;

  const qrSize = 70;
  const qrX = (170 - qrSize) / 2;
  const qrY = doc.y;
  doc.image(qrBuffer, qrX, qrY, { width: qrSize, height: qrSize });
  doc.link(qrX, qrY, qrSize, qrSize, qrContent);
  doc.y = qrY + qrSize + 4;

  centro('Escanee con su celular', 6);
  doc.y += GAP;

  // ===== CUFE =====
  centro('CUFE:', 5);
  const cufeLines = cufe.match(/.{1,40}/g) || [cufe];
  cufeLines.forEach(seg => centro(seg, 4));
  doc.y += GAP;

  linea(SEP2, 6);
  doc.y += GAP;

  // ===== PIE =====
  wrapCentro(FERRETERIA.resolucion, 5);
  wrapCentro(`Rango: ${FERRETERIA.rango}`, 5);
  centro(`Generado: ${new Date().toISOString().slice(0, 16)}`, 5);
  doc.y += GAP;
  linea(SEP2, 6);
  doc.y += GAP;

  negritaCentro('!Gracias por su compra!', 6);
  centro('Este documento equivale a', 5);
  centro('factura electronica segun', 5);
  centro('Art. 617 Estatuto Tributario', 5);
  centro('Conserve este tiquete', 5);

  doc.end();
}