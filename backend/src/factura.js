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
    dir:          process.env.FERRETERIA_DIR    || 'Calle 10 #20-30, Bogotá',
    tel:          process.env.FERRETERIA_TEL    || '300 123 4567',
    resolucion:   process.env.FERRETERIA_RESOLUCION || 'Resolución DIAN 165 de 2023',
    rango:        process.env.FERRETERIA_RANGO  || 'POS-000001 al POS-999999',
    claveTecnica: process.env.FERRETERIA_CLAVE_TECNICA || 'fc8eac422eba16e22ffd8c6f94b3f40a6e38162c',
  };

  // ===== CUFE único (SHA-384, igual que usa DIAN) =====
  // Combina NIT + número + fecha + valores + clave técnica del facturador
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
    .substring(0, 96); // DIAN usa 96 caracteres hexadecimales

  // ===== URL oficial de verificación DIAN (formato real) =====
  const qrContent = `https://catalogo-vpfe.dian.gov.co/document/searchqr?documentkey=${cufe}`;

  // ===== Generar imagen del QR =====
  const qrBuffer = await QRCode.toBuffer(qrContent, {
    width: 200,
    margin: 0,
    errorCorrectionLevel: 'M',
    color: { dark: '#000000', light: '#FFFFFF' },
  });

  // ===== Altura dinámica (incluye sección QR de ~140pt) =====
  const numLineas = 15 + lineas.length * 1.5;
  const altura = Math.min(1600, Math.max(680, Math.round(numLineas * 11 + 60 + 140)));

  const doc = new PDFDocument({
    size: [227, altura],
    margins: { top: 8, bottom: 8, left: 8, right: 8 },
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

  const ANCHO = 227 - 16;
  const SEP  = '-'.repeat(46);
  const SEP2 = '='.repeat(46);
  const GAP  = 3;

  const linea = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier').text(txt, 8, y, { width: ANCHO, lineBreak: false });
    doc.y = y + size + 2;
  };
  const centro = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier').text(txt, 8, y, { width: ANCHO, align: 'center', lineBreak: false });
    doc.y = y + size + 2;
  };
  const negrita = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier-Bold').text(txt, 8, y, { width: ANCHO, lineBreak: false });
    doc.y = y + size + 2;
  };
  const negritaCentro = (txt, size = 7) => {
    const y = doc.y;
    doc.fontSize(size).font('Courier-Bold').text(txt, 8, y, { width: ANCHO, align: 'center', lineBreak: false });
    doc.y = y + size + 2;
  };

  // ===== ENCABEZADO =====
  negritaCentro(FERRETERIA.nombre.toUpperCase(), 8);
  centro(`NIT: ${FERRETERIA.nit}`, 7);
  centro(FERRETERIA.dir, 7);
  centro(`Tel: ${FERRETERIA.tel}`, 7);
  doc.y += GAP;
  centro(SEP2, 7);
  negritaCentro('DOCUMENTO EQUIVALENTE ELECTRÓNICO', 7);
  negritaCentro('TIQUETE DE MÁQUINA REGISTRADORA - POS', 7);
  centro(SEP2, 7);
  doc.y += GAP;

  // ===== DATOS DEL TIQUETE =====
  linea(`Tiquete No.: POS-${String(venta.id_venta).padStart(6, '0')}`, 7);
  linea(`Fecha: ${String(venta.fecha_hora).slice(0, 16)}`, 7);
  linea(`Cajero: ${venta.cajero || 'admin'}`, 7);
  doc.y += GAP;
  linea(SEP, 7);
  doc.y += GAP;

  // ===== CLIENTE =====
  linea(`Cliente: ${venta.cliente}`, 7);
  if (venta.numero_documento) {
    linea(`${venta.tipo_documento || 'CC'}: ${venta.numero_documento}`, 7);
  }
  doc.y += GAP;
  linea(SEP, 7);
  doc.y += GAP;

  // ===== CABECERA PRODUCTOS =====
  negrita('CANT  DESCRIPCION                  TOTAL', 7);
  linea(SEP, 7);

  // ===== PRODUCTOS =====
  lineas.forEach(l => {
    const cant  = padLeft(String(Number(l.cantidad)), 4);
    const desc  = padRight(String(l.nombre), 25);
    const total = padLeft(fmtNum(l.subtotal_linea), 13);
    linea(`${cant}  ${desc} ${total}`, 7);
    if (Number(l.cantidad) > 1) {
      linea(`      ${padLeft(String(Number(l.cantidad)), 3)} x ${padLeft(fmtNum(l.precio_unitario), 10)} c/u`, 6);
    }
  });

  doc.y += GAP;
  linea(SEP, 7);
  doc.y += GAP;

  // ===== TOTALES =====
  linea(`${padRight('Subtotal:', 32)}${padLeft(fmtNum(venta.subtotal), 14)}`, 7);
  linea(`${padRight('IVA 19%:', 32)}${padLeft(fmtNum(venta.iva), 14)}`, 7);
  doc.y += GAP;
  negrita(`${padRight('TOTAL:', 32)}${padLeft(fmtNum(venta.total), 14)}`, 8);
  doc.y += GAP;
  linea(SEP2, 7);
  doc.y += GAP;

  // ===== FORMA DE PAGO =====
  const formaPago = venta.estado === 'PAGADA' ? 'CONTADO'
                  : venta.estado === 'CREDITO' ? 'CRÉDITO'
                  : venta.estado === 'ANULADA' ? 'ANULADA'
                  : 'PENDIENTE';
  linea(`Forma de pago: ${formaPago}`, 7);
  if (venta.estado === 'CREDITO') {
    linea('(saldo pendiente de pago)', 7);
  }
  doc.y += GAP;
  linea(SEP2, 7);
  doc.y += GAP;

  // ===== QR + CUFE =====
  negritaCentro('Consulte su factura en la DIAN:', 7);
  doc.y += GAP;

  const qrSize = 70;
  const qrX = (227 - qrSize) / 2;
  const qrY = doc.y;
  doc.image(qrBuffer, qrX, qrY, { width: qrSize, height: qrSize });
  doc.link(qrX, qrY, qrSize, qrSize, qrContent); // clickeable en PDF
  doc.y = qrY + qrSize + 4;

  centro('Escanee o haga clic para verificar', 6);
  doc.y += GAP;

  // CUFE en varias líneas (es muy largo para una sola)
  centro('CUFE:', 6);
  const cufeLines = cufe.match(/.{1,40}/g) || [cufe];
  cufeLines.forEach(seg => centro(seg, 5));
  doc.y += GAP;

  linea(SEP2, 7);
  doc.y += GAP;

  // ===== PIE / DATOS DIAN =====
  centro(FERRETERIA.resolucion, 6);
  centro(`Rango autorizado: ${FERRETERIA.rango}`, 6);
  centro(`Generado: ${new Date().toISOString().slice(0, 16)}`, 6);
  doc.y += GAP;
  linea(SEP2, 7);
  doc.y += GAP;

  negritaCentro('¡Gracias por su compra!', 7);
  centro('Este documento equivale a factura electrónica', 6);
  centro('según Art. 617 del Estatuto Tributario', 6);
  centro('Conserve este tiquete', 6);

  doc.end();
}