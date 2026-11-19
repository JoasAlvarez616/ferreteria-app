import PDFDocument from 'pdfkit';
import QRCode from 'qrcode';
import crypto from 'crypto';

function fmtNum(n) {
  return new Intl.NumberFormat('es-CO', { maximumFractionDigits: 0 }).format(n || 0);
}
function fmtCant(n) {
  const num = Number(n);
  if (Number.isInteger(num)) return String(num);
  return num.toFixed(2).replace(/\.?0+$/, '');
}
function wrapText(text, width) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) {
      if (line) lines.push(line.trim());
      line = w;
    } else {
      line = (line + ' ' + w).trim();
    }
  }
  if (line) lines.push(line.trim());
  return lines.length ? lines : [''];
}

export async function generarFacturaPDF(venta, lineas, res) {
  const F = {
    nombre:      process.env.FERRETERIA_NOMBRE || 'FERRETERIA DEMO S.A.S.',
    nit:         process.env.FERRETERIA_NIT || '900.123.456-7',
    dir:         process.env.FERRETERIA_DIR || 'Calle 10 #20-30, Bogota',
    tel:         process.env.FERRETERIA_TEL || '300 123 4567',
    ciiu:        process.env.FERRETERIA_CIIU || '4752',
    resNumero:   process.env.FERRETERIA_RESOLUCION_NUMERO || '18764000123456',
    resFecha:    process.env.FERRETERIA_RESOLUCION_FECHA || '2024-01-15',
    resVigencia: process.env.FERRETERIA_RESOLUCION_VIGENCIA || '2025-01-15',
    rango:       process.env.FERRETERIA_RANGO || 'POS-000001 al POS-999999',
    software:    process.env.FERRETERIA_SOFTWARE || 'FerreStock S.A.S.',
    softwareNit: process.env.FERRETERIA_SOFTWARE_NIT || '901.234.567-8',
    clienteDefaultNit: process.env.FERRETERIA_CLIENTE_DEFAULT_NIT || '222222222222',
    claveTecnica: process.env.FERRETERIA_CLAVE_TECNICA || 'fc8eac422eba16e22ffd8c6f94b3f40a6e38162c',
  };

  const cufe = crypto.createHash('sha384').update([
    F.nit, `POS-${String(venta.id_venta).padStart(6, '0')}`,
    venta.fecha_hora, venta.total, venta.iva, venta.subtotal, F.claveTecnica,
  ].join('|')).digest('hex').substring(0, 96);
  const qrUrl = `https://catalogo-vpfe.dian.gov.co/document/searchqr?documentkey=${cufe}`;

  const qrBuffer = await QRCode.toBuffer(qrUrl, {
    width: 200, margin: 0, errorCorrectionLevel: 'M',
    color: { dark: '#000000', light: '#FFFFFF' },
  });

  // Altura dinámica — calculada por el número de líneas reales
  const lineasProductos = lineas.reduce((acc, l) => acc + wrapText(l.nombre, 32).length + 1, 0);
  const totalLineas = 40 + lineasProductos;
  const altura = Math.min(1600, Math.max(900, totalLineas * 9 + 100));

  const doc = new PDFDocument({
    size: [170, altura],  // 58mm
    margins: { top: 6, bottom: 6, left: 6, right: 6 },
    info: { Title: `POS-${venta.id_venta}`, Author: F.nombre, Subject: `CUFE: ${cufe}` },
  });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="POS-${String(venta.id_venta).padStart(6, '0')}.pdf"`);
  doc.pipe(res);

  const ANCHO = 158;   // 170 - márgenes (6*2)
  const FONT_SIZE = 7;
  const LINE_H = 8;
  const SEP  = '-'.repeat(30);
  const SEP2 = '='.repeat(30);
  const GAP  = 2;

  const ln = (txt, size = FONT_SIZE) => {
    doc.fontSize(size).font('Courier').text(txt, 6, doc.y, { width: ANCHO, lineBreak: false });
    doc.y += LINE_H;
  };
  const ce = (txt, size = FONT_SIZE) => {
    doc.fontSize(size).font('Courier').text(txt, 6, doc.y, { width: ANCHO, align: 'center', lineBreak: false });
    doc.y += LINE_H;
  };
  const bo = (txt, size = FONT_SIZE) => {
    doc.fontSize(size).font('Courier-Bold').text(txt, 6, doc.y, { width: ANCHO, lineBreak: false });
    doc.y += LINE_H;
  };
  const boc = (txt, size = FONT_SIZE) => {
    doc.fontSize(size).font('Courier-Bold').text(txt, 6, doc.y, { width: ANCHO, align: 'center', lineBreak: false });
    doc.y += LINE_H;
  };
  const right = (label, value, size = FONT_SIZE) => {
    const lbl = String(label).padEnd(18, ' ');
    const val = String(value).padStart(12, ' ');
    ln(`${lbl}${val}`, size);
  };

  // ===== ENCABEZADO =====
  boc(F.nombre.toUpperCase(), 8);
  ce(`NIT: ${F.nit}`);
  ce(F.dir);
  ce(`Tel: ${F.tel}`);
  ce(`Act. economica: ${F.ciiu}`);
  doc.y += GAP;
  ce(SEP2);
  boc('DOCUMENTO EQUIVALENTE', 7);
  boc('ELECTRONICO - POS', 7);
  ce(`No. POS-${String(venta.id_venta).padStart(6, '0')}`);
  ce(SEP2);
  doc.y += GAP;

  // ===== FECHAS =====
  ln(`Fecha gen.: ${String(venta.fecha_hora).slice(0, 16)}`);
  ln(`Fecha exp.: ${String(venta.fecha_hora).slice(0, 16)}`);
  ln(SEP);
  doc.y += GAP;

  // ===== CLIENTE =====
  const clienteNit = venta.numero_documento
    ? `${venta.tipo_documento || 'CC'} ${venta.numero_documento}`
    : `CC ${F.clienteDefaultNit}`;
  ln(`Cliente: ${venta.cliente}`);
  ln(`C.C./NIT: ${clienteNit}`);
  ln(`Direccion: ${F.dir}`);
  ln(`Telefono: ${F.tel}`);
  ln(`Vendedor: ${venta.cajero || 'admin'}`);
  ln(SEP);
  doc.y += GAP;

  // ===== ITEMS =====
  boc('DETALLE PRODUCTOS', 7);
  ln(SEP);

  let totalItems = 0;
  lineas.forEach(l => {
    totalItems += Number(l.cantidad);
    const nombreLines = wrapText(String(l.nombre), 32);
    nombreLines.forEach(line => ln(line));
    const qtyUnit = `  ${fmtCant(l.cantidad)} x $${fmtNum(l.precio_unitario)}`;
    right(qtyUnit, `$${fmtNum(l.subtotal_linea)}`);
  });
  ln(SEP);
  doc.y += GAP;

  // ===== TOTALES =====
  ln(`Total items: ${totalItems}`);
  right('Total bruto:', `$${fmtNum(venta.subtotal)}`);
  right('Descuentos:', '$0');
  ln(SEP);
  doc.y += GAP;

  // ===== IMPUESTOS =====
  boc('DISCRIMINACION IMPUESTOS', 7);
  ln(SEP);
  const tasa = Number(venta.subtotal) > 0
    ? Math.round((Number(venta.iva) / Number(venta.subtotal)) * 100) : 0;
  const ivaLabel = tasa > 0 ? `IVA ${tasa}%` : 'IVA 0% (exento)';
  ln('ID  Base            Imp.');
  ln(`A   $${fmtNum(venta.subtotal)}        $${fmtNum(venta.iva)}`);
  ln(`A = ${ivaLabel}`);
  ln(SEP);
  doc.y += GAP;

  right('SUBTOTAL:', `$${fmtNum(venta.subtotal)}`);
  right(`${ivaLabel}:`, `$${fmtNum(venta.iva)}`);
  bo(`TOTAL A PAGAR:      $${fmtNum(venta.total)}`, 9);
  ce(SEP2);
  doc.y += GAP;

  // ===== PAGO =====
  const formaPago = venta.estado === 'PAGADA' ? 'CONTADO'
                  : venta.estado === 'CREDITO' ? 'CREDITO'
                  : venta.estado === 'ANULADA' ? 'ANULADA' : 'PENDIENTE';
  const medioPago = venta.estado === 'PAGADA' ? 'Efectivo'
                  : venta.estado === 'CREDITO' ? 'Credito' : '-';
  ln(`Forma de pago: ${formaPago}`);
  ln(`Medio de pago: ${medioPago}`);
  if (venta.estado === 'PAGADA') {
    right('Recibido:', `$${fmtNum(venta.total)}`);
    right('Cambio:', '$0');
  } else if (venta.estado === 'CREDITO') {
    right('Saldo pendiente:', `$${fmtNum(venta.total)}`);
  }
  ln(SEP);
  doc.y += GAP;

  // ===== QR =====
  ce('Escanee para verificar', 7);
  ce('en la DIAN', 7);
  const qrSize = 70;
  const qrX = (170 - qrSize) / 2;
  const qrY = doc.y;
  doc.image(qrBuffer, qrX, qrY, { width: qrSize, height: qrSize });
  doc.link(qrX, qrY, qrSize, qrSize, qrUrl);
  doc.y = qrY + qrSize + 4;
  ln(SEP);
  doc.y += GAP;

  // ===== CUFE =====
  bo('CUFE:', 6);
  const cufeChunks = cufe.match(/.{1,32}/g) || [cufe];
  cufeChunks.forEach(c => ln(c, 5));
  ln(SEP);
  doc.y += GAP;

  // ===== LEYENDA LEGAL =====
  ce('Esta factura electronica', 5);
  ce('equivale a titulo valor', 5);
  ce('Art. 617 Estatuto Tributario', 5);
  ln(SEP);
  doc.y += GAP;

  ce(`Res. DIAN No. ${F.resNumero}`, 5);
  ce(`Fecha: ${F.resFecha}`, 5);
  ce(`Prefijo: POS`, 5);
  ce(`Rango: ${F.rango}`, 5);
  ce(`Vigencia: ${F.resVigencia}`, 5);
  ln(SEP);
  doc.y += GAP;

  ce('Fabricante software:', 5);
  ce(F.software, 5);
  ce(`NIT: ${F.softwareNit}`, 5);
  ln(SEP);
  doc.y += GAP;

  boc('Gracias por su compra', 6);
  ce('Conserve este tiquete', 5);

  doc.end();
}