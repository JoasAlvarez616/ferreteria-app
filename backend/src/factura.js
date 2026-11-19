import PDFDocument from 'pdfkit';

function fmtNum(n) {
  return new Intl.NumberFormat('es-CO', { maximumFractionDigits: 0 }).format(n || 0);
}
function padRight(str, n) {
  return String(str).substring(0, n).padEnd(n, ' ');
}
function padLeft(str, n) {
  return String(str).substring(0, n).padStart(n, ' ');
}

export function generarFacturaPDF(venta, lineas, res) {
  const FERRETERIA = {
    nombre:     process.env.FERRETERIA_NOMBRE || 'FerreStock Demo S.A.S.',
    nit:        process.env.FERRETERIA_NIT    || '900.123.456-7',
    dir:        process.env.FERRETERIA_DIR    || 'Calle 10 #20-30, Bogotá',
    tel:        process.env.FERRETERIA_TEL    || '300 123 4567',
    resolucion: process.env.FERRETERIA_RESOLUCION || 'Resolución DIAN 165 de 2023',
    rango:      process.env.FERRETERIA_RANGO  || 'POS-000001 al POS-999999',
  };

  // Altura dinámica: mínimo 500pt, máximo 1400pt
  const numLineas = 15 + lineas.length * 1.5;
  const altura = Math.min(1400, Math.max(500, Math.round(numLineas * 11 + 60)));

  const doc = new PDFDocument({
    size: [227, altura], // 80mm de ancho - papel térmico POS
    margins: { top: 8, bottom: 8, left: 8, right: 8 },
    info: { Title: `POS-${venta.id_venta}` },
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

  // ===== PIE / DATOS DIAN =====
  centro('CUFE:', 6);
  centro('[pendiente de transmisión DIAN]', 6);
  doc.y += GAP;
  centro(FERRETERIA.resolucion, 6);
  centro(`Rango: ${FERRETERIA.rango}`, 6);
  doc.y += GAP;
  linea(SEP2, 7);
  doc.y += GAP;

  negritaCentro('¡Gracias por su compra!', 7);
  centro('Este documento equivale a factura electrónica', 6);
  centro('según Art. 617 del Estatuto Tributario', 6);
  centro('Conserve este tiquete', 6);

  doc.end();
}