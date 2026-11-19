import PDFDocument from 'pdfkit';

function fmtCOP(n) {
  return new Intl.NumberFormat('es-CO', {
    style: 'currency', currency: 'COP', maximumFractionDigits: 0,
  }).format(n || 0);
}

export function generarFacturaPDF(venta, lineas, res) {
  const FERRETERIA = {
    nombre: process.env.FERRETERIA_NOMBRE || 'FerreStock Demo S.A.S.',
    nit:    process.env.FERRETERIA_NIT    || '900.123.456-7',
    dir:    process.env.FERRETERIA_DIR    || 'Calle 10 #20-30, Bogotá',
    tel:    process.env.FERRETERIA_TEL    || '300 123 4567',
  };

  const doc = new PDFDocument({ margin: 50, size: 'A4' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="Factura-${String(venta.id_venta).padStart(6, '0')}.pdf"`
  );
  doc.pipe(res);

  doc.fontSize(18).font('Helvetica-Bold').text('FACTURA DE VENTA', { align: 'center' });
  doc.moveDown(0.3);
  doc.fontSize(9).font('Helvetica').text(`No. ${String(venta.id_venta).padStart(6, '0')}`, { align: 'center' });
  doc.moveDown(1);

  doc.fontSize(10).font('Helvetica-Bold').text('VENDEDOR');
  doc.font('Helvetica').fontSize(9);
  doc.text(`${FERRETERIA.nombre}  —  NIT: ${FERRETERIA.nit}`);
  doc.text(`${FERRETERIA.dir}  —  Tel: ${FERRETERIA.tel}`);
  doc.moveDown(1);

  doc.font('Helvetica-Bold').text('ADQUIRENTE');
  doc.font('Helvetica').fontSize(9);
  doc.text(`Nombre: ${venta.cliente}`);
  if (venta.numero_documento) {
    doc.text(`${venta.tipo_documento || 'CC'}: ${venta.numero_documento}`);
  }
  doc.text(`Fecha de expedición: ${String(venta.fecha_hora).slice(0, 16)}`);
  doc.moveDown(1);

  const yIni = doc.y;
  doc.font('Helvetica-Bold').fontSize(9);
  doc.text('Ref.', 50, yIni, { width: 60 });
  doc.text('Producto', 110, yIni, { width: 230 });
  doc.text('Cant.', 340, yIni, { width: 50, align: 'right' });
  doc.text('Vr. Unit.', 390, yIni, { width: 70, align: 'right' });
  doc.text('Subtotal', 460, yIni, { width: 80, align: 'right' });
  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(540, doc.y).stroke();

  doc.font('Helvetica').fontSize(8.5);
  lineas.forEach(l => {
    const y = doc.y + 3;
    doc.text(l.referencia, 50, y, { width: 60 });
    doc.text(String(l.nombre).slice(0, 45), 110, y, { width: 230 });
    doc.text(String(l.cantidad), 340, y, { width: 50, align: 'right' });
    doc.text(fmtCOP(l.precio_unitario), 390, y, { width: 70, align: 'right' });
    doc.text(fmtCOP(l.subtotal_linea), 460, y, { width: 80, align: 'right' });
    doc.moveDown(0.6);
  });

  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(540, doc.y).stroke();
  doc.moveDown(0.5);

  const yTot = doc.y;
  doc.font('Helvetica').fontSize(9);
  doc.text('Subtotal:', 380, yTot, { width: 80, align: 'right' });
  doc.text(fmtCOP(venta.subtotal), 460, yTot, { width: 80, align: 'right' });
  doc.text('IVA (19%):', 380, yTot + 14, { width: 80, align: 'right' });
  doc.text(fmtCOP(venta.iva), 460, yTot + 14, { width: 80, align: 'right' });
  doc.font('Helvetica-Bold').fontSize(10);
  doc.text('TOTAL:', 380, yTot + 28, { width: 80, align: 'right' });
  doc.text(fmtCOP(venta.total), 460, yTot + 28, { width: 80, align: 'right' });

  doc.moveDown(3);
  doc.fontSize(7).font('Helvetica').fillColor('#666');
  doc.text(
    'Esta factura cumple los requisitos del Art. 617 del Estatuto Tributario. ' +
    'Documento generado electrónicamente — no requiere firma manuscrita.',
    { align: 'center' }
  );
  doc.text('Generada por FerreStock', { align: 'center' });

  doc.end();
}