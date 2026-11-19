// backend/reset-transacciones.js
// ⚠️ DESTRUCTIVO: borra ventas, pagos, CxC, devoluciones, kardex.
// NO toca productos, clientes, catálogos.
// Uso:  node reset-transacciones.js         (solo cuenta, no borra)
//       node reset-transacciones.js --confirm  (borra de verdad)
import 'dotenv/config';
import { pool } from './src/db.js';

const CONFIRMAR = process.argv.includes('--confirm');

async function main() {
  const conn = await pool.getConnection();
  try {
    const [[v]] = await conn.query('SELECT COUNT(*) AS n FROM ventas');
    const [[c]] = await conn.query('SELECT COUNT(*) AS n FROM cuentas_por_cobrar');
    const [[d]] = await conn.query('SELECT COUNT(*) AS n FROM devoluciones');
    const [[p]] = await conn.query('SELECT COUNT(*) AS n FROM pagos');
    const [[m]] = await conn.query('SELECT COUNT(*) AS n FROM movimientos_inventario');

    console.log('\n=== ESTADO ACTUAL ===');
    console.log(`Ventas:         ${v.n}`);
    console.log(`CxC:            ${c.n}`);
    console.log(`Devoluciones:   ${d.n}`);
    console.log(`Pagos:          ${p.n}`);
    console.log(`Movimientos:    ${m.n}`);

    if (!CONFIRMAR) {
      console.log('\n⚠️  DRY RUN. Para borrar de verdad ejecuta:');
      console.log('   node reset-transacciones.js --confirm\n');
      return;
    }

    console.log('\n🔄 Borrando transacciones...');
    try {
      await conn.query('SET FOREIGN_KEY_CHECKS = 0');
      const tablas = [
        'detalle_devolucion', 'devoluciones', 'pagos', 'auditoria',
        'detalle_venta', 'cuentas_por_cobrar', 'movimientos_inventario',
        'ventas', 'stock_condicion',
      ];
      for (const t of tablas) {
        const [r] = await conn.query(`DELETE FROM ${t}`);
        console.log(`  ✓ ${t}: ${r.affectedRows} filas`);
      }
      await conn.query('UPDATE inventario SET cantidad_actual = 0');
      console.log('  ✓ inventario reseteado a 0');
    } finally {
      await conn.query('SET FOREIGN_KEY_CHECKS = 1');
    }

    console.log('\n🔄 Reseteando AUTO_INCREMENT...');
    for (const t of ['ventas','pagos','detalle_venta','devoluciones','detalle_devolucion','cuentas_por_cobrar','movimientos_inventario','auditoria']) {
      try { await conn.query(`ALTER TABLE ${t} AUTO_INCREMENT = 1`); } catch {}
    }
    console.log('  ✓ OK');

    console.log('\n✅ Reset completo. Listo para nuevo seed.\n');
  } finally {
    conn.release();
    await pool.end();
  }
}

main().catch(e => { console.error('❌', e.message); process.exit(1); });