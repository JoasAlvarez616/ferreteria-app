// backend/seed-masivo.js
import 'dotenv/config';
import { pool } from './src/db.js';

const DIAS_HACIA_ATRAS   = Number(process.env.SEED_DIAS)           || 240;
const VENTAS_POR_DIA     = Number(process.env.SEED_VENTAS_POR_DIA) || 5;
const STOCK_INICIAL      = Number(process.env.SEED_STOCK)          || 50000;
const CLIENTES_A_USAR    = Number(process.env.SEED_CLIENTES)       || 5;
const PRODUCTOS_A_USAR   = Number(process.env.SEED_PRODUCTOS)      || 50;

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

async function main() {
  const conn = await pool.getConnection();
  try {
    const [clientes] = await conn.query(
      `SELECT id_cliente FROM clientes WHERE nombre <> 'Consumidor Final' LIMIT ?`,
      [CLIENTES_A_USAR]
    );
    const [productos] = await conn.query(
      `SELECT p.id_producto, pr.id_presentacion
       FROM productos p
       JOIN presentaciones pr ON pr.id_producto = p.id_producto AND pr.es_presentacion_base = TRUE
       LIMIT ?`,
      [PRODUCTOS_A_USAR]
    );
    if (!clientes.length || !productos.length) {
      throw new Error('Faltan clientes o productos. Corre el seed base primero.');
    }

    const [[admin]] = await conn.query(
      `SELECT id_usuario FROM usuarios WHERE usuario = 'admin' LIMIT 1`
    );
    if (!admin) throw new Error('No existe el usuario admin.');

    // ---- 1) Stock inicial: kardex + forzar inventario ----
    console.log(`\n📦 Insertando stock inicial (${STOCK_INICIAL} por producto)...`);

    const [todosProductos] = await conn.query('SELECT id_producto FROM productos');

    // Asegurar que todos tengan fila en inventario
    await conn.query(
      `INSERT IGNORE INTO inventario (id_producto, cantidad_actual)
       SELECT id_producto, 0 FROM productos`
    );

    // Insertar movimientos de kardex (por trazabilidad)
    for (const p of todosProductos) {
      await conn.query(
        `INSERT INTO movimientos_inventario
         (id_producto, tipo_movimiento, condicion_stock, cantidad_base, origen, motivo, id_usuario)
         VALUES (?, 'ENTRADA', 'BUENO', ?, 'INICIAL', 'Stock inicial masivo', ?)`,
        [p.id_producto, STOCK_INICIAL, admin.id_usuario]
      );
    }

    // 🔧 FORZAR inventario sin depender del trigger
    await conn.query(`UPDATE inventario SET cantidad_actual = ?`, [STOCK_INICIAL]);

    // Verificar que SÍ quedó
    const [check] = await conn.query(
      `SELECT COUNT(*) AS total, MIN(cantidad_actual) AS min, MAX(cantidad_actual) AS max FROM inventario`
    );
    console.log(`  ✓ ${check[0].total} productos. Min: ${check[0].min}, Max: ${check[0].max}`);
    if (Number(check[0].min) !== STOCK_INICIAL) {
      throw new Error(
        `❌ Inventario no se fijó correctamente. Min: ${check[0].min}, esperado: ${STOCK_INICIAL}. Revisa triggers de inventario.`
      );
    }

    // ---- 2) Ventas ----
    const totalObjetivo = DIAS_HACIA_ATRAS * VENTAS_POR_DIA;
    console.log(`\n🛒 Sembrando ${totalObjetivo} ventas (${DIAS_HACIA_ATRAS} días × ${VENTAS_POR_DIA}/día)...`);
    let totalVentas = 0;
    let fallidas = 0;

    for (let dia = DIAS_HACIA_ATRAS; dia >= 0; dia--) {
      for (let v = 0; v < VENTAS_POR_DIA; v++) {
        try {
          const fecha = new Date();
          fecha.setDate(fecha.getDate() - dia);
          fecha.setHours(randInt(9, 18), randInt(0, 59), 0, 0);

          const esCredito = Math.random() < 0.25;
          const cliente = esCredito ? pick(clientes).id_cliente : null;

          const numLineas = randInt(1, 3);
          const items = [];
          const usados = new Set(); // evitar producto repetido en la misma venta
          for (let l = 0; l < numLineas; l++) {
            let prod;
            let intentos = 0;
            do {
              prod = pick(productos);
              intentos++;
            } while (usados.has(prod.id_producto) && intentos < 10);
            usados.add(prod.id_producto);
            items.push({
              id_producto: prod.id_producto,
              id_presentacion: prod.id_presentacion,
              cantidad: randInt(1, 5),
              precio_unitario: randInt(5, 150) * 1000,
              iva: 0,
            });
          }

          await conn.query('SET @id_venta = 0');
          await conn.query(
            'CALL sp_registrar_venta(?, ?, CAST(? AS JSON), @id_venta)',
            [admin.id_usuario, cliente, JSON.stringify(items)]
          );
          const [[{ id_venta }]] = await conn.query('SELECT @id_venta AS id_venta');
          if (!id_venta) throw new Error('SP no devolvió id_venta');

          await conn.query('UPDATE ventas SET fecha_hora = ? WHERE id_venta = ?', [fecha, id_venta]);

          const [[venta]] = await conn.query('SELECT total FROM ventas WHERE id_venta = ?', [id_venta]);
          if (!esCredito) {
            await conn.query(
              'CALL sp_registrar_pago(?, ?, ?, ?, ?)',
              [id_venta, venta.total, 'EFECTIVO', 'Pago masivo', admin.id_usuario]
            );
          } else {
            const dias = pick([15, 30, 45, 60]);
            await conn.query(
              `INSERT INTO cuentas_por_cobrar (id_venta, fecha_vencimiento, monto_original, saldo, estado)
               VALUES (?, DATE_ADD(?, INTERVAL ? DAY), ?, ?, 'PENDIENTE')`,
              [id_venta, fecha, dias, venta.total, venta.total]
            );
            await conn.query("UPDATE ventas SET estado = 'CREDITO' WHERE id_venta = ?", [id_venta]);
          }

          totalVentas++;
        } catch (err) {
          fallidas++;
          // Loguear pero continuar
          if (fallidas <= 10) {
            console.log(`  ⚠️  Venta #${totalVentas + fallidas} falló: ${err.message.slice(0, 80)}`);
          }
          // Si falla por stock, subir más stock para esa venta y reintentar
          if (err.message.includes('chk_inv_cantidad')) {
            await conn.query(`UPDATE inventario SET cantidad_actual = ?`, [STOCK_INICIAL]);
          }
        }

        if ((totalVentas + fallidas) % 50 === 0) {
          console.log(`  → ${totalVentas} OK / ${fallidas} fallidas de ${totalObjetivo}`);
        }
      }
    }

    // ---- 3) Devoluciones ----
    console.log(`\n↩  Sembrando devoluciones (~50)...`);
    const [ventasParaDevolver] = await conn.query(
      `SELECT id_venta FROM ventas WHERE estado <> 'ANULADA' ORDER BY RAND() LIMIT 50`
    );
    for (const v of ventasParaDevolver) {
      try {
        const [[linea]] = await conn.query(
          `SELECT id_detalle_venta, cantidad FROM detalle_venta WHERE id_venta = ? LIMIT 1`,
          [v.id_venta]
        );
        if (!linea || linea.cantidad < 1) continue;
        const items = [{
          id_detalle_venta: linea.id_detalle_venta,
          cantidad: 1,
          condicion_producto: pick(['BUENO', 'DEFECTUOSO', 'REACONDICIONADO']),
        }];
        await conn.query('SET @id_dev = 0');
        await conn.query(
          'CALL sp_registrar_devolucion(?, ?, ?, CAST(? AS JSON), @id_dev)',
          [v.id_venta, admin.id_usuario, 'Devolución demo', JSON.stringify(items)]
        );
      } catch (err) {
        // silencioso
      }
    }

    console.log(`\n✅ Listo. ${totalVentas} ventas OK, ${fallidas} fallidas, devoluciones generadas.\n`);
  } finally {
    conn.release();
    await pool.end();
  }
}

main().catch(e => { console.error('❌', e); process.exit(1); });