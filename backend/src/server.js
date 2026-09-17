import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import 'dotenv/config';
import { pool } from './db.js';

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());

// ============================================================
// JWT minimalista (HMAC-SHA256, sin dependencias externas)
// ============================================================
const SECRET = process.env.JWT_SECRET || 'ferreteria-cambiar-este-secreto';

function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [data, sig] = token.split('.');
  if (!data || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ============================================================
// Middleware de autenticación
// ============================================================
function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'No autorizado' });
  req.user = payload;
  next();
}

// Middleware global: protege todo /api excepto /auth/login y /health
app.use('/api', (req, res, next) => {
  if (req.path === '/auth/login' || req.path === '/health') return next();
  return authRequired(req, res, next);
});

// ============================================================
// AUTH
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password) {
    return res.status(400).json({ error: 'usuario y password son obligatorios' });
  }
  try {
    const [[user]] = await pool.query(
      'SELECT id_usuario, nombre, usuario, password_hash, estado FROM usuarios WHERE usuario = ?',
      [usuario]
    );
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
    if (user.estado !== 'ACTIVO') return res.status(403).json({ error: 'Usuario inactivo' });

    // Comparación en texto plano (temporal, migrar a bcrypt después)
    if (user.password_hash !== password) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const payload = {
      id_usuario: user.id_usuario,
      usuario: user.usuario,
      nombre: user.nombre,
      exp: Date.now() + 1000 * 60 * 60 * 8,
    };
    const token = signToken(payload);
    res.json({ ok: true, token, user: { id: payload.id_usuario, nombre: user.nombre, usuario: user.usuario } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', (req, res) => {
  res.json({ ok: true, user: req.user });
});

// ============================================================
// HEALTH (público)
// ============================================================
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, db: 'conectada', ts: new Date().toISOString() });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ============================================================
// KPIs
// ============================================================
app.get('/api/kpis', async (_req, res) => {
  try {
    const [[{ total_productos }]] = await pool.query('SELECT COUNT(*) AS total_productos FROM productos');
    const [[{ total_stock }]]     = await pool.query('SELECT COALESCE(SUM(cantidad_actual),0) AS total_stock FROM inventario');
    const [[{ total_ventas }]]    = await pool.query('SELECT COUNT(*) AS total_ventas FROM ventas');
    const [[{ total_ingresos }]]  = await pool.query("SELECT COALESCE(SUM(total),0) AS total_ingresos FROM ventas WHERE estado = 'PAGADA'");
    res.json({ total_productos, total_stock, total_ventas, total_ingresos });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// PRODUCTOS
// ============================================================
app.get('/api/productos', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT p.id_producto, p.referencia, p.nombre,
             c.nombre AS categoria, m.nombre AS marca,
             um.abreviatura AS unidad,
             COALESCE(i.cantidad_actual, 0) AS stock,
             COALESCE(sc_def.cantidad, 0)   AS defectuosos,
             COALESCE(sc_reac.cantidad, 0)  AS reacondicionados,
             p.id_categoria, p.id_marca, p.id_unidad_base
      FROM productos p
      JOIN categorias c ON c.id_categoria = p.id_categoria
      LEFT JOIN marcas m ON m.id_marca = p.id_marca
      JOIN unidades_medida um ON um.id_unidad = p.id_unidad_base
      LEFT JOIN inventario i ON i.id_producto = p.id_producto
      LEFT JOIN stock_condicion sc_def
        ON sc_def.id_producto = p.id_producto AND sc_def.condicion = 'DEFECTUOSO'
      LEFT JOIN stock_condicion sc_reac
        ON sc_reac.id_producto = p.id_producto AND sc_reac.condicion = 'REACONDICIONADO'
      ORDER BY p.id_producto DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/productos', async (req, res) => {
  const { referencia, nombre, id_categoria, id_marca, id_unidad_base,
          presentacion, cantidad_base } = req.body;
  if (!referencia || !nombre || !id_categoria || !id_unidad_base) {
    return res.status(400).json({ error: 'Campos obligatorios: referencia, nombre, id_categoria, id_unidad_base' });
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [r] = await conn.query(
      `INSERT INTO productos (referencia, nombre, id_categoria, id_marca, id_unidad_base)
       VALUES (?, ?, ?, ?, ?)`,
      [referencia, nombre, id_categoria, id_marca || null, id_unidad_base]
    );
    const id_producto = r.insertId;
    await conn.query(
      `INSERT INTO presentaciones (id_producto, nombre, id_unidad, cantidad_base, es_presentacion_base)
       VALUES (?, ?, ?, ?, TRUE)`,
      [id_producto, presentacion || 'Unidad', id_unidad_base, cantidad_base || 1]
    );
    await conn.query(
      `INSERT IGNORE INTO inventario (id_producto, cantidad_actual) VALUES (?, 0)`,
      [id_producto]
    );
    await conn.commit();
    res.status(201).json({ ok: true, id_producto });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally { conn.release(); }
});

app.get('/api/productos/:id/kardex', async (req, res) => {
  try {
    const { id } = req.params;
    const [[producto]] = await pool.query(`
      SELECT p.id_producto, p.referencia, p.nombre,
             c.nombre AS categoria, m.nombre AS marca,
             COALESCE(i.cantidad_actual, 0) AS stock
      FROM productos p
      JOIN categorias c ON c.id_categoria = p.id_categoria
      LEFT JOIN marcas m ON m.id_marca = p.id_marca
      LEFT JOIN inventario i ON i.id_producto = p.id_producto
      WHERE p.id_producto = ?
    `, [id]);
    if (!producto) return res.status(404).json({ error: 'Producto no encontrado' });

    const [movimientos] = await pool.query(`
      SELECT mi.id_movimiento, mi.fecha_hora, mi.tipo_movimiento,
             mi.condicion_stock, mi.cantidad_base, mi.origen, mi.motivo,
             u.usuario AS registrado_por
      FROM movimientos_inventario mi
      JOIN usuarios u ON u.id_usuario = mi.id_usuario
      WHERE mi.id_producto = ?
      ORDER BY mi.id_movimiento DESC
    `, [id]);

    res.json({ producto, movimientos });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// CATÁLOGOS
// ============================================================
app.get('/api/catalogos', async (_req, res) => {
  try {
    const [categorias] = await pool.query("SELECT id_categoria, nombre FROM categorias WHERE estado='ACTIVO' ORDER BY nombre");
    const [marcas]     = await pool.query("SELECT id_marca, nombre FROM marcas WHERE estado='ACTIVO' ORDER BY nombre");
    const [unidades]   = await pool.query("SELECT id_unidad, nombre, abreviatura FROM unidades_medida WHERE estado='ACTIVO' ORDER BY nombre");
    res.json({ categorias, marcas, unidades });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// VENTAS
// ============================================================
app.get('/api/ventas', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT v.id_venta, v.fecha_hora, v.total, v.estado,
             COALESCE(c.nombre, 'Consumidor final') AS cliente,
             u.usuario AS vendedor
      FROM ventas v
      LEFT JOIN clientes c ON c.id_cliente = v.id_cliente
      JOIN usuarios u ON u.id_usuario = v.id_usuario
      ORDER BY v.id_venta DESC LIMIT 20
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ventas', async (req, res) => {
  const { items, id_cliente } = req.body;
  const id_usuario = req.user.id_usuario;
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'items es obligatorio' });
  }
  const conn = await pool.getConnection();
  try {
    await conn.query('SET @id_venta = 0');
    await conn.query('CALL sp_registrar_venta(?, ?, ?, @id_venta)',
      [id_usuario, id_cliente || null, JSON.stringify(items)]);
    const [[{ id_venta }]] = await conn.query('SELECT @id_venta AS id_venta');
    const [[venta]] = await conn.query(
      'SELECT id_venta, subtotal, iva, total, estado FROM ventas WHERE id_venta = ?',
      [id_venta]
    );
    res.status(201).json({ ok: true, venta });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally { conn.release(); }
});

// ============================================================
// DETALLE DE VENTA + DEVOLUCIONES
// ============================================================
app.get('/api/ventas/:id/detalle', async (req, res) => {
  try {
    const { id } = req.params;
    const [[venta]] = await pool.query(`
      SELECT v.id_venta, v.fecha_hora, v.total, v.estado,
             COALESCE(c.nombre, 'Consumidor final') AS cliente
      FROM ventas v
      LEFT JOIN clientes c ON c.id_cliente = v.id_cliente
      WHERE v.id_venta = ?
    `, [id]);

    if (!venta) return res.status(404).json({ error: 'Venta no encontrada' });

    const [lineas] = await pool.query(`
      SELECT dv.id_detalle_venta,
             dv.id_producto,
             p.referencia, p.nombre AS producto,
             dv.cantidad AS cantidad_vendida,
             dv.cantidad_base AS cantidad_vendida_base,
             dv.precio_unitario,
             COALESCE(SUM(dd.cantidad), 0) AS cantidad_devuelta,
             COALESCE(SUM(dd.cantidad_base), 0) AS cantidad_devuelta_base
      FROM detalle_venta dv
      JOIN productos p ON p.id_producto = dv.id_producto
      LEFT JOIN detalle_devolucion dd ON dd.id_detalle_venta = dv.id_detalle_venta
      WHERE dv.id_venta = ?
      GROUP BY dv.id_detalle_venta
    `, [id]);

    const lineasConDisponible = lineas.map(l => ({
      ...l,
      cantidad_disponible: Number(l.cantidad_vendida) - Number(l.cantidad_devuelta),
    }));

    res.json({ venta, lineas: lineasConDisponible });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ventas/:id/devolucion', async (req, res) => {
  try {
    const { id } = req.params;
    const { motivo, items } = req.body;
    const id_usuario = req.user.id_usuario;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'items es obligatorio' });
    }

    const conn = await pool.getConnection();
    try {
      await conn.query('SET @id_dev = 0');
      await conn.query('CALL sp_registrar_devolucion(?, ?, ?, ?, @id_dev)',
        [id, id_usuario, motivo || null, JSON.stringify(items)]);
      const [[{ id_dev }]] = await conn.query('SELECT @id_dev AS id_dev');
      res.status(201).json({ ok: true, id_devolucion: id_dev });
    } finally { conn.release(); }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// CLIENTES
// ============================================================
app.get('/api/clientes', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT c.id_cliente, c.nombre, c.tipo_documento, c.numero_documento,
             c.telefono, c.limite_credito, c.estado,
             COALESCE(SUM(cxc.saldo), 0) AS deuda_actual
      FROM clientes c
      LEFT JOIN cuentas_por_cobrar cxc
        ON cxc.id_venta IN (SELECT id_venta FROM ventas WHERE id_cliente = c.id_cliente)
       AND cxc.estado <> 'ANULADA'
      GROUP BY c.id_cliente
      ORDER BY c.nombre
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/clientes', async (req, res) => {
  const { nombre, tipo_documento, numero_documento, telefono, direccion, limite_credito } = req.body;
  if (!nombre) return res.status(400).json({ error: 'nombre es obligatorio' });
  try {
    const [r] = await pool.query(
      `INSERT INTO clientes (nombre, tipo_documento, numero_documento, telefono, direccion, limite_credito)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [nombre, tipo_documento || 'CC', numero_documento || null, telefono || null,
       direccion || null, limite_credito || 0]
    );
    res.status(201).json({ ok: true, id_cliente: r.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// CUENTAS POR COBRAR
// ============================================================
app.get('/api/cuentas-por-cobrar', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT cxc.id_cuenta, cxc.id_venta, cxc.fecha_vencimiento,
             cxc.monto_original, cxc.saldo, cxc.estado,
             v.fecha_hora, v.total AS total_venta,
             c.nombre AS cliente, c.id_cliente
      FROM cuentas_por_cobrar cxc
      JOIN ventas v ON v.id_venta = cxc.id_venta
      JOIN clientes c ON c.id_cliente = v.id_cliente
      WHERE cxc.estado <> 'ANULADA'
      ORDER BY cxc.estado, cxc.fecha_vencimiento
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ventas/:id/credito', async (req, res) => {
  try {
    const { id } = req.params;
    const { dias_vencimiento } = req.body;
    const [[venta]] = await pool.query(
      'SELECT id_venta, total FROM ventas WHERE id_venta = ?', [id]
    );
    if (!venta) return res.status(404).json({ error: 'Venta no encontrada' });

    const [existe] = await pool.query(
      'SELECT id_cuenta FROM cuentas_por_cobrar WHERE id_venta = ?', [id]
    );
    if (existe.length) return res.status(400).json({ error: 'Esta venta ya tiene cuenta por cobrar' });

    const dias = Number(dias_vencimiento) || 30;
    const [r] = await pool.query(
      `INSERT INTO cuentas_por_cobrar
       (id_venta, fecha_vencimiento, monto_original, saldo, estado)
       VALUES (?, DATE_ADD(CURRENT_DATE, INTERVAL ? DAY), ?, ?, 'PENDIENTE')`,
      [id, dias, venta.total, venta.total]
    );
    res.status(201).json({ ok: true, id_cuenta: r.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/cuentas-por-cobrar/:id/pago', async (req, res) => {
  try {
    const { id } = req.params;
    const { monto, metodo_pago, referencia } = req.body;
    const id_usuario = req.user.id_usuario;

    const [[cuenta]] = await pool.query(
      'SELECT id_venta, saldo FROM cuentas_por_cobrar WHERE id_cuenta = ?', [id]
    );
    if (!cuenta) return res.status(404).json({ error: 'Cuenta no encontrada' });
    if (Number(monto) <= 0) return res.status(400).json({ error: 'Monto debe ser positivo' });
    if (Number(monto) > Number(cuenta.saldo)) {
      return res.status(400).json({ error: `Monto supera el saldo (${cuenta.saldo})` });
    }

    const conn = await pool.getConnection();
    try {
      await conn.query('CALL sp_registrar_pago(?, ?, ?, ?, ?)',
        [cuenta.id_venta, monto, metodo_pago || 'EFECTIVO', referencia || null, id_usuario]);

      await conn.query(
        `UPDATE cuentas_por_cobrar
         SET saldo = GREATEST(0, saldo - ?),
             estado = CASE
               WHEN saldo - ? <= 0 THEN 'PAGADA'
               ELSE 'PAGADA_PARCIAL'
             END
         WHERE id_cuenta = ?`,
        [monto, monto, id]
      );
      res.json({ ok: true });
    } finally { conn.release(); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// REPORTES
// ============================================================
app.get('/api/reportes/ventas-por-dia', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT DATE(fecha_hora) AS fecha,
             COUNT(*) AS cantidad,
             COALESCE(SUM(total),0) AS total
      FROM ventas
      WHERE fecha_hora >= DATE_SUB(CURRENT_DATE, INTERVAL 7 DAY)
        AND estado <> 'ANULADA'
      GROUP BY DATE(fecha_hora)
      ORDER BY fecha
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reportes/top-productos', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT p.id_producto, p.referencia, p.nombre,
             SUM(dv.cantidad_base) AS unidades,
             SUM(dv.subtotal) AS total
      FROM detalle_venta dv
      JOIN productos p ON p.id_producto = dv.id_producto
      JOIN ventas v ON v.id_venta = dv.id_venta
      WHERE v.estado <> 'ANULADA'
      GROUP BY p.id_producto
      ORDER BY unidades DESC
      LIMIT 5
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reportes/por-categoria', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT c.nombre AS categoria,
             COALESCE(SUM(dv.subtotal),0) AS total
      FROM detalle_venta dv
      JOIN productos p ON p.id_producto = dv.id_producto
      JOIN categorias c ON c.id_categoria = p.id_categoria
      JOIN ventas v ON v.id_venta = dv.id_venta
      WHERE v.estado <> 'ANULADA'
      GROUP BY c.id_categoria
      ORDER BY total DESC
      LIMIT 8
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// REPORTE DE DEFECTUOSOS Y DEVOLUCIONES
// ============================================================
app.get('/api/reportes/defectuosos', async (_req, res) => {
  try {
    const [porProducto] = await pool.query(`
      SELECT p.id_producto, p.referencia, p.nombre,
             c.nombre AS categoria,
             sc.cantidad, sc.condicion
      FROM stock_condicion sc
      JOIN productos p ON p.id_producto = sc.id_producto
      JOIN categorias c ON c.id_categoria = p.id_categoria
      WHERE sc.cantidad > 0
      ORDER BY sc.cantidad DESC
    `);

    const [porCategoria] = await pool.query(`
      SELECT c.nombre AS categoria,
             SUM(sc.cantidad) AS total
      FROM stock_condicion sc
      JOIN productos p ON p.id_producto = sc.id_producto
      JOIN categorias c ON c.id_categoria = p.id_categoria
      WHERE sc.cantidad > 0
      GROUP BY c.id_categoria
      ORDER BY total DESC
    `);

    const [devolucionesPorCondicion] = await pool.query(`
      SELECT dd.condicion_producto AS condicion,
             COUNT(*) AS total,
             SUM(dd.cantidad) AS unidades
      FROM detalle_devolucion dd
      GROUP BY dd.condicion_producto
    `);

    const [kpis] = await pool.query(`
      SELECT
        (SELECT COALESCE(SUM(cantidad),0) FROM stock_condicion WHERE condicion='DEFECTUOSO')      AS total_defectuoso,
        (SELECT COALESCE(SUM(cantidad),0) FROM stock_condicion WHERE condicion='REACONDICIONADO') AS total_reacondicionado,
        (SELECT COUNT(*) FROM detalle_devolucion WHERE condicion_producto='DEFECTUOSO')           AS devoluciones_defectuosas
    `);

    res.json({ porProducto, porCategoria, devolucionesPorCondicion, kpis: kpis[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// START
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 API escuchando en puerto ${PORT}`);
});