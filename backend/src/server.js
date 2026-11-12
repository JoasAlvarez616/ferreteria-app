import { validate } from './middleware/validate.js';
import {
  loginSchema,
  productoSchema,
  ventaSchema,
  clienteSchema,
  devolucionSchema,
  pagoCxCSchema,
  importSchema,
  chatSchema,
} from './schemas/index.js';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import 'dotenv/config';
import { pool } from './db.js';
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import { AppError } from './utils/errors.js';
import { errorHandler, notFoundHandler, asyncHandler } from './middleware/errorHandler.js';

const app = express();
const TASA_IVA = 0.19; // 19% Colombia - centralizado
app.set('trust proxy', 1);
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' }));
// Rate limiting en login (5 intentos por IP cada 15 min)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Demasiados intentos fallidos. Espera 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

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
app.post('/api/auth/login', loginLimiter, validate(loginSchema), async (req, res) => {
  const { usuario, password } = req.body;
  try {
    const [[user]] = await pool.query(
      'SELECT id_usuario, nombre, usuario, password_hash, estado FROM usuarios WHERE usuario = ?',
      [usuario]
    );
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
    if (user.estado !== 'ACTIVO') return res.status(403).json({ error: 'Usuario inactivo' });

    // Comparar con bcrypt
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
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
    const [[{ total_ventas }]]    = await pool.query("SELECT COUNT(*) AS total_ventas FROM ventas WHERE estado <> 'ANULADA'");
    const [[{ total_ingresos }]]  = await pool.query(`
      SELECT COALESCE(SUM(CASE WHEN tipo = 'PAGO' THEN monto ELSE -monto END), 0) AS total_ingresos
      FROM pagos
      WHERE estado = 'REGISTRADO'
    `);
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
             p.id_categoria, p.id_marca, p.id_unidad_base,
             pr.id_presentacion
      FROM productos p
      JOIN categorias c ON c.id_categoria = p.id_categoria
      LEFT JOIN marcas m ON m.id_marca = p.id_marca
      JOIN unidades_medida um ON um.id_unidad = p.id_unidad_base
      LEFT JOIN inventario i ON i.id_producto = p.id_producto
      LEFT JOIN stock_condicion sc_def
        ON sc_def.id_producto = p.id_producto AND sc_def.condicion = 'DEFECTUOSO'
      LEFT JOIN stock_condicion sc_reac
        ON sc_reac.id_producto = p.id_producto AND sc_reac.condicion = 'REACONDICIONADO'
      LEFT JOIN presentaciones pr
        ON pr.id_producto = p.id_producto AND pr.es_presentacion_base = TRUE
      ORDER BY p.id_producto DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/productos', validate(productoSchema), async (req, res) => {
  const { referencia, nombre, id_categoria, id_marca, id_unidad_base,
          presentacion, cantidad_base } = req.body;
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

app.post('/api/ventas', validate(ventaSchema), async (req, res) => {
  const { items, id_cliente, forma_pago = 'CONTADO', dias_vencimiento = 30 } = req.body;
  const id_usuario = req.user.id_usuario;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. Validar stock
    for (const item of items) {
      const [[{ cantidad_base: cantBase }]] = await conn.query(
        'SELECT cantidad_base FROM presentaciones WHERE id_presentacion = ?',
        [item.id_presentacion]
      );
      const cantTotal = Number(item.cantidad) * Number(cantBase);
      const [[{ stock }]] = await conn.query(
        'SELECT COALESCE(cantidad_actual, 0) AS stock FROM inventario WHERE id_producto = ?',
        [item.id_producto]
      );
      if (Number(stock) < cantTotal) {
        const [[p]] = await conn.query('SELECT nombre FROM productos WHERE id_producto = ?', [item.id_producto]);
        throw new AppError(`Stock insuficiente para "${p.nombre}". Disponible: ${Number(stock).toFixed(0)}, solicitado: ${cantTotal.toFixed(0)}`, 400);
      }
    }
    // ⬆⬆⬆ ESTE ES EL } QUE FALTABA (cierra el for)

    // 2. Calcular total estimado
    let totalEstimado = 0;
    for (const item of items) {
      totalEstimado += Number(item.cantidad) * Number(item.precio_unitario) * (1 + TASA_IVA);
    }

    // 3. Validar límite de crédito si es a CRÉDITO
    if (forma_pago === 'CREDITO') {
      if (!id_cliente) {
        throw new AppError('Una venta a crédito requiere cliente', 400);
      }
      const [[cliente]] = await conn.query(
        'SELECT nombre, limite_credito FROM clientes WHERE id_cliente = ?',
        [id_cliente]
      );
      if (!cliente) throw new AppError('Cliente no encontrado', 404);

      const [[{ deudaActual }]] = await conn.query(`
        SELECT COALESCE(SUM(saldo), 0) AS deudaActual
        FROM cuentas_por_cobrar
        WHERE id_venta IN (SELECT id_venta FROM ventas WHERE id_cliente = ?)
          AND estado NOT IN ('PAGADA', 'ANULADA')
      `, [id_cliente]);

      const limite = Number(cliente.limite_credito);
      const deudaTotal = Number(deudaActual) + totalEstimado;

      if (limite > 0 && deudaTotal > limite) {
        throw new AppError(
          `Límite de crédito excedido para ${cliente.nombre}. ` +
          `Deuda actual: $${Number(deudaActual).toLocaleString('es-CO')}, ` +
          `nueva venta: $${totalEstimado.toLocaleString('es-CO')}, ` +
          `límite: $${limite.toLocaleString('es-CO')}`
        );
      }
    }

    // 4. Registrar venta
    await conn.query('SET @id_venta = 0');
    await conn.query('CALL sp_registrar_venta(?, ?, CAST(? AS JSON), @id_venta)',
      [id_usuario, id_cliente || null, JSON.stringify(items)]);
    const [[{ id_venta }]] = await conn.query('SELECT @id_venta AS id_venta');
    const [[venta]] = await conn.query(
      'SELECT id_venta, subtotal, iva, total, estado FROM ventas WHERE id_venta = ?',
      [id_venta]
    );

    // 5. CONTADO → pago completo
    if (forma_pago === 'CONTADO') {
      await conn.query('CALL sp_registrar_pago(?, ?, ?, ?, ?)',
        [id_venta, venta.total, 'EFECTIVO', 'Pago contado automático', id_usuario]);
    }
    // 6. CRÉDITO → CxC automática
    else if (forma_pago === 'CREDITO' && id_cliente) {
      await conn.query(`
        INSERT INTO cuentas_por_cobrar (id_venta, fecha_vencimiento, monto_original, saldo, estado)
        VALUES (?, DATE_ADD(CURRENT_DATE, INTERVAL ? DAY), ?, ?, 'PENDIENTE')
      `, [id_venta, Number(dias_vencimiento) || 30, venta.total, venta.total]);
      await conn.query("UPDATE ventas SET estado = 'CREDITO' WHERE id_venta = ?", [id_venta]);
    }

    const [[ventaFinal]] = await conn.query(
      'SELECT id_venta, subtotal, iva, total, estado FROM ventas WHERE id_venta = ?',
      [id_venta]
    );
    await conn.commit();
    res.status(201).json({ ok: true, venta: ventaFinal });
  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
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

app.post('/api/ventas/:id/devolucion', validate(devolucionSchema), async (req, res) => {
  try {
    const { id } = req.params;
    const { motivo, items } = req.body;
    const id_usuario = req.user.id_usuario;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // 1. Validar que no devuelva más de lo vendido
      for (const item of items) {
        const [[info]] = await conn.query(`
          SELECT dv.cantidad AS vendida,
                 COALESCE(SUM(dd.cantidad), 0) AS devuelta,
                 p.nombre AS producto
          FROM detalle_venta dv
          JOIN productos p ON p.id_producto = dv.id_producto
          LEFT JOIN detalle_devolucion dd ON dd.id_detalle_venta = dv.id_detalle_venta
          WHERE dv.id_detalle_venta = ?
          GROUP BY dv.id_detalle_venta
        `, [item.id_detalle_venta]);

        if (!info) {
          throw new AppError(`Detalle de venta ${item.id_detalle_venta} no existe`, 404);
        }

        const disponible = Number(info.vendida) - Number(info.devuelta);
        if (Number(item.cantidad) > disponible) {
          throw new AppError(
            `No puedes devolver ${item.cantidad} de "${info.producto}". ` +
            `Disponible para devolver: ${disponible}`
          );
        }
      }

      // 2. Registrar la devolución
      await conn.query('SET @id_dev = 0');
      await conn.query('CALL sp_registrar_devolucion(?, ?, ?, CAST(? AS JSON), @id_dev)',
        [id, id_usuario, motivo || null, JSON.stringify(items)]);
      const [[{ id_dev }]] = await conn.query('SELECT @id_dev AS id_dev');

      // 3. Calcular monto devuelto
      const [[{ monto_dev }]] = await conn.query(`
        SELECT COALESCE(SUM(dd.cantidad * dv.precio_unitario * (1 + ${TASA_IVA})), 0) AS monto_dev
        FROM detalle_devolucion dd
        JOIN detalle_venta dv ON dv.id_detalle_venta = dd.id_detalle_venta
        WHERE dd.id_devolucion = ?
      `, [id_dev]);

      // 4. Registrar reembolso si la venta estaba PAGADA o CREDITO
      const [[venta]] = await conn.query(
        'SELECT estado FROM ventas WHERE id_venta = ?', [id]
      );
      if ((venta.estado === 'PAGADA' || venta.estado === 'CREDITO') && Number(monto_dev) > 0) {
        await conn.query(`
          INSERT INTO pagos (id_venta, id_devolucion, tipo, monto, metodo_pago, referencia, id_usuario, estado)
          VALUES (?, ?, 'REEMBOLSO', ?, 'EFECTIVO', 'Reembolso por devolución', ?, 'REGISTRADO')
        `, [id, id_dev, monto_dev, id_usuario]);
      }

      await conn.commit();
      res.status(201).json({ ok: true, id_devolucion: id_dev, monto_devuelto: Number(monto_dev) });
    } catch (err) {
      await conn.rollback();
      res.status(400).json({ error: err.message });
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

app.post('/api/clientes', validate(clienteSchema), async (req, res) => {
  const { nombre, tipo_documento, numero_documento, telefono, direccion, limite_credito } = req.body;
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

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const dias = Number(dias_vencimiento) || 30;
      const [r] = await conn.query(
        `INSERT INTO cuentas_por_cobrar
         (id_venta, fecha_vencimiento, monto_original, saldo, estado)
         VALUES (?, DATE_ADD(CURRENT_DATE, INTERVAL ? DAY), ?, ?, 'PENDIENTE')`,
        [id, dias, venta.total, venta.total]
      );
      await conn.query("UPDATE ventas SET estado = 'CREDITO' WHERE id_venta = ?", [id]);
      await conn.commit();
      res.status(201).json({ ok: true, id_cuenta: r.insertId });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally { conn.release(); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/cuentas-por-cobrar/:id/pago', validate(pagoCxCSchema), async (req, res) => {
  try {
    const { id } = req.params;
    const { monto, metodo_pago, referencia } = req.body;
    const id_usuario = req.user.id_usuario;

    const [[cuenta]] = await pool.query(
      'SELECT id_venta, saldo FROM cuentas_por_cobrar WHERE id_cuenta = ?', [id]
    );
    if (!cuenta) return res.status(404).json({ error: 'Cuenta no encontrada' });
    if (Number(monto) > Number(cuenta.saldo)) {
      return res.status(400).json({ error: `Monto supera el saldo (${cuenta.saldo})` });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
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
      await conn.commit();
      res.json({ ok: true });
    } catch (err) {
      await conn.rollback();
      throw err;
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
// IMPORTAR PRODUCTOS EN LOTE
// ============================================================
app.post('/api/productos/importar', validate(importSchema), async (req, res) => {
  const { items } = req.body;

  const conn = await pool.getConnection();
  const resultado = { creados: 0, errores: [], categorias_creadas: [], marcas_creadas: [] };

  try {
    await conn.beginTransaction();

    // Caché de catálogos existentes
    const [cats]   = await conn.query('SELECT id_categoria, nombre FROM categorias');
    const [marcas] = await conn.query('SELECT id_marca, nombre FROM marcas');
    const [unds]   = await conn.query('SELECT id_unidad, abreviatura, nombre FROM unidades_medida');

    const catMap   = {};
    const marcaMap = {};
    const uniMap   = {};
    cats.forEach(c   => catMap[c.nombre.toLowerCase()] = c.id_categoria);
    marcas.forEach(m => marcaMap[m.nombre.toLowerCase()] = m.id_marca);
    unds.forEach(u   => {
      uniMap[u.abreviatura.toLowerCase()] = u.id_unidad;
      uniMap[u.nombre.toLowerCase()]      = u.id_unidad;
    });

    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const fila = i + 2; // 1 header + 1 index

      try {
        if (!it.referencia || !it.nombre || !it.categoria) {
          resultado.errores.push({ fila, referencia: it.referencia || '?', error: 'Faltan referencia, nombre o categoria' });
          continue;
        }

        // Categoría: crea si no existe
        let id_categoria = catMap[String(it.categoria).toLowerCase()];
        if (!id_categoria) {
          const [r] = await conn.query('INSERT INTO categorias (nombre) VALUES (?)', [it.categoria]);
          id_categoria = r.insertId;
          catMap[String(it.categoria).toLowerCase()] = id_categoria;
          resultado.categorias_creadas.push(it.categoria);
        }

        // Marca: opcional, crea si no existe
        let id_marca = null;
        if (it.marca && String(it.marca).trim()) {
          id_marca = marcaMap[String(it.marca).toLowerCase()];
          if (!id_marca) {
            const [r] = await conn.query('INSERT INTO marcas (nombre) VALUES (?)', [it.marca]);
            id_marca = r.insertId;
            marcaMap[String(it.marca).toLowerCase()] = id_marca;
            resultado.marcas_creadas.push(it.marca);
          }
        }

        // Unidad: por abreviatura o nombre; default 'und'
        let id_unidad = null;
        if (it.unidad) {
          id_unidad = uniMap[String(it.unidad).toLowerCase()];
        }
        if (!id_unidad) id_unidad = uniMap['und'];
        if (!id_unidad) {
          resultado.errores.push({ fila, referencia: it.referencia, error: 'Unidad no encontrada' });
          continue;
        }

        // Insertar producto
        const [r] = await conn.query(
          `INSERT INTO productos (referencia, nombre, id_categoria, id_marca, id_unidad_base, descripcion)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [it.referencia, it.nombre, id_categoria, id_marca, id_unidad, it.descripcion || null]
        );
        const id_producto = r.insertId;

        // Presentación
        await conn.query(
          `INSERT INTO presentaciones (id_producto, nombre, id_unidad, cantidad_base, es_presentacion_base)
           VALUES (?, ?, ?, ?, TRUE)`,
          [id_producto, it.presentacion || 'Unidad', id_unidad, Number(it.cantidad_base) || 1]
        );

        // Inventario inicial
        await conn.query(
          'INSERT IGNORE INTO inventario (id_producto, cantidad_actual) VALUES (?, 0)',
          [id_producto]
        );

        resultado.creados++;
      } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          resultado.errores.push({ fila, referencia: it.referencia, error: 'Referencia duplicada' });
        } else {
          resultado.errores.push({ fila, referencia: it.referencia, error: err.message });
        }
      }
    }

    await conn.commit();
    res.json({ ok: true, ...resultado });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ============================================================
// CHAT IA CON FUNCTION CALLING (Groq → OpenRouter failover)
// ============================================================
app.post('/api/chat', validate(chatSchema), async (req, res) => {
  const { mensaje } = req.body;

  try {
    // ============================================================
    // 1. Definir las herramientas (formato OpenAI)
    // ============================================================
    const tools = [
      {
        type: 'function',
        function: {
          name: 'consultar_stock_producto',
          description: 'Consulta el stock actual de un producto específico por su nombre o referencia.',
          parameters: {
            type: 'object',
            properties: {
              nombre: { type: 'string', description: 'Nombre o referencia del producto' }
            },
            required: ['nombre']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'listar_productos_bajo_stock',
          description: 'Lista los productos con stock menor a 5 unidades. Útil para saber qué reabastecer.',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'listar_productos_por_categoria',
          description: 'Lista TODOS los productos de una categoría específica (ej: Plomería, Pinturas, Electricidad, Herramientas manuales).',
          parameters: {
            type: 'object',
            properties: {
              categoria: { type: 'string', description: 'Nombre exacto o parcial de la categoría' }
            },
            required: ['categoria']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'ventas_del_dia',
          description: 'Devuelve el total vendido hoy, cantidad de ventas y monto en pesos.',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'top_productos_vendidos',
          description: 'Devuelve los 5 productos más vendidos de la historia del negocio.',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'saldo_cliente',
          description: 'Consulta el saldo deudor pendiente de un cliente por su nombre.',
          parameters: {
            type: 'object',
            properties: {
              nombre: { type: 'string', description: 'Nombre del cliente' }
            },
            required: ['nombre']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'listar_clientes',
          description: 'Lista todos los clientes con su límite de crédito y deuda actual.',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'ventas_recientes',
          description: 'Devuelve las últimas 10 ventas realizadas con cliente, total y estado.',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'resumen_negocio',
          description: 'Devuelve KPIs generales: total de productos, stock total, número de ventas e ingresos netos.',
          parameters: { type: 'object', properties: {} }
        }
      }
    ];

    // ============================================================
    // 2. Ejecutor de herramientas
    // ============================================================
    async function ejecutarTool(nombre, args) {
      switch (nombre) {

        case 'consultar_stock_producto': {
          const q = `%${args.nombre}%`;
          const [rows] = await pool.query(`
            SELECT p.referencia, p.nombre,
                   COALESCE(i.cantidad_actual, 0) AS stock,
                   COALESCE(sc_def.cantidad, 0) AS defectuosos,
                   COALESCE(sc_reac.cantidad, 0) AS reacondicionados
            FROM productos p
            LEFT JOIN inventario i ON i.id_producto = p.id_producto
            LEFT JOIN stock_condicion sc_def ON sc_def.id_producto = p.id_producto AND sc_def.condicion = 'DEFECTUOSO'
            LEFT JOIN stock_condicion sc_reac ON sc_reac.id_producto = p.id_producto AND sc_reac.condicion = 'REACONDICIONADO'
            WHERE p.nombre LIKE ? OR p.referencia LIKE ?
            LIMIT 5
          `, [q, q]);
          return rows.length ? rows : { mensaje: `No encontré productos con "${args.nombre}"` };
        }

        case 'listar_productos_bajo_stock': {
          const [rows] = await pool.query(`
            SELECT p.referencia, p.nombre, i.cantidad_actual AS stock
            FROM productos p
            JOIN inventario i ON i.id_producto = p.id_producto
            WHERE i.cantidad_actual < 5
            ORDER BY i.cantidad_actual ASC
            LIMIT 15
          `);
          return rows.length ? rows : { mensaje: 'No hay productos con stock bajo' };
        }

        case 'listar_productos_por_categoria': {
          const q = `%${args.categoria}%`;
          const [rows] = await pool.query(`
            SELECT p.referencia, p.nombre, c.nombre AS categoria,
                   COALESCE(i.cantidad_actual, 0) AS stock
            FROM productos p
            JOIN categorias c ON c.id_categoria = p.id_categoria
            LEFT JOIN inventario i ON i.id_producto = p.id_producto
            WHERE c.nombre LIKE ?
            ORDER BY p.nombre
            LIMIT 30
          `, [q]);
          return rows.length ? rows : { mensaje: `No encontré productos en la categoría "${args.categoria}"` };
        }

        case 'ventas_del_dia': {
          const [[data]] = await pool.query(`
            SELECT COUNT(*) AS cantidad, COALESCE(SUM(total), 0) AS total
            FROM ventas
            WHERE DATE(fecha_hora) = CURRENT_DATE AND estado <> 'ANULADA'
          `);
          return { ventas_hoy: Number(data.cantidad), total_hoy: Number(data.total) };
        }

        case 'top_productos_vendidos': {
          const [rows] = await pool.query(`
            SELECT p.referencia, p.nombre, SUM(dv.cantidad_base) AS unidades
            FROM detalle_venta dv
            JOIN productos p ON p.id_producto = dv.id_producto
            JOIN ventas v ON v.id_venta = dv.id_venta
            WHERE v.estado <> 'ANULADA'
            GROUP BY p.id_producto
            ORDER BY unidades DESC
            LIMIT 5
          `);
          return rows.length ? rows : { mensaje: 'Aún no hay ventas registradas' };
        }

        case 'saldo_cliente': {
          const q = `%${args.nombre}%`;
          const [rows] = await pool.query(`
            SELECT c.nombre, COALESCE(SUM(cxc.saldo), 0) AS deuda_total
            FROM clientes c
            LEFT JOIN cuentas_por_cobrar cxc
              ON cxc.id_venta IN (SELECT id_venta FROM ventas WHERE id_cliente = c.id_cliente)
             AND cxc.estado NOT IN ('PAGADA', 'ANULADA')
            WHERE c.nombre LIKE ?
            GROUP BY c.id_cliente
            LIMIT 3
          `, [q]);
          return rows.length ? rows : { mensaje: `No encontré clientes con "${args.nombre}"` };
        }

        case 'listar_clientes': {
          const [rows] = await pool.query(`
            SELECT c.nombre, c.limite_credito,
                   COALESCE(SUM(cxc.saldo), 0) AS deuda
            FROM clientes c
            LEFT JOIN cuentas_por_cobrar cxc
              ON cxc.id_venta IN (SELECT id_venta FROM ventas WHERE id_cliente = c.id_cliente)
             AND cxc.estado NOT IN ('PAGADA', 'ANULADA')
            GROUP BY c.id_cliente
            ORDER BY c.nombre
            LIMIT 20
          `);
          return rows.length ? rows : { mensaje: 'No hay clientes registrados' };
        }

        case 'ventas_recientes': {
          const [rows] = await pool.query(`
            SELECT v.id_venta,
                   COALESCE(c.nombre, 'Consumidor final') AS cliente,
                   v.total, v.estado,
                   DATE_FORMAT(v.fecha_hora, '%Y-%m-%d %H:%i') AS fecha
            FROM ventas v
            LEFT JOIN clientes c ON c.id_cliente = v.id_cliente
            ORDER BY v.id_venta DESC
            LIMIT 10
          `);
          return rows.length ? rows : { mensaje: 'Aún no hay ventas registradas' };
        }

        case 'resumen_negocio': {
          const [[kpis]] = await pool.query(`
            SELECT
              (SELECT COUNT(*) FROM productos) AS productos,
              (SELECT COALESCE(SUM(cantidad_actual),0) FROM inventario) AS stock,
              (SELECT COUNT(*) FROM ventas WHERE estado <> 'ANULADA') AS ventas,
              (SELECT COALESCE(SUM(CASE WHEN tipo='PAGO' THEN monto ELSE -monto END),0)
                 FROM pagos WHERE estado='REGISTRADO') AS ingresos
          `);
          return {
            productos: Number(kpis.productos),
            stock_total: Number(kpis.stock),
            ventas_registradas: Number(kpis.ventas),
            ingresos_netos: Number(kpis.ingresos)
          };
        }

        default:
          return { error: `Herramienta desconocida: ${nombre}` };
      }
    }

    // ============================================================
    // 3. System prompt ESTRICTO (anti-alucinación)
    // ============================================================
    const systemPrompt = `Eres FerreBot, el asistente virtual del sistema FerreStock para gestión de ferretería.

REGLAS ESTRICTAS:
1. Responde SIEMPRE en español, máximo 5 líneas, tono profesional y amable.
2. NO uses markdown ni negritas (no **, no ##, no tablas).
3. SOLO usa información real obtenida de las herramientas disponibles.
4. NUNCA inventes datos, cifras, productos ni funcionalidades.
5. NUNCA digas que puedes enviar correos, generar PDFs, crear enlaces de descarga o hacer llamadas. NO PUEDES.
6. Si te piden algo que no puedes hacer, di exactamente: "No puedo [acción]. Pero puedo mostrarte [alternativa]".
7. Si necesitas datos, LLAMA a la herramienta adecuada. No respondas de memoria.
8. Si no encuentras un producto/cliente/categoría, dilo claramente.

CAPACIDADES REALES:
- Consultar stock de productos
- Listar productos por categoría o con stock bajo
- Ver ventas del día, últimas ventas y top productos
- Consultar deuda de clientes
- Mostrar resumen general del negocio

EJEMPLOS DE RESPUESTAS CORRECTAS:
- Pregunta: "¿Cuántos martillos tengo?" → Llamas consultar_stock_producto("martillo") → Respondes con la cantidad exacta.
- Pregunta: "Envíame la lista de plomería por correo" → Respondes: "No puedo enviar correos. Pero puedo mostrarte la lista de productos de plomería aquí mismo: ..."
- Pregunta: "¿Cuánto vendí hoy?" → Llamas ventas_del_dia() → Respondes con el monto exacto.

Ante cualquier ambigüedad, ofrece una alternativa concreta de lo que SÍ puedes hacer.`;

    // ============================================================
    // 4. Failover Groq → OpenRouter con function calling
    // ============================================================
    const providers = [
      {
        nombre: 'Groq',
        url: 'https://api.groq.com/openai/v1/chat/completions',
        key: process.env.GROQ_API_KEY,
        model: 'llama-3.3-70b-versatile',
      },
      {
        nombre: 'OpenRouter',
        url: 'https://openrouter.ai/api/v1/chat/completions',
        key: process.env.OPENROUTER_API_KEY,
        model: 'meta-llama/llama-3.3-70b-instruct:free',
      },
    ];

    let ultimoError = null;

    for (const provider of providers) {
      if (!provider.key) {
        console.warn(`[IA] ${provider.nombre} omitido: falta ${provider.nombre === 'Groq' ? 'GROQ_API_KEY' : 'OPENROUTER_API_KEY'}`);
        continue;
      }

      try {
        // Historial de mensajes
        const messages = [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: mensaje }
        ];

        let respuestaFinal = null;
        let iteraciones = 0;
        const MAX_ITERACIONES = 5;

        while (iteraciones < MAX_ITERACIONES && !respuestaFinal) {
          iteraciones++;

          const response = await fetch(provider.url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${provider.key}`,
            },
            body: JSON.stringify({
              model: provider.model,
              messages,
              tools,
              tool_choice: 'auto',
              temperature: 0.3,
              max_tokens: 500,
            }),
          });

          if (!response.ok) {
            const errText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errText.slice(0, 200)}`);
          }

          const data = await response.json();
          const choice = data.choices?.[0]?.message;

          if (!choice) throw new Error('Respuesta vacía del modelo');

          // ¿El modelo quiere llamar herramientas?
          if (choice.tool_calls && choice.tool_calls.length > 0) {
            // Agregar respuesta del modelo al historial
            messages.push({
              role: 'assistant',
              content: choice.content || null,
              tool_calls: choice.tool_calls
            });

            // Ejecutar cada tool_call
            for (const call of choice.tool_calls) {
              const nombreTool = call.function.name;
              let args = {};
              try {
                args = JSON.parse(call.function.arguments || '{}');
              } catch (e) {
                args = {};
              }

              console.log(`[IA] ${provider.nombre} invoca: ${nombreTool}`, args);

              const resultado = await ejecutarTool(nombreTool, args);

              // Agregar respuesta de la tool al historial
              messages.push({
                role: 'tool',
                tool_call_id: call.id,
                content: JSON.stringify(resultado)
              });
            }
            // Continuar el loop para que el modelo redacte la respuesta final
            continue;
          }

          // Si no hay tool_calls → ya tenemos respuesta final
          respuestaFinal = choice.content?.trim() || 'No pude generar una respuesta.';
        }

        if (respuestaFinal) {
          console.log(`[IA] ✅ Respondido por: ${provider.nombre}`);
          return res.json({ respuesta: respuestaFinal });
        }

        throw new Error('Máximo de iteraciones alcanzado sin respuesta final');

      } catch (err) {
        ultimoError = err;
        console.error(`[IA] ❌ Falló ${provider.nombre}:`, err.message);
        // Continúa al siguiente proveedor
      }
    }

    // Todos fallaron
    console.error('❌ Todos los proveedores de IA fallaron');
    return res.json({
      respuesta: 'El asistente está temporalmente no disponible. Intenta de nuevo en un momento.'
    });

  } catch (err) {
    console.error('Error crítico en /api/chat:', err);
    res.status(500).json({ error: 'Error procesando el chat.' });
  }
});

// ============================================================
// START
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 API escuchando en puerto ${PORT}`);
});