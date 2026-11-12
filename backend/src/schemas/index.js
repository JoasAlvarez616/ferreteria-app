import { z } from 'zod';

// ============================================================
// AUTH
// ============================================================
export const loginSchema = z.object({
  usuario:  z.string().min(1, 'Usuario obligatorio').max(50).trim(),
  password: z.string().min(1, 'Contraseña obligatoria').max(100),
});

// ============================================================
// PRODUCTOS
// ============================================================
export const productoSchema = z.object({
  referencia: z.string().min(1, 'Referencia obligatoria').max(50, 'Máximo 50 caracteres').trim(),
  nombre:     z.string().min(1, 'Nombre obligatorio').max(150, 'Máximo 150 caracteres').trim(),
  id_categoria:   z.coerce.number().int().positive('Categoría inválida'),
  id_marca:       z.coerce.number().int().positive().nullable().optional(),
  id_unidad_base: z.coerce.number().int().positive('Unidad inválida'),
  presentacion:   z.string().max(80).optional().default('Unidad'),
  cantidad_base:  z.coerce.number().positive('Cantidad debe ser positiva').optional().default(1),
});

// ============================================================
// VENTAS
// ============================================================
export const ventaItemSchema = z.object({
  id_producto:     z.coerce.number().int().positive(),
  id_presentacion: z.coerce.number().int().positive(),
  cantidad:        z.coerce.number().positive('Cantidad debe ser mayor a 0'),
  precio_unitario: z.coerce.number().nonnegative('Precio no puede ser negativo'),
  iva:             z.coerce.number().nonnegative().optional().default(0),
});

export const ventaSchema = z.object({
  items: z.array(ventaItemSchema).min(1, 'Agrega al menos un producto'),
  id_cliente: z.coerce.number().int().positive().nullable().optional(),
  forma_pago: z.enum(['CONTADO', 'CREDITO']).optional().default('CONTADO'),
  dias_vencimiento: z.coerce.number().int().min(1).max(365).optional().default(30),
});

// ============================================================
// CLIENTES
// ============================================================
export const clienteSchema = z.object({
  nombre: z.string().min(1, 'Nombre obligatorio').max(150, 'Máximo 150 caracteres').trim(),
  tipo_documento: z.enum(['CC', 'NIT', 'PASAPORTE', 'OTRO']).optional().default('CC'),
  numero_documento: z.string().max(30).nullable().optional(),
  telefono: z.string().max(30).nullable().optional(),
  direccion: z.string().max(255).nullable().optional(),
  limite_credito: z.coerce.number().nonnegative('Límite no puede ser negativo').optional().default(0),
});

// ============================================================
// DEVOLUCIONES
// ============================================================
export const devolucionItemSchema = z.object({
  id_detalle_venta:   z.coerce.number().int().positive(),
  cantidad:           z.coerce.number().positive(),
  condicion_producto: z.enum(['BUENO', 'DEFECTUOSO', 'REACONDICIONADO']),
});

export const devolucionSchema = z.object({
  motivo: z.string().max(255).nullable().optional(),
  items:  z.array(devolucionItemSchema).min(1, 'Indica al menos un producto a devolver'),
});

// ============================================================
// PAGOS CxC
// ============================================================
export const pagoCxCSchema = z.object({
  monto:       z.coerce.number().positive('Monto debe ser mayor a 0'),
  metodo_pago: z.enum(['EFECTIVO', 'TRANSFERENCIA', 'TARJETA', 'OTRO']).optional().default('EFECTIVO'),
  referencia:  z.string().max(100).nullable().optional(),
});

// ============================================================
// IMPORTAR PRODUCTOS
// ============================================================
export const importItemSchema = z.object({
  referencia:  z.string().min(1).max(50).trim(),
  nombre:      z.string().min(1).max(150).trim(),
  categoria:   z.string().min(1).max(100).trim(),
  marca:       z.string().max(100).nullable().optional(),
  unidad:      z.string().max(10).nullable().optional(),
  presentacion: z.string().max(80).optional().default('Unidad'),
  cantidad_base: z.coerce.number().positive().optional().default(1),
  descripcion: z.string().max(2000).nullable().optional(),
});

export const importSchema = z.object({
  items: z.array(importItemSchema).min(1, 'No hay productos para importar'),
});

// ============================================================
// CHAT
// ============================================================
export const chatSchema = z.object({
  mensaje: z.string().min(1, 'Mensaje vacío').max(500, 'Máximo 500 caracteres').trim(),
});