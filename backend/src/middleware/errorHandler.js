import { AppError } from '../utils/errors.js';

export function errorHandler(err, req, res, next) {
  // Log del error (con contexto)
  const timestamp = new Date().toISOString();
  const method = req.method;
  const path = req.path;

  if (err.isOperational) {
    // Error de negocio: log ligero
    console.warn(`[${timestamp}] ${method} ${path} → ${err.statusCode}: ${err.message}`);
  } else {
    // Error técnico: log completo con stack
    console.error(`[${timestamp}] ERROR NO CONTROLADO en ${method} ${path}`);
    console.error(`  → ${err.message}`);
    console.error(`  → Stack: ${err.stack}`);
  }

  // Respuesta al cliente
  const statusCode = err.statusCode || 500;
  const message = err.isOperational
    ? err.message
    : 'Error interno del servidor. Contacta al administrador.';

  res.status(statusCode).json({
    error: message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
}

export function notFoundHandler(req, res) {
  res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.path}` });
}

// Wrapper para async/await (evita try/catch repetitivo)
export function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}