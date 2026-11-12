// Errores personalizados de negocio
export class AppError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Recurso no encontrado') {
    super(message, 404);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'No autorizado') {
    super(message, 401);
  }
}

export class ValidationError extends AppError {
  constructor(message = 'Datos inválidos') {
    super(message, 400);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Conflicto con datos existentes') {
    super(message, 409);
  }
}