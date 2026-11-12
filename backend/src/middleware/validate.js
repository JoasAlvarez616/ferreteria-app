export function validate(schema) {
  return (req, res, next) => {
    try {
      const result = schema.safeParse(req.body);
      if (!result.success) {
        // Extraer el primer mensaje de error amigable
        const firstError = result.error.errors[0];
        const path = firstError.path.join('.');
        const mensaje = path ? `${path}: ${firstError.message}` : firstError.message;
        return res.status(400).json({ error: mensaje });
      }
      req.body = result.data; // body ya validado y normalizado
      next();
    } catch (err) {
      next(err);
    }
  };
}