const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader) {
    return res.status(401).json({ error: 'Por favor, autentica' });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findOne({
      _id: decoded._id,
      'tokens.token': token
    });

    if (!user) {
      return res.status(401).json({ error: 'Por favor, autentica' });
    }

    req.token = token;
    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({ error: 'Por favor, autentica' });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    // Verifica si el usuario tiene el rol de administrador
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Acceso denegado. Permisos insuficientes.' });
    }

    // Llama al siguiente middleware
    next();
  } catch (error) {
    // Maneja errores de permisos
    res.status(403).json({ error: 'Acceso denegado. Permisos insuficientes.' });
  }
};

module.exports = { auth , adminAuth};
