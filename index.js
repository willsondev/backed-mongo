const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston'); // Para el logging


const authRoutes = require('./routes/auth');
const classRoutes = require('./routes/classes');
const userRoutes = require('./routes/users'); // Importa la ruta de usuarios
const { auth, adminAuth } = require('./middleware/auth');

const app = express(); // Inicializa 'app' antes de usarlo
const port = process.env.PORT || 5000;

// Configuración de CORS
app.use(cors({
  origin: '*', // Permite cualquier origen. Puedes personalizarlo según tus necesidades.
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Métodos permitidos
  allowedHeaders: ['Content-Type', 'Authorization'] // Headers permitidos
}));

// Middleware
app.use(express.json());
app.use(helmet());

// Swagger Documentation Route


// Rutas
app.use('/api/auth', authRoutes);
app.use('/api/classes', classRoutes);
app.use('/api/users', userRoutes); // Agrega la ruta de usuarios

// Logging con winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.Console({ level: 'info' })
  ]
});

// Manejo de errores
const errorHandler = (err, req, res, next) => {
  logger.error(err.stack); // Registra el error en el log

  let statusCode = 500;
  if (err.name === 'ValidationError') {
    statusCode = 400;
  } else if (err.name === 'UnauthorizedError') {
    statusCode = 401;
  } else if (err.name === 'NotFound') {
    statusCode = 404;
  }

  const response = {
    error: err.message || 'Internal server error'
  };

  res.status(statusCode).json(response);
};
app.use(errorHandler);

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true }) // Asegúrate de usar las opciones recomendadas
  .then(() => {
    logger.info('MongoDB connected'); // Registra la conexión en el log
    app.listen(port, () => {
      logger.info(`Server running on port ${port}`); // Registra el inicio del servidor en el log
    });
  })
  .catch(err => logger.error('Error connecting to MongoDB:', err)); // Registra el error de conexión en el log
