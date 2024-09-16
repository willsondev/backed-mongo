const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const Class = require('../models/Class');
const { auth, adminAuth } = require('../middleware/auth');

const sanitizeHtml = require('sanitize-html');
const User = require('../models/user.js');

// Crear una nueva clase
router.post('/', auth, adminAuth, 
  body('title').notEmpty().withMessage('El título es obligatorio'),
  body('description').notEmpty().withMessage('La descripción es obligatoria'),
  body('dateTime').isISO8601().withMessage('Formato de fecha/hora inválido'),
  body('maxReservations').isInt({ min: 1 }).withMessage('Las reservas máximas deben ser al menos 1'),
  body('description').custom(value => {
    const sanitizedDescription = sanitizeHtml(value, {
      allowedTags: ['p', 'br', 'strong', 'em'],
      allowedAttributes: {
        p: ['style'],
        br: [],
        strong: [],
        em: []
      }
    });
    if (sanitizedDescription !== value) {
      throw new Error('HTML inválido en la descripción');
    }
    return sanitizedDescription;
  }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { title, description, dateTime, maxReservations } = req.body;

      // Validación para evitar clases duplicadas
      const existingClass = await Class.findOne({
        $or: [
          { title: { $regex: new RegExp(title, 'i') } },
          { dateTime: { $eq: new Date(dateTime) } }
        ]
      });

      if (existingClass) {
        return res.status(400).json({ error: 'Ya existe una clase con un título y una fecha/hora similares' });
      }

      const newClass = new Class({ title, description, dateTime, maxReservations, reservedCount: 0 });
      await newClass.save();
      res.status(201).json(newClass);
    } catch (error) {
      console.error(error.stack);
      res.status(500).json({ error: 'Error al crear la clase' });
    }
  }
);

// Obtener todas las clases (con paginación)
router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const classes = await Class.find().skip(startIndex).limit(limit);
    const total = await Class.countDocuments();

    const pagination = {
      current: page,
      limit: limit,
      total: total,
      totalPages: Math.ceil(total / limit)
    };

    res.json({
      classes: classes,
      pagination: pagination
    });
  } catch (error) {
    console.error(error.stack);
    res.status(500).json({ error: 'Error al recuperar las clases' });
  }
});

// Obtener una clase por ID
router.get('/:id', async (req, res) => {
  try {
    const classData = await Class.findById(req.params.id);
    if (!classData) {
      return res.status(404).json({ error: 'Clase no encontrada' });
    }
    res.json(classData);
  } catch (error) {
    console.error(error.stack);
    res.status(500).json({ error: 'Error al obtener la clase' });
  }
});

// Actualizar una clase
router.put('/:id', auth, adminAuth, async (req, res) => {
  try {
    const updatedClass = await Class.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedClass) {
      return res.status(404).json({ error: 'Clase no encontrada' });
    }
    res.json(updatedClass);
  } catch (error) {
    console.error(error.stack);
    res.status(500).json({ error: 'Error al actualizar la clase' });
  }
});

// Eliminar una clase
router.delete('/:id', auth, adminAuth, async (req, res) => {
  try {
    const deletedClass = await Class.findByIdAndDelete(req.params.id);
    if (!deletedClass) {
      return res.status(404).json({ error: 'Clase no encontrada' });
    }
    res.json({ message: 'Clase eliminada' });
  } catch (error) {
    console.error(error.stack);
    res.status(500).json({ error: 'Error al eliminar la clase' });
  }
});

// Reservar una Clase
router.post('/:id/reserve', auth,
  body('name').notEmpty().withMessage('El nombre es obligatorio'),
  body('email').isEmail().withMessage('Dirección de correo electrónico inválida'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const classData = await Class.findById(req.params.id);
      if (!classData) {
        return res.status(404).json({ error: 'Clase no encontrada' });
      }

      // Verificar si el usuario ya ha reservado la clase
      if (classData.reservedBy.includes(req.user._id.toString())) {
        return res.status(400).json({ error: 'Ya has reservado esta clase' });
      }

      if (classData.reservedCount >= classData.maxReservations) {
        return res.status(400).json({ error: 'No hay plazas disponibles' });
      }

      // Actualizar la clase
      classData.reservedCount += 1;
      classData.reservedBy.push(req.user._id);
      await classData.save();

      // Actualizar el usuario (agregar la reserva al historial)
      const user = await User.findById(req.user._id);
      user.reservations.push({
        classId: classData._id,
        date: new Date()
      });
      await user.save();

      // Mostrar un mensaje de confirmación
      res.json({ message: 'Reserva exitosa para la clase: ' + classData.title });
    } catch (error) {
      console.error(error.stack);
      res.status(500).json({ error: 'Error al reservar la clase' });
    }
  }
);

module.exports = router;