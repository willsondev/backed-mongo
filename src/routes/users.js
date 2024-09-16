const express = require('express');
const router = express.Router();
const User = require('../models/User'); // Importa el modelo de usuario
const { auth } = require('../middleware/auth'); // Importa el middleware de autenticación
const Class = require('../models/Class'); // Ruta al modelo de clase

// Ruta para obtener el historial de reservas
router.get('/reservations', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('reservations.classId', 'title description dateTime'); // Agrega 'name' a la lista de campos

    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const reservations = user.reservations.map(reservation => {
      if (!reservation.classId) {
        // Manejar el error de población
        console.error(`Clase no encontrada para la reserva: ${reservation._id}`);
        return {
           ...reservation,
          classId: null,
          title: 'Clase no disponible',
          description: 'La clase no está disponible',
          dateTime: null
        };
      }
      return reservation;
    });

    res.json(reservations);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
module.exports = router;