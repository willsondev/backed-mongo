//user.js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }],
    reservations: [{
        classId: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: true }, // Referencia a la clase
        date: { type: Date, required: true }, // Fecha de la reserva
        // Puedes agregar más campos si necesitas información adicional sobre la reserva
    }]
});

// Middleware para hash de contraseña antes de guardar
userSchema.pre('save', async function (next) {
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
    }
    next();
});

// Método para comparar contraseñas
userSchema.methods.comparePassword = async function (password) {
    const user = this;
    return await bcrypt.compare(password, user.password);
};

// Método para generar un token
userSchema.methods.generateToken = async function () {
    const user = this;
    const token = await jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);
    
    // Guarda el token en el campo tokens
    user.tokens = user.tokens.concat({ token });
    await user.save(); // No olvides guardar el usuario para que se almacene el token
    return token;
};

const User = mongoose.model('User', userSchema);

module.exports = User;