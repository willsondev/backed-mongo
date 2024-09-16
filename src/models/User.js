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
        classId: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: true },
        date: { type: Date, required: true },
    }]
});

// Middleware to hash password before saving
userSchema.pre('save', async function (next) {
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
    }
    next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (password) {
    const user = this;
    return await bcrypt.compare(password, user.password);
};

// Method to generate a token
userSchema.methods.generateToken = async function () {
    const user = this;
    const token = await jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);
    
    // Save the token in the tokens field
    user.tokens = user.tokens.concat({ token });
    await user.save();
    return token;
};

// Use this pattern to avoid overwriting the model
const User = mongoose.models.User || mongoose.model('User', userSchema);

module.exports = User;