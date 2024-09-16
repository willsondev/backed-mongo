const mongoose = require('mongoose');

const classSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    description: {
        type: String,
    },
    dateTime: {
        type: Date,
        required: true,
    },
    maxReservations: {
        type: Number,
        required: true,
    },
    reservedCount: {
        type: Number,
        default: 0,
    },
    reservedBy: [{ // Add the reservedBy field
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Reference to the User model
    }]
});

module.exports = mongoose.model('Class', classSchema);