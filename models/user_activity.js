const mongoose = require('mongoose');

// Este es el "Schema" o la plantilla para tus documentos.
// Le dice a tu APP cómo debe ser la data.
const activitySchema = new mongoose.Schema({
    // Usamos Number para que coincida con tu user_id de PostgreSQL
    userId: {
        type: Number,
        required: true,
        index: true
    },

    // RATED_MOVIE, WROTE_REVIEW, ADDED_TO_FAVORITES
    type: {
        type: String,
        enum: {
            values: ['calificacion', 'favorito', 'reseña'],
            message: 'El tipo de actividad no es válido'
        },
        required: true
    },

    // La fecha en que ocurrió el evento
    timestamp: {
        type: Date,
        default: Date.now // Se pone automáticamente
    },

    // Aquí guardaremos los detalles que cambian (rating, movieTitle, etc.)
    details: {
        type: Object,
        required: true
    }
}, {
    // Le decimos a Mongoose que la colección en Mongo se llama 'user_activity'
    collection: 'user_activity'
});

// "Compilamos" el plano y lo convertimos en un Modelo (un objeto que sabe
// cómo hablar con la colección 'user_activity' usando ese plano)
const Activity = mongoose.model('Activity', activitySchema);

// Exportamos el Modelo para que app.js pueda usarlo
module.exports = Activity;

