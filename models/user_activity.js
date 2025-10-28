// models/user_activity.js
const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
    userId: {
        type: Number, // coincide con tu user_id de PostgreSQL
        required: true,
        index: true
    },
    type: {
        type: String,
        enum: {
            values: ['RATED_MOVIE', 'WROTE_REVIEW', 'ADDED_TO_FAVORITES'],
            message: 'El tipo de actividad no es válido'
        },
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    details: {
        type: Object,
        required: true
    }
}, {
    collection: 'user_activity'
});

const Activity = mongoose.model('Activity', activitySchema);
module.exports = Activity;
