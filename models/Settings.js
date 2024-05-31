const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SettingsSchema = new Schema({
    videoLink: {
        type: String,
        default: ''
    },
    chinaAddress: {
        type: String,
        default: ''
    },
    whatsappNumber: {
        type: String,
        default: ''
    },
    aboutUsText: {
        type: String,
        default: ''
    },
    prohibitedItemsText: {
        type: String,
        default: ''
    }
});

module.exports = mongoose.model('Settings', SettingsSchema);
