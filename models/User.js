const {Schema, model, ObjectId} = require("mongoose")

const TrackBookmarkSchema = new Schema({
    createdAt: { type: Date, default: Date.now },
    description: { type: String, required: true },
    trackNumber: { type: String, required: true },
    trackId: { type: Schema.Types.ObjectId, ref: 'Track', required: false },
    currentStatus: { type: Schema.Types.ObjectId, ref: 'Status', default: null }
});

const ArchiveBookmarkSchema = new Schema({
    createdAt: { type: Date, default: Date.now },
    description: { type: String, required: true },
    trackNumber: { type: String, required: true },
    history: {
        type: [{
            status: {
                type: Schema.Types.ObjectId,
                ref: 'Status'
            },
            date: {
                type: Date,
                default: Date.now
            }
        }],
        default: []
    }
});


const UserSchema = new Schema({
    phone: { type: Number, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    surname: { type: String, required: true },
    email: { type: String, required: false },
    role: { type: String, default: "client" },
    profilePhoto: { type: String, required: false },
    createdAt: { type: Date, default: Date.now },
    userId: { type: String, unique: true, required: true }, // Уникальный идентификатор пользователя с префиксом
    filialId: { type: Schema.Types.ObjectId, ref: 'Filial', required: true }, // Ссылка на филиал
    bookmarks: [TrackBookmarkSchema],  // Объекты с информацией о прикрепленных трек-номерах
    archive: [ArchiveBookmarkSchema]
});

module.exports = model('User', UserSchema);
