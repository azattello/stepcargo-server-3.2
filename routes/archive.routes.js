const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Track = require('../models/Track');
const Archive = require('../models/Archive');

// Функция для поиска трека по номеру и добавления в архив
const findTrackAndAddToArchive = async (userId, trackNumber) => {
    try {
        // Находим трек по его номеру
        const track = await Track.findOne({ track: trackNumber });

        // Если трек не найден, возвращаем ошибку 404
        if (!track) {
            throw new Error('Трек не найден');
        }

        // Создаем новый объект для архива
        const newArchive = new Archive({
            trackNumber: trackNumber,
            user: userId,
            history: track.history
        });

        // Сохраняем трек в архив
        await newArchive.save();

        // Удаляем трек из основного списка
        await Track.deleteOne({ track: trackNumber });

        console.log(`Трек ${trackNumber} успешно добавлен в архив и удален из основного списка`);

        return true;
    } catch (error) {
        console.error('Ошибка при добавлении трека в архив:', error.message);
        return false;
    }
};

// Роут для архивирования закладок
router.post('/:userId/archive', async (req, res) => {
    const { userId } = req.params;
    const { bookmarksToArchive } = req.body;

    try {
        // Находим пользователя по его идентификатору
        const user = await User.findById(userId);

        // Если пользователь не найден, возвращаем ошибку 404
        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        // Проверяем, что bookmarksToArchive является массивом
        if (!Array.isArray(bookmarksToArchive)) {
            return res.status(400).json({ message: 'Неверный формат данных для архивирования закладок' });
        }

        // Перебираем закладки для архивирования
        for (const bookmark of bookmarksToArchive) {
            const { trackNumber, description } = bookmark;

            // Находим трек в модели Track по его номеру
            const track = await Track.findOne({ track: trackNumber });
            
            if(track) {
                // Создаем новый архивный объект
                const archiveBookmark = {
                    trackNumber,
                    description,
                    history: track.history
                };

                // Добавляем архивную закладку в архив пользователя
                user.archive.push(archiveBookmark);

                // Удаляем закладку из основного списка пользователя
                user.bookmarks = user.bookmarks.filter(b => b.trackNumber !== trackNumber);

            }
            
        }

        // Удаляем закладки из основного списка и добавляем их в архив
        for (const bookmark of bookmarksToArchive) {
            await findTrackAndAddToArchive(userId, bookmark.trackNumber);
        }

        // Сохраняем изменения в базе данных
        await user.save();

        // Возвращаем успешный ответ
        return res.status(200).json({ message: 'Закладки успешно архивированы' });
    } catch (error) {
        console.error('Ошибка при архивировании закладок:', error.message);
        return res.status(500).json({ message: 'Произошла ошибка при архивировании закладок' });
    }
});

// Роут для получения всех записей из архива пользователя
router.get('/:userId/getArchive', async (req, res) => {
    const { userId } = req.params;

    try {
        // Находим пользователя по его идентификатору
        const user = await User.findById(userId);

        // Если пользователь не найден, возвращаем ошибку 404
        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        // Возвращаем записи из архива пользователя
        return res.status(200).json(user.archive);
    } catch (error) {
        console.error('Ошибка при получении записей из архива:', error.message);
        return res.status(500).json({ message: 'Произошла ошибка при получении записей из архива' });
    }
});


// DELETE запрос для удаления трека из архива пользователя
router.delete('/:userId/delete/:trackNumber', async (req, res) => {
    const { userId, trackNumber } = req.params;

    try {
        // Находим пользователя по его идентификатору
        const user = await User.findById(userId);

        // Если пользователь не найден, возвращаем ошибку 404
        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        // Находим индекс архивного трека в массиве archive пользователя
        const index = user.archive.findIndex(item => item.trackNumber === trackNumber);

        // Если трек не найден в архиве, возвращаем ошибку 404
        if (index === -1) {
            return res.status(404).json({ message: 'Трек не найден в архиве' });
        }

        // Удаляем трек из массива archive
        user.archive.splice(index, 1);

        // Сохраняем изменения
        await user.save();

        return res.status(200).json({ message: 'Трек успешно удален из архива пользователя' });
    } catch (error) {
        console.error('Ошибка при удалении трека из архива:', error.message);
        return res.status(500).json({ message: 'Произошла ошибка при удалении трека из архива' });
    }
});


module.exports = router;
