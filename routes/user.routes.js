const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Роут для получения всех пользователей с пагинацией и сортировкой
router.get('/users', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 100;
  const sortByDate = req.query.sortByDate || 'latest'; // Сортировка по дате
  const searchQuery = req.query.search || ''; // Поисковый запрос
  const sortByActivity = req.query.sortByActivity === 'true'; // Сортировка по активности
  const filterByRole = req.query.filterByRole || ''; // Получение роли для фильтрации

  try {
    const startIndex = (page - 1) * limit;

    let query = {}; // Пустой объект запроса для фильтрации

    // Добавляем поисковый запрос в запрос, если он есть
    if (searchQuery) {
      const parsedQuery = parseInt(searchQuery);
      if (!isNaN(parsedQuery)) {
        query.phone = parsedQuery;
      } else {
        query.$or = [
          { name: { $regex: new RegExp(searchQuery, 'i') } },
          { surname: { $regex: new RegExp(searchQuery, 'i') } },
          { userId: { $regex: new RegExp(searchQuery, 'i') } } // Добавляем поиск по полю userId
        ];
      }
    }

    let sortOptions = {};

    // Устанавливаем опции сортировки по дате
    if (sortByDate === 'latest') {
      sortOptions.createdAt = 'desc'; // Сортировка по последней дате создания
    } else if (sortByDate === 'oldest') {
      sortOptions.createdAt = 'asc'; // Сортировка по первой дате создания
    }

    if (filterByRole) {
      query.role = filterByRole; // Фильтрация по роли
    }

    const users = await User.find(query)
      .sort(sortOptions) // Применяем опции сортировки
      .limit(limit)
      .skip(startIndex)
      .lean(); // Используем lean() для получения простых JavaScript объектов

    const usersWithCounts = users.map(user => ({
      ...user,
      bookmarkCount: (user.bookmarks || []).length,
      archiveCount: (user.archive || []).length,
      totalActivity: (user.bookmarks || []).length + (user.archive || []).length
    }));

    // Сортируем пользователей по активности, если необходимо
    if (sortByActivity) {
      usersWithCounts.sort((a, b) => b.totalActivity - a.totalActivity);
    }

    const totalCount = await User.countDocuments(query);

    const response = {
      totalCount,
      currentPage: page,
      totalPages: Math.ceil(totalCount / limit),
      users: usersWithCounts
    };

    res.json(response);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

module.exports = router;
