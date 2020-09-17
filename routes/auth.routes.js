const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Ошибка! Некорректный email!').isEmail(),
    check('password', 'Ошибка! Минимальная длина пароля 8 символов').isLength('8')
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req)

    if(!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Ошибка! Вы указали некорректные данные при регистрации!'
      })
    }

    const {email, password} = req.body

    const candidate = await User.findOne({email})

    if(candidate) {
      return res.status(400).json({message: 'Ошибка! Пользователь с таким логином уже существует!'})
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({email, password: hashedPassword})

    await user.save()

    res.status(201).json({message: 'Поздравляем! Пользователь успешно создан!'})

  } catch (e) {
    res.status(500).json({message: 'Ошибка! Что-то пошло не так, пожалуйста попробуйте снова!'})
  }
})

// /api/auth/login
router.post(
  '/login', 
  [
    check('email', 'Ошибка! Введите корректный email!').normalizeEmail().isEmail(),
    check('password', 'Ошибка! Пароль отсутствует! Введите пароль!').exists()
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req)

    if(!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Ошибка! Вы указали некорректные данные для входа!'
      })
    }

    const {email, password} = req.body

    const user = await User.findOne({email})

    if(!user) {
      return res.status(400).json({message: 'Ошибка! Неверные данные для входа!'})
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if(!isMatch) {
      return res.status(400).json({message: 'Ошибка! Неверные данные для входа!'})
    }

    const token = jwt.sign(
      {userId: user.id},
      config.get('jwtSecret'),
      {expiresIn: '1h'}
    )

    res.json({token, userId: user.id})

  } catch (e) {
    res.status(500).json({message: 'Ошибка! Что-то пошло не так, пожалуйста попробуйте снова!'})
  }
})

module.exports = router