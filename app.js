require('dotenv').config()
const 
  express = require('express'),
  mongoose = require('mongoose'),
  bcrypt = require('bcrypt'),
  jwt = require('jsonwebtoken'),
  app = express()

app.use(express.json())

const User = require('./models/User')
// models
const user = require('./models/User')

// rota pública
app.get('/', (req, res) => {
  res.status(200).json({message: 'Rota principal'})
})

// rota privada
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    // check if user exists
    const user  = await User.findById(id, '-password')
    if (!user) {
        return res.status(404).json({msg: "Usuário não encontrado"})
    }

    res.status(200).json({msg: "Acesso permitido!"})
})

// Registrar usuário
app.post('/auth/register', async (req, res) => {
  const {name, email, password, confirmPassword} = req.body
  if (!name) {
    return res.status(422).json({msg: 'Nome é obrigatório!'})
  }
  if (!email) {
    return res.status(422).json({msg: 'Email é obrigatório!'})
  }
  if (!password) {
    return res.status(422).json({msg: 'Senha é obrigatória!'})
  }
  if (password !== confirmPassword) {
    return res.status(422).json({msg: 'Senhas não conferem!'})
  }

  // check if user exists
  const userExists = await User.findOne({ email: email })
  if (userExists) {
    return res.status(422).json({msg: "Por favor, utilize outro email"})
  }

  // create password
  const salt = await bcrypt.genSalt(12),
    passwordHash = await bcrypt.hash(password, salt)
  
  // create user
  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try {
    await user.save()
    res.status(201).json({msg: "Usuário criado com sucesso!"})
  } catch (error) {
    console.log(error)
    res.status(500).json({
      msg: "Aconteceu um erro no servidor!"
    })
  }
})

// login
app.post('/auth/user', async (req, res) => {
  const {email, password} = req.body
  if (!email) {
    return res.status(422).json({msg: 'Email é obrigatório!'})
  }
  if (!password) {
    return res.status(422).json({msg: 'Senha é obrigatória!'})
  }
  // check if user exists
  const user = await User.findOne({ email: email})
  if (!user) {
    return res.status(422).json({msg: "Usuário não encontrado!"})
  }

  // check password match
  const checkPassword = await bcrypt.compare(password, user.password)

  if (!checkPassword) {
    res.status(404).json({msg: "Senha inválida!"})
  }

  try {
    const secret = process.env.SECRET
    const token = jwt.sign({id: user._id}, secret)
    res.status(200).json({msg: "Autenticado!", token})
  } catch (error) {
    res.status(422).json({msg: "Erro de servidor!"})
  }

})

// checando token válido
function checkToken (req, res, next) {
    const authHeader = req.headers['authorization'],
        token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({msg: "Acesso negado!"})
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    } catch (error) {
        res.status(400).json({msg: "Token inválido!"})
    }
}

// Conectando ao banco
const DB_USER = process.env.DB_USER,
  DB_PASSWORD = process.env.DB_PASSWORD
mongoose.connect(
  `mongodb+srv://${DB_USER}:${DB_PASSWORD}@cluster0.cal7nfv.mongodb.net/?retryWrites=true&w=majority`
).then(() => {
  console.log('Conectado ao banco!')
}).catch((err) => console.log(err))

// Enregando porta
app.listen(3000)