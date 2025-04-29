# 🚂 Guía Completa de Express.js con MySQL desde Cero

<div align="center">
  <img src="https://expressjs.com/images/express-facebook-share.png" width="240" alt="Express.js Logo" />
</div>

## 📋 Tabla de Contenidos

- [Introducción](#introducción)
- [Prerrequisitos](#prerrequisitos)
- [Instalación](#instalación)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Enrutamiento](#enrutamiento)
- [Middleware](#middleware)
- [Control de Errores](#control-de-errores)
- [Plantillas](#plantillas)
- [Gestión de Peticiones](#gestión-de-peticiones)
- [Bases de Datos con MySQL](#bases-de-datos-con-mysql)
- [Autenticación](#autenticación)
- [Validación](#validación)
- [Despliegue](#despliegue)
- [Mejores Prácticas](#mejores-prácticas)

## 🚀 Introducción

Express.js es un framework web minimalista, flexible y rápido para Node.js. Proporciona un conjunto robusto de características para aplicaciones web y móviles, sin ocultar las funcionalidades de Node.js.

Express facilita la creación de APIs rápidas y robustas, y es la base de muchas otras herramientas y frameworks como NestJS y Sails.js.

## 🛠️ Prerrequisitos

Antes de comenzar con Express.js, asegúrate de tener instalado:

- Node.js (versión 14.x o superior)
- npm (normalmente viene con Node.js)
- MySQL (versión 5.7 o superior)
- Conocimientos básicos de JavaScript

## ⚙️ Instalación

### 1. Crear un nuevo proyecto

```bash
mkdir mi-proyecto-express
cd mi-proyecto-express
npm init -y
```

### 2. Instalar Express

```bash
npm install express
```

### 3. Crear una aplicación básica

Crea un archivo `app.js` en la raíz:

```javascript
const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
  res.send('¡Hola mundo con Express!');
});

app.listen(port, () => {
  console.log(`Aplicación escuchando en http://localhost:${port}`);
});
```

### 4. Ejecutar la aplicación

```bash
node app.js
```

Tu aplicación estará disponible en `http://localhost:3000`.

## 📁 Estructura del Proyecto

Express no impone una estructura específica, pero aquí tienes una organización recomendada:

```
mi-proyecto-express/
├── config/              # Configuraciones (db, env, etc.)
├── controllers/         # Controladores de rutas
├── middleware/          # Middleware personalizado
├── models/              # Modelos para la base de datos
├── public/              # Archivos estáticos (CSS, JS, imágenes)
├── routes/              # Definiciones de rutas
├── services/            # Lógica de negocio
├── views/               # Plantillas de vistas
├── tests/               # Pruebas
├── app.js               # Punto de entrada de la aplicación
├── package.json         # Dependencias y scripts
└── README.md            # Documentación
```

### Ejemplo de proyecto estructurado

Creemos un proyecto estructurado paso a paso:

```bash
mkdir -p config controllers middleware models public/css public/js public/img routes services views tests
touch app.js config/database.js routes/index.js controllers/homeController.js
```

## 🛣️ Enrutamiento

El enrutamiento determina cómo una aplicación responde a una solicitud del cliente en una ruta y método HTTP específico.

### Rutas básicas

```javascript
// app.js
const express = require('express');
const app = express();
const port = 3000;

// Ruta GET
app.get('/', (req, res) => {
  res.send('Página de inicio');
});

// Ruta POST
app.post('/usuarios', (req, res) => {
  res.send('Usuario creado');
});

// Ruta con parámetros
app.get('/usuarios/:id', (req, res) => {
  res.send(`Detalles del usuario ${req.params.id}`);
});

app.listen(port, () => {
  console.log(`Aplicación escuchando en http://localhost:${port}`);
});
```

### Organizando rutas en archivos separados

```javascript
// routes/usuarios.js
const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.send('Listado de usuarios');
});

router.get('/:id', (req, res) => {
  res.send(`Detalles del usuario ${req.params.id}`);
});

router.post('/', (req, res) => {
  res.send('Usuario creado');
});

router.put('/:id', (req, res) => {
  res.send(`Usuario ${req.params.id} actualizado`);
});

router.delete('/:id', (req, res) => {
  res.send(`Usuario ${req.params.id} eliminado`);
});

module.exports = router;
```

```javascript
// app.js
const express = require('express');
const usuariosRouter = require('./routes/usuarios');

const app = express();
const port = 3000;

app.use('/usuarios', usuariosRouter);

app.listen(port, () => {
  console.log(`Aplicación escuchando en http://localhost:${port}`);
});
```

## 🔄 Middleware

Los middleware son funciones que tienen acceso al objeto de solicitud (req), al objeto de respuesta (res) y a la siguiente función de middleware en el ciclo de solicitud/respuesta.

### Middleware incorporado

```javascript
const express = require('express');
const app = express();

// Middleware para analizar JSON
app.use(express.json());

// Middleware para analizar datos de formularios
app.use(express.urlencoded({ extended: true }));

// Middleware para servir archivos estáticos
app.use(express.static('public'));
```

### Middleware personalizado

```javascript
// middleware/logger.js
function logger(req, res, next) {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
}

module.exports = logger;
```

```javascript
// app.js
const express = require('express');
const logger = require('./middleware/logger');

const app = express();

// Aplicar middleware globalmente
app.use(logger);

// Aplicar middleware a una ruta específica
app.get('/usuarios', logger, (req, res) => {
  res.send('Listado de usuarios');
});

app.listen(3000);
```

### Middleware de terceros populares

```bash
npm install morgan cors helmet cookie-parser
```

```javascript
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const app = express();

// Registro de solicitudes HTTP
app.use(morgan('dev'));

// Seguridad con encabezados HTTP
app.use(helmet());

// Habilitar CORS
app.use(cors());

// Analizar cookies
app.use(cookieParser());
```

## ⚠️ Control de Errores

Express proporciona un mecanismo para manejar errores de manera centralizada.

### Middleware de manejo de errores

```javascript
// middleware/errorHandler.js
function errorHandler(err, req, res, next) {
  console.error(err.stack);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Error interno del servidor';
  
  res.status(statusCode).json({
    status: 'error',
    statusCode,
    message
  });
}

module.exports = errorHandler;
```

```javascript
// app.js
const express = require('express');
const errorHandler = require('./middleware/errorHandler');

const app = express();

// Rutas y middleware
app.get('/error', (req, res, next) => {
  const err = new Error('Algo salió mal');
  err.statusCode = 400;
  next(err);
});

// Middleware de manejo de errores (siempre al final)
app.use(errorHandler);

app.listen(3000);
```

### Errores 404 (No encontrado)

```javascript
// app.js
const express = require('express');
const app = express();

// Rutas y middleware aquí...

// Middleware para rutas no encontradas (404)
app.use((req, res, next) => {
  res.status(404).json({
    status: 'error',
    message: 'Ruta no encontrada'
  });
});

app.listen(3000);
```

## 📄 Plantillas

Express puede trabajar con varios motores de plantillas como EJS, Pug, Handlebars, etc.

### Configurar EJS

```bash
npm install ejs
```

```javascript
const express = require('express');
const path = require('path');
const app = express();

// Configurar el motor de plantillas
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Ruta que renderiza una plantilla
app.get('/', (req, res) => {
  res.render('index', { 
    title: 'Mi Aplicación Express', 
    message: '¡Bienvenido!' 
  });
});

app.listen(3000);
```

### Ejemplo de plantilla EJS

```html
<!-- views/index.ejs -->
<!DOCTYPE html>
<html>
<head>
  <title><%= title %></title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <h1><%= message %></h1>
  <p>Esta es una plantilla EJS.</p>
  
  <% if (user) { %>
    <p>Hola, <%= user.name %>!</p>
  <% } else { %>
    <p>Por favor inicia sesión</p>
  <% } %>
  
  <script src="/js/main.js"></script>
</body>
</html>
```

## 📨 Gestión de Peticiones

### Parámetros URL

```javascript
app.get('/usuarios/:id', (req, res) => {
  const userId = req.params.id;
  res.send(`Usuario ID: ${userId}`);
});
```

### Parámetros de consulta (Query)

```javascript
app.get('/productos', (req, res) => {
  const { categoria, ordenar, pagina = 1 } = req.query;
  res.send(`Categoría: ${categoria}, Ordenar: ${ordenar}, Página: ${pagina}`);
});
```

### Cuerpo de la petición (Body)

```javascript
// Asegúrate de tener el middleware para parsear JSON
app.use(express.json());

app.post('/usuarios', (req, res) => {
  const { nombre, email } = req.body;
  res.send(`Usuario creado: ${nombre}, Email: ${email}`);
});
```

### Subida de archivos

```bash
npm install multer
```

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();

// Configurar almacenamiento
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// Ruta para subida de un solo archivo
app.post('/upload', upload.single('archivo'), (req, res) => {
  res.send(`Archivo subido: ${req.file.filename}`);
});

// Ruta para subida de múltiples archivos
app.post('/upload-multiple', upload.array('archivos', 5), (req, res) => {
  res.send(`${req.files.length} archivos subidos`);
});

app.listen(3000);
```

## 💾 Bases de Datos con MySQL

Express se integra fácilmente con MySQL a través de paquetes como `mysql2` o con ORM como Sequelize.

### Conexión directa con mysql2

```bash
npm install mysql2
```

```javascript
// config/database.js
const mysql = require('mysql2/promise');

// Crear pool de conexiones
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'tupassword',
  database: 'mibasededatos',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
```

```javascript
// models/usuario.js
const db = require('../config/database');

class Usuario {
  static async findAll() {
    try {
      const [rows] = await db.query('SELECT * FROM usuarios');
      return rows;
    } catch (error) {
      throw error;
    }
  }

  static async findById(id) {
    try {
      const [rows] = await db.query('SELECT * FROM usuarios WHERE id = ?', [id]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }

  static async create(usuario) {
    try {
      const { nombre, email, password } = usuario;
      const [result] = await db.query(
        'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)',
        [nombre, email, password]
      );
      return { id: result.insertId, nombre, email };
    } catch (error) {
      throw error;
    }
  }

  static async update(id, usuario) {
    try {
      const { nombre, email } = usuario;
      await db.query(
        'UPDATE usuarios SET nombre = ?, email = ? WHERE id = ?',
        [nombre, email, id]
      );
      return { id, ...usuario };
    } catch (error) {
      throw error;
    }
  }

  static async delete(id) {
    try {
      await db.query('DELETE FROM usuarios WHERE id = ?', [id]);
      return { id };
    } catch (error) {
      throw error;
    }
  }
}

module.exports = Usuario;
```

### Usando Sequelize (ORM)

```bash
npm install sequelize mysql2
```

```javascript
// config/database.js
const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('mibasededatos', 'root', 'tupassword', {
  host: 'localhost',
  dialect: 'mysql',
  logging: false // Desactivar logs SQL
});

// Probar la conexión
async function testConnection() {
  try {
    await sequelize.authenticate();
    console.log('Conexión a la base de datos establecida correctamente.');
  } catch (error) {
    console.error('No se pudo conectar a la base de datos:', error);
  }
}

testConnection();

module.exports = sequelize;
```

```javascript
// models/usuario.js
const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Usuario = sequelize.define('Usuario', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  nombre: {
    type: DataTypes.STRING,
    allowNull: false
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  activo: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  }
}, {
  // Opciones del modelo
  tableName: 'usuarios',
  timestamps: true // Añade createdAt y updatedAt
});

module.exports = Usuario;
```

```javascript
// app.js
const express = require('express');
const sequelize = require('./config/database');
const Usuario = require('./models/usuario');

const app = express();
app.use(express.json());

// Sincronizar modelos con la base de datos
sequelize.sync({ force: false }) // force: true borrará y recreará las tablas
  .then(() => console.log('Modelos sincronizados con la base de datos'))
  .catch(err => console.error('Error sincronizando modelos:', err));

// Rutas para usuarios usando Sequelize
app.get('/usuarios', async (req, res) => {
  try {
    const usuarios = await Usuario.findAll();
    res.json(usuarios);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/usuarios/:id', async (req, res) => {
  try {
    const usuario = await Usuario.findByPk(req.params.id);
    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(usuario);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/usuarios', async (req, res) => {
  try {
    const usuario = await Usuario.create(req.body);
    res.status(201).json(usuario);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/usuarios/:id', async (req, res) => {
  try {
    const usuario = await Usuario.findByPk(req.params.id);
    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    await usuario.update(req.body);
    res.json(usuario);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/usuarios/:id', async (req, res) => {
  try {
    const usuario = await Usuario.findByPk(req.params.id);
    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    await usuario.destroy();
    res.json({ message: 'Usuario eliminado' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});
```

## 🔐 Autenticación

Express puede implementar autenticación de varias maneras, pero aquí mostraremos JWT y Passport.js.

### Autenticación con JWT

```bash
npm install jsonwebtoken bcrypt
```

```javascript
// middleware/auth.js
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'tu_secreto_super_seguro'; // Usar variables de entorno en producción

function auth(req, res, next) {
  // Obtener token del header
  const token = req.header('x-auth-token');

  // Verificar si no hay token
  if (!token) {
    return res.status(401).json({ message: 'Acceso denegado. No hay token' });
  }

  try {
    // Verificar token
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token no válido' });
  }
}

module.exports = auth;
```

```javascript
// controllers/authController.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Usuario = require('../models/usuario');

const JWT_SECRET = 'tu_secreto_super_seguro'; // Usar variables de entorno en producción

// Registro de usuario
exports.registro = async (req, res) => {
  try {
    const { nombre, email, password } = req.body;

    // Verificar si el usuario ya existe
    let usuario = await Usuario.findOne({ where: { email } });
    if (usuario) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    // Encriptar contraseña
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Crear usuario
    usuario = await Usuario.create({
      nombre,
      email,
      password: passwordHash
    });

    // Crear JWT
    const payload = {
      id: usuario.id,
      nombre: usuario.nombre
    };

    jwt.sign(
      payload,
      JWT_SECRET,
      { expiresIn: '1h' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Error en el servidor');
  }
};

// Login de usuario
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verificar si el usuario existe
    const usuario = await Usuario.findOne({ where: { email } });
    if (!usuario) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }

    // Verificar contraseña
    const isMatch = await bcrypt.compare(password, usuario.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }

    // Crear JWT
    const payload = {
      id: usuario.id,
      nombre: usuario.nombre
    };

    jwt.sign(
      payload,
      JWT_SECRET,
      { expiresIn: '1h' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Error en el servidor');
  }
};

// Obtener información del usuario autenticado
exports.getUsuario = async (req, res) => {
  try {
    const usuario = await Usuario.findByPk(req.usuario.id, {
      attributes: { exclude: ['password'] }
    });
    res.json(usuario);
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Error en el servidor');
  }
};
```

```javascript
// routes/auth.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const auth = require('../middleware/auth');

// Rutas de autenticación
router.post('/registro', authController.registro);
router.post('/login', authController.login);
router.get('/usuario', auth, authController.getUsuario);

module.exports = router;
```

### Autenticación con Passport.js

```bash
npm install passport passport-local passport-jwt bcrypt
```

```javascript
// config/passport.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const Usuario = require('../models/usuario');

const JWT_SECRET = 'tu_secreto_super_seguro'; // Usar variables de entorno en producción

// Estrategia local para login (email y contraseña)
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      // Buscar usuario por email
      const usuario = await Usuario.findOne({ where: { email } });
      
      if (!usuario) {
        return done(null, false, { message: 'Credenciales inválidas' });
      }
      
      // Verificar contraseña
      const isMatch = await bcrypt.compare(password, usuario.password);
      
      if (!isMatch) {
        return done(null, false, { message: 'Credenciales inválidas' });
      }
      
      return done(null, usuario);
    } catch (error) {
      return done(error);
    }
  }
));

// Estrategia JWT
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET
};

passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
  try {
    const usuario = await Usuario.findByPk(jwt_payload.id);
    
    if (usuario) {
      return done(null, usuario);
    }
    
    return done(null, false);
  } catch (error) {
    return done(error, false);
  }
}));

module.exports = passport;
```

## ✅ Validación

Express puede usar validación a través de diferentes librerías como express-validator, joi, o yup.

### Usando express-validator

```bash
npm install express-validator
```

```javascript
// routes/usuarios.js
const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const Usuario = require('../models/usuario');

// Validaciones para crear usuario
const validarUsuario = [
  body('nombre').notEmpty().withMessage('El nombre es requerido'),
  body('email')
    .notEmpty().withMessage('El email es requerido')
    .isEmail().withMessage('Formato de email inválido')
    .custom(async value => {
      const existente = await Usuario.findOne({ where: { email: value } });
      if (existente) {
        throw new Error('El email ya está registrado');
      }
      return true;
    }),
  body('password')
    .isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
];

router.post('/', validarUsuario, async (req, res) => {
  // Verificar errores de validación
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Resto del código para crear usuario
    // ...
  } catch (error) {
    console.error(error);
    res.status(500).send('Error en el servidor');
  }
});

module.exports = router;
```

## 🚀 Despliegue

Hay varias formas de desplegar una aplicación Express:

### 1. Despliegue tradicional

1. Instalar PM2 para gestionar la aplicación:

```bash
npm install -g pm2
```

2. Crear un archivo `ecosystem.config.js`:

```javascript
module.exports = {
  apps: [{
    name: 'mi-app-express',
    script: 'app.js',
    instances: 'max',
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'development'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 80
    }
  }]
};
```

3. Iniciar con PM2:

```bash
pm2 start ecosystem.config.js --env production
```

### 2. Despliegue con Docker

1. Crear un `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000

CMD ["node", "app.js"]
```

2. Crear un archivo `docker-compose.yml` para incluir MySQL:

```yaml
version: '3'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DB_HOST=db
      - DB_USER=root
      - DB_PASSWORD=password
      - DB_NAME=mibasededatos
    depends_on:
      - db

  db:
    image: mysql:8.0
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=password
      - MYSQL_DATABASE=mibasededatos
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
```

3. Construir y ejecutar con Docker Compose:

```bash
docker-compose up -d
```

## 🏆 Mejores Prácticas

1. **Seguridad**:
   - Usar HTTPS
   - Implementar CORS correctamente
   - Proteger contra ataques comunes (XSS, CSRF, inyección SQL)
   - Ocultar información sensible en encabezados
   - Usar helmet para mejorar seguridad con encabezados HTTP

   ```javascript
   const helmet = require('helmet');
   app.use(helmet());
   ```

2. **Rendimiento**:
   - Comprimir respuestas
   - Implementar caché
   - Optimizar consultas a la base de datos
   - Usar un proceso de construcción
   
   ```javascript
   const compression = require('compression');
   app.use(compression());
   ```

3. **Escalabilidad**:
   - Usar múltiples instancias (PM2, Kubernetes)
   - Implementar balanceo de carga
   - Utilizar servicios en la nube (AWS, Azure, GCP)

4. **Estructura y organización**:
   - Seguir el patrón MVC o similar
   - Modularizar el código
   - Documentar rutas (con Swagger/OpenAPI)

5. **Desarrollo**:
   - Usar variables de entorno para configuración
   - Implementar tests (unitarios, integración, e2e)
   - Establecer CI/CD
   
   ```javascript
   // config/config.js
   require('dotenv').config();
   
   module.exports = {
     port: process.env.PORT || 3000,
     dbHost: process.env.DB_HOST || 'localhost',
     dbUser: process.env.DB_USER || 'root',
     dbPassword: process.env.DB_PASSWORD || '',
     dbName: process.env.DB_NAME || 'mibasededatos',
     nodeEnv: process.env.NODE_ENV || 'development',
     jwtSecret: process.env.JWT_SECRET || 'mi_secreto_temporal'
   };
   ```
