const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = 4000;
const SECRET = 'secreto';  // Cambia esta clave por una más segura en producción

app.use(cors());
app.use(bodyParser.json());

// Configuración de la conexión a PostgreSQL
const pool = new Pool({
    user: 'postgres',       // Cambia esto según tu configuración
    host: 'localhost',
    database: 'logindb',
    password: 'admin',   // Cambia esto según tu configuración
    port: 5432,
});

// Crear la tabla de usuarios si no existe
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL
  );
`, (err, res) => {
    if (err) {
        console.error(err);
    } else {
        console.log('Tabla de usuarios creada o ya existe');
    }
});

// Registro de usuario
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    console.log('username: '+username);
    console.log('password: '+password);
    console.log('email: '+email);

    const hashedPassword = await bcrypt.hash(password, 10);

    pool.query(
        'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING *',
        [username, hashedPassword, email],
        (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error al registrar el usuario');
            }
            res.status(201).send('Usuario registrado con éxito');
        }
    );
});

// Login de usuario
app.post('/login', (req, res) => {
    const { username, password} = req.body;
    console.log('username: '+username);
    console.log('password: '+password);


    pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username],
        async (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error en el servidor');
            }
            if (result.rows.length === 0) {
                return res.status(404).send('Usuario no encontrado');
            }

            const user = result.rows[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).send('Contraseña incorrecta');
            }

            const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '1h' });
            res.json({ token });
        }
    );
});

// Rutas protegidas (requiere JWT)
app.get('/profile', verifyToken, (req, res) => {
    res.send('Bienvenido a tu perfil, autenticado con JWT');
});

// Middleware para verificar JWT
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).send('Token no proporcionado');
    }

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send('Token inválido');
        }
        req.userId = decoded.id;
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
