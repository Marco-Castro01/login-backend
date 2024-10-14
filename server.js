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
        console.error('Error al crear la tabla de usuarios:', err);
    } else {
        console.log('Tabla de usuarios creada o ya existe');
    }
});

// Registro de usuario
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;

    // Verificar si faltan campos
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING *',
            [username, hashedPassword, email]
        );
        return res.status(200).json({ message: 'Usuario registrado con éxito', user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') {  // Error de duplicidad (username/email)
            return res.status(400).json({ error: 'El nombre de usuario o correo ya está en uso' });
        }
        console.error('Error al registrar el usuario:', err);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Login de usuario
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Verificar si faltan campos
    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '1h' });
        return res.json({ token });
    } catch (err) {
        console.error('Error al hacer login:', err);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Rutas protegidas (requiere JWT)
app.get('/profile', verifyToken, (req, res) => {
    return res.json({ message: 'Bienvenido a tu perfil', userId: req.userId });
});

// Middleware para verificar JWT
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ error: 'Token no proporcionado' });
    }

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Token inválido' });
        }
        req.userId = decoded.id;
        next();
    });
}

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
