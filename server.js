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
    console.log('REGISTER')
    const { username, password, email } = req.body;
    console.log('Datos recibidos - username:', username, ', email:', email);

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Contraseña encriptada:', hashedPassword);

        pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING *',
            [username, hashedPassword, email],
            (err, result) => {
                if (err) {
                    console.error('Error al insertar el usuario en la BD:', err);
                    return res.status(500).send('Error al registrar el usuario');
                }
                console.log('Usuario registrado con éxito:', result.rows[0]);
                console.log('Si')
                res.status(200).send('Usuario registrado con éxito');
            }
        );
    } catch (err) {
        console.error('Error en el proceso de registro:', err);
        res.status(500).send('Error interno en el servidor');
    }
});

// Login de usuario
app.post('/login', (req, res) => {
    console.log('Aqui llego')
    const { username, password } = req.body;
    console.log('Intento de login - username:', username);

    pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username],
        async (err, result) => {
            if (err) {
                console.error('Error al buscar el usuario en la BD:', err);
                return res.status(500).send('Error en el servidor');
            }
            if (result.rows.length === 0) {
                console.log('Usuario no encontrado:', username);
                return res.status(404).send('Usuario no encontrado');
            }

            const user = result.rows[0];
            console.log('Usuario encontrado:', user);

            try {
                const isMatch = await bcrypt.compare(password, user.password);
                if (!isMatch) {
                    console.log('Contraseña incorrecta para el usuario:', username);
                    return res.status(400).send('Contraseña incorrecta');
                }

                const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '1h' });
                console.log('Token generado para el usuario:', username);
                res.json({ token });
            } catch (err) {
                console.error('Error al comparar contraseñas:', err);
                res.status(500).send('Error interno en el servidor');
            }
        }
    );
});

// Rutas protegidas (requiere JWT)
app.get('/profile', verifyToken, (req, res) => {
    console.log('Accediendo al perfil del usuario con ID:', req.userId);
    res.send('Bienvenido a tu perfil, autenticado con JWT');
});

// Middleware para verificar JWT
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        console.log('Token no proporcionado');
        return res.status(403).send('Token no proporcionado');
    }

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) {
            console.log('Token inválido:', err);
            return res.status(401).send('Token inválido');
        }
        req.userId = decoded.id;
        console.log('Token verificado, usuario ID:', req.userId);
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
