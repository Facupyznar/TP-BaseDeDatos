
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3500;

// ===== EJS + estáticos =====
app.set('view engine', 'ejs');
app.set('views', 'views');          // tus .ejs viven en /views
app.use(express.static('public'));  // poné tu CSS/imagenes en /public

// ===== Body parser + sesión =====
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'cambialo-por-algo-largo',
    resave: false,
    saveUninitialized: false
}));

// Exponer usuario a todas las vistas (para mostrar el botón de login / logout)
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// ===== PostgreSQL Pool =====
const db = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    // si preferís NO usar search_path, quitá esta línea y califica como movies.tabla en las queries
    options: `-c search_path=movies,public`
});

// ===== Helpers Auth =====
async function findUserByUsername(username) {
    const { rows } = await db.query(
        `SELECT user_id, user_username, user_name, user_email, password_hash
     FROM movies.users
     WHERE user_username = $1`,
        [username]
    );
    return rows[0] || null;
}

async function createUser({ username, name, email, password }) {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await db.query(
        `INSERT INTO movies.users (user_username, user_name, user_email, password_hash)
     VALUES ($1, $2, $3, $4)
     RETURNING user_id, user_username, user_name, user_email`,
        [username, name, email, hash]
    );
    return rows[0];
}

function requireAuth(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
}

// ===== Rutas base =====
app.get('/', (req, res) => {
    // res.locals.user ya está disponible en index.ejs para mostrar el botón
    res.render('index');
});

app.get('/buscar', async (req, res) => {
    const searchTerm = (req.query.q || '').trim();
    const sql = `
    SELECT movie_id, title, release_date
    FROM movie
    WHERE title ILIKE $1
    ORDER BY release_date DESC
    LIMIT 50`;
    try {
        const { rows: movies } = await db.query(sql, [`%${searchTerm}%`]);
        res.render('resultado', { movies });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error en la búsqueda.');
    }
});

app.get('/pelicula/:id', async (req, res) => {
    const movieId = Number(req.params.id);
    const sql = `
    SELECT
      m.*,
      p_cast.person_id   AS actor_id,
      p_cast.person_name AS actor_name,
      mc.character_name,
      mc."order"         AS cast_order,
      p_crew.person_id   AS crew_member_id,
      p_crew.person_name AS crew_member_name,
      mcr.job            AS job
    FROM movie m
    LEFT JOIN movie_cast mc  ON mc.movie_id = m.movie_id
    LEFT JOIN person p_cast  ON p_cast.person_id = mc.person_id
    LEFT JOIN movie_crew mcr ON mcr.movie_id = m.movie_id
    LEFT JOIN person p_crew  ON p_crew.person_id = mcr.person_id
    WHERE m.movie_id = $1
  `;
    try {
        const { rows } = await db.query(sql, [movieId]);
        if (!rows.length) return res.status(404).send('Película no encontrada.');

        const base = rows[0];
        const movie = {
            movie_id: base.movie_id,
            title: base.title,
            release_date: base.release_date,
            overview: base.overview,
            directors: [],
            writers: [],
            cast: [],
            crew: []
        };

        const seenDir = new Set(), seenWr = new Set(), seenCast = new Set(), seenCrew = new Set();

        for (const r of rows) {
            if (r.crew_member_id && r.job === 'Director' && !seenDir.has(r.crew_member_id)) {
                seenDir.add(r.crew_member_id);
                movie.directors.push({ crew_member_id: r.crew_member_id, crew_member_name: r.crew_member_name, job: r.job });
            }
            if (r.crew_member_id && (r.job === 'Writer' || r.job === 'Screenplay') && !seenWr.has(r.crew_member_id)) {
                seenWr.add(r.crew_member_id);
                movie.writers.push({ crew_member_id: r.crew_member_id, crew_member_name: r.crew_member_name, job: r.job });
            }
            if (r.actor_id && r.character_name && !seenCast.has(r.actor_id)) {
                seenCast.add(r.actor_id);
                movie.cast.push({ actor_id: r.actor_id, actor_name: r.actor_name, character_name: r.character_name, cast_order: r.cast_order });
            }
            if (r.crew_member_id && !['Director', 'Writer', 'Screenplay'].includes(r.job) && !seenCrew.has(r.crew_member_id)) {
                seenCrew.add(r.crew_member_id);
                movie.crew.push({ crew_member_id: r.crew_member_id, crew_member_name: r.crew_member_name, job: r.job });
            }
        }

        res.render('pelicula', { movie });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error al cargar los datos de la película.');
    }
});

app.get('/actor/:id', async (req, res) => {
    const actorId = Number(req.params.id);
    const sql = `
    SELECT DISTINCT
      p.person_name AS actor_name,
      m.movie_id, m.title, m.release_date, mc.character_name
    FROM movie m
    JOIN movie_cast mc ON m.movie_id = mc.movie_id
    JOIN person p      ON p.person_id = mc.person_id
    WHERE mc.person_id = $1
    ORDER BY m.release_date DESC NULLS LAST
  `;
    try {
        const { rows } = await db.query(sql, [actorId]);
        const actorName = rows.length ? rows[0].actor_name : '';
        res.render('actor', { actorName, movies: rows });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error al cargar las películas del actor.');
    }
});

app.get('/director/:id', async (req, res) => {
    const directorId = Number(req.params.id);
    const sql = `
    SELECT DISTINCT
      p.person_name AS director_name,
      m.movie_id, m.title, m.release_date
    FROM movie m
    JOIN movie_crew mcr ON m.movie_id = mcr.movie_id
    JOIN person p       ON p.person_id = mcr.person_id
    WHERE mcr.job = 'Director' AND mcr.person_id = $1
    ORDER BY m.release_date DESC NULLS LAST
  `;
    try {
        const { rows } = await db.query(sql, [directorId]);
        const directorName = rows.length ? rows[0].director_name : '';
        res.render('director', { directorName, movies: rows });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error al cargar las películas del director.');
    }
});

// ===== Auth =====
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await findUserByUsername(username);
        if (!user) return res.status(401).render('login', { error: 'Usuario o contraseña inválidos' });

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.status(401).render('login', { error: 'Usuario o contraseña inválidos' });

        req.session.user = {
            id: user.user_id,
            username: user.user_username,
            name: user.user_name,
            email: user.user_email
        };
        res.redirect('/');
    } catch (e) {
        console.error(e);
        res.status(500).render('login', { error: 'Error interno' });
    }
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;

        const exists = await findUserByUsername(username);
        if (exists) return res.status(400).render('register', { error: 'El usuario ya existe' });

        const user = await createUser({ username, name, email, password });
        req.session.user = {
            id: user.user_id,
            username: user.user_username,
            name: user.user_name,
            email: user.user_email
        };
        res.redirect('/');
    } catch (e) {
        const msg = /user_email|users_user_email_key/i.test(String(e))
            ? 'Ese email ya está registrado'
            : /user_username|users_user_username_key/i.test(String(e))
                ? 'Ese usuario ya existe'
                : 'Error creando el usuario';
        console.error(e);
        res.status(400).render('register', { error: msg });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// Ruta protegida de ejemplo (si usás user_profile.ejs)
app.get('/perfil', requireAuth, (req, res) => {
    res.render('user_profile', { user: req.session.user });
});

// ===== Start =====
app.listen(port, async () => {
    try {
        await db.query('SELECT 1');
        console.log(`Servidor en http://localhost:${port}`);
    } catch (e) {
        console.error('No se pudo conectar a PostgreSQL:', e);
    }
});
