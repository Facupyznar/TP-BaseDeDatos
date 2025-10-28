require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const { Pool } = require('pg');

// === Mongoose y modelo de MongoDB ===
const mongoose = require('mongoose');
const Activity = require('./models/user_activity');

const app = express();
const port = process.env.PORT || 3000;

// ======= EJS =======
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ✅ Servir el styles.css dentro de /views
app.get('/styles.css', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'styles.css'));
});

// ✅ Servir imágenes desde /views/imgs
app.use('/imgs', express.static(path.join(__dirname, 'views', 'imgs')));

app.locals.encodeURIComponent = encodeURIComponent;

// ======= Body & sesión =======
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'cambiar-esto-por-uno-largo',
    resave: false,
    saveUninitialized: false,
}));

// Hacer que "user" e "isAdmin" estén disponibles en todas las vistas
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.isAdmin = !!(req.session.user && req.session.user.is_admin === true);
    next();
});

// ======= PostgreSQL (usa tu DB y schema "movies") =======
const db = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_DATABASE || 'movies',
    password: process.env.DB_PASSWORD || 'postgres',
    port: Number(process.env.DB_PORT) || 5432,
});

db.query(`SET search_path TO movies, public`).catch(() => {/* si falla, prefijamos en queries */});

// === Conexion a MongoDB ===
const conectarMongoDB = async () => {
    try {
        const mongoUri = process.env.MONGODB_URI || null;
        if (!mongoUri) {
            console.warn('⚠️ Advertencia: No se definió MONGODB_URI. Omitiendo conexión a MongoDB.');
        }
        await mongoose.connect(mongoUri)
        console.log('¡Conectado exitosamente a MongoDB! ✅');
    } catch (error) {
        console.error('Error al conectar a MongoDB: ❌', error);
    }
};

conectarMongoDB();

// ======= Helpers =======
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).render('login', { error: 'Iniciá sesión para continuar' });
    next();
}

// --- Admin helpers ---
function isAdmin(req) {
    return !!(req.session.user && req.session.user.is_admin === true);
}

function requireAdmin(req, res, next) {
    if (!isAdmin(req)) return res.status(403).send('Solo administradores.');
    next();
}

function requireAdminOrFromApp(req, res, next) {
    if (isAdmin(req)) return next();
    const from = (req.query.from || '').toLowerCase();
    const allow = ['search', 'keyword', 'person', 'movie'].includes(from);
    if (allow) return next();
    return res.status(403).send('Acceso directo solo para admin. Usá el buscador para navegar.');
}

// =========================================================
//  Rutas básicas
// =========================================================
app.get('/', (req, res) => {
    res.render('index');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // movies.users: user_id, user_username, user_name, user_email, password_hash, is_admin
        const { rows } = await db.query(
            `SELECT user_id, user_username, user_name, user_email, password_hash, is_admin
         FROM movies.users
        WHERE user_username = $1`,
            [username]
        );
        const user = rows[0];
        if (!user) return res.status(401).render('login', { error: 'Usuario o contraseña inválidos' });

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.status(401).render('login', { error: 'Usuario o contraseña inválidos' });

        // Guardamos el flag en la sesión (no se puede transformar en admin desde el login)
        req.session.user = {
            id: user.user_id,
            username: user.user_username,
            name: user.user_name,
            email: user.user_email,
            is_admin: user.is_admin === true
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

        const exists = await db.query(
            `SELECT 1 FROM movies.users WHERE user_username=$1 OR user_email=$2 LIMIT 1`,
            [username, email]
        );
        if (exists.rows.length) {
            return res.status(400).render('register', { error: 'Usuario o email ya registrado' });
        }

        const hash = await bcrypt.hash(password, 12);
        const { rows } = await db.query(
            `INSERT INTO movies.users (user_username, user_name, user_email, password_hash)
       VALUES ($1,$2,$3,$4)
       RETURNING user_id, user_username, user_name, user_email`,
            [username, name, email, hash]
        );

        const u = rows[0];
        req.session.user = { id: u.user_id, username: u.user_username, name: u.user_name, email: u.user_email, is_admin: false };
        res.redirect('/');
    } catch (e) {
        console.error(e);
        res.status(500).render('register', { error: 'Error creando la cuenta' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// ---------- KEYWORDS: páginas dedicadas ----------
app.get('/keywords', (req, res) => {
    res.render('search_keyword', { user: req.session.user || null });
});

app.get('/keywords/search', async (req, res) => {
    try {
        const keyword = (req.query.k || '').trim();
        if (!keyword) {
            return res.render('resultados_keyword', {
                user: req.session.user || null,
                keyword,
                movies: [],
                total: 0,
                error: 'Ingresá una palabra clave.'
            });
        }

        const sql = `
      SELECT m.movie_id, m.title, m.release_date
      FROM movies.movie m
      JOIN movies.movie_keywords mk ON mk.movie_id = m.movie_id
      JOIN movies.keyword k        ON k.keyword_id = mk.keyword_id
      WHERE LOWER(k.keyword_name) LIKE LOWER('%' || $1 || '%')
      GROUP BY m.movie_id, m.title, m.release_date
      ORDER BY m.release_date DESC NULLS LAST, m.title ASC
      LIMIT 200;
    `;
        const { rows } = await db.query(sql, [keyword]);

        res.render('resultados_keyword', {
            user: req.session.user || null,
            keyword,
            movies: rows,
            total: rows.length,
            error: null
        });
    } catch (err) {
        console.error('Error buscando por keyword:', err);
        res.status(500).render('resultados_keyword', {
            user: req.session.user || null,
            keyword: req.query.k || '',
            movies: [],
            total: 0,
            error: 'Ocurrió un error buscando por keyword.'
        });
    }
});

// =========================================================
//  A) Búsqueda unificada  (/search → alias de /buscar)
// =========================================================
app.get('/search', (req, res, next) => {
    req.url = '/buscar' + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
    next();
});

app.get('/buscar', async (req, res) => {
    const q = (req.query.q || '').trim();
    const type = (req.query.type || 'todo').toLowerCase();
    const like = `%${q}%`;

    if (!q) return res.render('resultado', { q, movies: [], actors: [], directors: [] });

    // Si es keyword, redirigimos a su página dedicada
    if (type === 'keyword') {
        return res.redirect('/keywords/search?k=' + encodeURIComponent(q));
    }

    try {
        // Películas por título
        const movieQ = db.query(
            `SELECT movie_id, title, release_date
         FROM movies.movie
        WHERE title ILIKE $1
        ORDER BY release_date DESC NULLS LAST
        LIMIT 100`,
            [like]
        );

        // Actores por nombre (existen en movie_cast)
        const actorQ = db.query(
            `SELECT DISTINCT p.person_id, p.person_name
         FROM movies.person p
         JOIN movies.movie_cast mc ON mc.person_id = p.person_id
        WHERE p.person_name ILIKE $1
        ORDER BY p.person_name
        LIMIT 100`,
            [like]
        );

        // Directores por nombre (job = 'Director' en movie_crew)
        const directorQ = db.query(
            `SELECT DISTINCT p.person_id, p.person_name
         FROM movies.person p
         JOIN movies.movie_crew mcr ON mcr.person_id = p.person_id
        WHERE mcr.job = 'Director' AND p.person_name ILIKE $1
        ORDER BY p.person_name
        LIMIT 100`,
            [like]
        );

        if (type === 'movie') {
            const m = await movieQ;
            return res.render('resultado', { q, movies: m.rows, actors: [], directors: [] });
        }
        if (type === 'actor') {
            const a = await actorQ;
            return res.render('resultado', { q, movies: [], actors: a.rows, directors: [] });
        }
        if (type === 'director') {
            const d = await directorQ;
            return res.render('resultado', { q, movies: [], actors: [], directors: d.rows });
        }

        // Todo
        const [m, a, d] = await Promise.all([movieQ, actorQ, directorQ]);
        res.render('resultado', { q, movies: m.rows, actors: a.rows, directors: d.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error en la búsqueda.');
    }
});

// =========================================================
/*  B) Páginas de personas (restringidas: admin directo / usuarios via from=...) */
// =========================================================
app.get('/actor/:id', requireAdminOrFromApp, async (req, res) => {
    const id = Number(req.params.id);
    try {
        const { rows } = await db.query(
            `SELECT DISTINCT p.person_name AS actor_name,
              m.movie_id, m.title, m.release_date, mc.character_name
         FROM movies.movie m
         JOIN movies.movie_cast mc ON m.movie_id = mc.movie_id
         JOIN movies.person p      ON p.person_id = mc.person_id
        WHERE mc.person_id = $1
        ORDER BY m.release_date DESC NULLS LAST`,
            [id]
        );
        const actorName = rows.length ? rows[0].actor_name : '';
        res.render('actor', { actorName, movies: rows });
    } catch (e) {
        console.error(e);
        res.status(500).send('Error al cargar las películas del actor.');
    }
});

app.get('/director/:id', requireAdminOrFromApp, async (req, res) => {
    const id = Number(req.params.id);
    try {
        const { rows } = await db.query(
            `SELECT DISTINCT p.person_name AS director_name,
              m.movie_id, m.title, m.release_date
         FROM movies.movie m
         JOIN movies.movie_crew mcr ON m.movie_id = mcr.movie_id
         JOIN movies.person p       ON p.person_id = mcr.person_id
        WHERE mcr.job = 'Director' AND mcr.person_id = $1
        ORDER BY m.release_date DESC NULLS LAST`,
            [id]
        );
        const directorName = rows.length ? rows[0].director_name : '';
        res.render('director', { directorName, movies: rows });
    } catch (e) {
        console.error(e);
        res.status(500).send('Error al cargar las películas del director.');
    }
});

// =========================================================
/*  C) Detalle de película (restringido: admin directo / usuarios via from=...) */
// =========================================================
app.get('/pelicula/:id', requireAdminOrFromApp, async (req, res) => {
    const movieId = Number(req.params.id);
    try {
        // 1) Datos base de la película
        const base = await db.query(
            `SELECT movie_id, title, overview, release_date, runtime, vote_average, vote_count
         FROM movies.movie
        WHERE movie_id = $1`,
            [movieId]
        );
        if (!base.rows.length) return res.status(404).send('Película no encontrada.');
        const m = base.rows[0];

        const movie = {
            movie_id: m.movie_id,
            title: m.title,
            overview: m.overview,
            release_date: m.release_date,
            runtime: m.runtime,
            vote_average: m.vote_average,
            vote_count: m.vote_count,
            directors: [],
            writers: [],
            cast: [],
            crew: [],
            genres: [],
            languages: [],
            countries: [],
        };

        // 2) Paralelo: elenco, crew, géneros, idiomas, países
        const [castRs, crewRs, genresRs, langsRs, countriesRs, ratingsRs, commentsRs] = await Promise.all([
            db.query(
                `SELECT p.person_id AS actor_id, p.person_name AS actor_name,
                mc.character_name, mc.cast_order
           FROM movies.movie_cast mc
           JOIN movies.person p ON p.person_id = mc.person_id
          WHERE mc.movie_id = $1`,
                [movieId]
            ),
            db.query(
                `SELECT p.person_id AS crew_member_id, p.person_name AS crew_member_name,
                d.department_name, mcr.job
           FROM movies.movie_crew mcr
           LEFT JOIN movies.department d ON d.department_id = mcr.department_id
           JOIN movies.person p ON p.person_id = mcr.person_id
          WHERE mcr.movie_id = $1`,
                [movieId]
            ),
            db.query(
                `SELECT g.genre_name
           FROM movies.movie_genres mg
           JOIN movies.genre g ON g.genre_id = mg.genre_id
          WHERE mg.movie_id = $1
          ORDER BY g.genre_name`,
                [movieId]
            ),
            db.query(
                `SELECT l.language_name
           FROM movies.movie_languages ml
           JOIN movies.language l ON l.language_id = ml.language_id
          WHERE ml.movie_id = $1
          ORDER BY l.language_name`,
                [movieId]
            ),
            db.query(
                `SELECT c.country_name
           FROM movies.production_country pc
           JOIN movies.country c ON c.country_id = pc.country_id
          WHERE pc.movie_id = $1
          ORDER BY c.country_name`,
                [movieId]
            ),
            db.query(
                `SELECT AVG(rating)::numeric(10,2) AS average_rating, COUNT(*) AS ratings_count
           FROM movies.movie_user
          WHERE movie_id = $1`,
                [movieId]
            ),
            db.query(
                `SELECT mu.user_id, u.user_name, mu.rating, mu.opinion, mu.created_at
           FROM movies.movie_user mu
           JOIN movies.users u ON u.user_id = mu.user_id
          WHERE mu.movie_id = $1
          ORDER BY mu.created_at DESC`,
                [movieId]
            ),
        ]);

        movie.cast = castRs.rows;
        // Clasificar crew en directores/escritores/otros
        crewRs.rows.forEach(r => {
            if (r.job === 'Director') movie.directors.push(r);
            else if (r.job === 'Writer' || r.job === 'Screenplay') movie.writers.push(r);
            else movie.crew.push(r);
        });
        movie.genres    = genresRs.rows.map(r => r.genre_name);
        movie.languages = langsRs.rows.map(r => r.language_name);
        movie.countries = countriesRs.rows.map(r => r.country_name);

        const avg = ratingsRs.rows[0] || {};
        const comments = commentsRs.rows || [];

        // Verificar si está en favoritos (si hay usuario logueado)
        let isFavorite = false;
        if (req.session && req.session.user && req.session.user.id) {
          const favCheck = await db.query(
            'SELECT 1 FROM movies.user_favorites WHERE user_id = $1 AND movie_id = $2',
            [req.session.user.id, movieId]
          );
          isFavorite = favCheck.rows.length > 0;
        }

        // Agregar is_favorite al objeto movie
        movie.is_favorite = isFavorite;

        res.render('pelicula', {
          movie: movie,
          user: req.session.user || null,
          average_rating: avg.average_rating,
          ratings_count: avg.ratings_count,
          comments: comments
        });
    } catch (e) {
        console.error(e);
        res.status(500).send('Error al cargar los datos de la película.');
    }
});

// =========================================================
//  E) Guardar rating y opinión (tabla movies.movie_user)
// =========================================================
app.post('/users/:userId/movies/:movieId/review', requireAuth, async (req, res) => {
    const userId = Number(req.params.userId);
    const movieId = Number(req.params.movieId);
    const rating = parseInt(req.body.rating, 10);
    const opinion = (req.body.opinion || '').trim();

    if (!userId || req.session.user?.id !== userId) {
        return res.status(403).send('No autorizado.');
    }

    // Validación: se requiere rating 1..5 y opinion no vacía
    if (!Number.isFinite(rating) || rating < 1 || rating > 5 || opinion.length === 0) {
        return res.status(400).send('Debés ingresar una puntuación (1..5) y una opinión.');
    }

    try {
        // === 1️⃣ Guardar calificación/opinión en PostgreSQL ===
        await db.query(
            `INSERT INTO movies.movie_user (user_id, movie_id, rating, opinion)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (user_id, movie_id)
             DO UPDATE SET rating = EXCLUDED.rating,
                           opinion = EXCLUDED.opinion,
                           created_at = now()`,
            [userId, movieId, rating, opinion]
        );

        // === 2️⃣ Registrar actividad en MongoDB (timeline del usuario) ===
        try {
            // Obtener el título de la película desde PostgreSQL
            const movieTitleResult = await db.query(
                `SELECT title FROM movies.movie WHERE movie_id = $1`,
                [movieId]
            );
            const movieTitle = movieTitleResult.rows[0]?.title || 'Película desconocida';

            // --- Evento de calificación ---
            await Activity.create({
                userId,
                type: 'RATED_MOVIE',
                details: {
                    movieId,
                    movieTitle,
                    rating
                }
            });

            // --- Evento de reseña ---
            await Activity.create({
                userId,
                type: 'WROTE_REVIEW',
                details: {
                    movieId,
                    movieTitle,
                    reviewText: opinion
                }
            });

        } catch (mongoErr) {
            console.warn('⚠️ No se pudo registrar la actividad en MongoDB:', mongoErr.message);
        }

        // Redirigir al detalle de película
        res.redirect(`/pelicula/${movieId}?from=movie`);

    } catch (e) {
        console.error('Error guardando review:', e);
        res.status(500).send('Error guardando calificación/opinión');
    }
});


// ========== EDITAR (GET): ver y editar rating+opinión del usuario para una película ==========
app.get('/users/:userId/movies/:movieId/edit', requireAuth, async (req, res) => {
    const userId = Number(req.params.userId);
    const movieId = Number(req.params.movieId);

    if (!userId || req.session.user?.id !== userId) {
        return res.status(403).send('No autorizado.');
    }

    try {
        // Datos de la película
        const mRs = await db.query(
            `SELECT movie_id, title
         FROM movies.movie
        WHERE movie_id = $1`,
            [movieId]
        );
        if (!mRs.rows.length) return res.status(404).send('Película no encontrada.');

        // Rating/opinión existentes (si hay)
        const muRs = await db.query(
            `SELECT rating, opinion
         FROM movies.movie_user
        WHERE user_id = $1 AND movie_id = $2`,
            [userId, movieId]
        );

        const movie = {
            movie_id: mRs.rows[0].movie_id,
            title: mRs.rows[0].title,
            rating: muRs.rows[0]?.rating || null,
            opinion: muRs.rows[0]?.opinion || ''
        };

        res.render('edit_movie_users', { user: { user_id: userId }, movie });
    } catch (e) {
        console.error('Error cargando edición de review:', e);
        res.status(500).send('Error interno.');
    }
});

// ===== Perfil de usuario  =====

// Usuario por ID
async function getPgUser(db, userId) {
    const { rows } = await db.query(
        `SELECT user_id, user_username, user_name, user_email
       FROM movies.users
      WHERE user_id = $1`,
        [userId]
    );
    return rows[0] || null;
}

// Calificaciones/opiniones del usuario (con títulos de película)
async function getPgUserReviews(db, userId) {
    const { rows } = await db.query(
        `SELECT mu.movie_id, m.title, mu.rating, mu.opinion, mu.created_at
       FROM movies.movie_user mu
       JOIN movies.movie m ON m.movie_id = mu.movie_id
      WHERE mu.user_id = $1
      ORDER BY mu.created_at DESC`,
        [userId]
    );
    return rows;
}

app.get('/profile/:userId', async (req, res) => {
    const userId = Number(req.params.userId);
    if (!Number.isFinite(userId)) return res.status(400).send('ID inválido');

    try {
        const user = await getPgUser(db, userId);
        if (!user) return res.status(404).send('Usuario no encontrado');

        const reviews = await getPgUserReviews(db, userId);

        // Actividades desde MongoDB
        let activities = [];
        const isAdminFlag = isAdmin(req);

        if (isAdminFlag) {
        activities = await Activity.find({ userId })
            .sort({ timestamp: -1 })
            .limit(30)
            .lean();
        }

        // Agregar consulta de favoritos (CAMBIADO: pool → db)
        const favoritesResult = await db.query(`
          SELECT m.movie_id, m.title, m.release_date
          FROM movies.user_favorites uf
          JOIN movies.movie m ON uf.movie_id = m.movie_id
          WHERE uf.user_id = $1
          ORDER BY uf.added_at DESC
          LIMIT 10
        `, [userId]);

        res.render('user_profile', {
          user,
          reviews,
          favorites: favoritesResult.rows,
          activities,
          isAdmin: isAdminFlag
        });
    } catch (e) {
        console.error('Error cargando perfil:', e);
        res.status(500).send('Error interno al cargar el perfil.');
    }
});

app.get('/users/:userId/profile', (req, res) => {
    res.redirect(`/profile/${encodeURIComponent(req.params.userId)}`);
});

// ===== Usuarios (solo admin) =====
app.get('/users', requireAdmin, async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT user_id, user_username, user_name, user_email, is_admin
         FROM movies.users
        ORDER BY user_name`
        );
        res.render('users', { users: rows, successMessage: null });
    } catch (e) {
        console.error('Error listando usuarios:', e);
        res.status(500).send('Error listando usuarios.');
    }
});

app.post('/users/:userId/delete', requireAdmin, async (req, res) => {
    const userId = Number(req.params.userId);
    if (!Number.isFinite(userId)) return res.status(400).send('ID inválido');

    try {
        // Si tu FK no tiene ON DELETE CASCADE, primero borra relaciones
        await db.query(`DELETE FROM movies.movie_user WHERE user_id = $1`, [userId]);

        // Ahora el usuario
        await db.query(`DELETE FROM movies.users WHERE user_id = $1`, [userId]);

        // Volver al listado
        res.redirect('/users');
    } catch (e) {
        console.error('Error borrando usuario:', e);
        res.status(500).send('Error borrando usuario.');
    }
});

// =========================================================
//  Start
// =========================================================
app.listen(port, async () => {
    try {
        await db.query('SELECT 1');
        console.log(`Servidor en http://localhost:${port}`);
        console.log('PostgreSQL OK. Si no carga el CSS, verificá que /views/styles.css exista (ruta /styles.css).');
    } catch (e) {
        console.error('No se pudo conectar a PostgreSQL:', e);
    }
});

// Ruta para agregar/quitar de favoritos (toggle automático)
app.post('/users/:userId/movies/:movieId/favorite', requireAuth, async (req, res) => {
  try {
    const { userId, movieId } = req.params;

    // Verificar que el usuario sea el correcto
    if (req.session.user.id !== Number(userId)) {
      return res.status(403).json({ success: false, error: 'No autorizado' });
    }

    // Verificar si ya está en favoritos (CAMBIADO: pool → db)
    const check = await db.query(
      'SELECT 1 FROM movies.user_favorites WHERE user_id = $1 AND movie_id = $2',
      [userId, movieId]
    );

    let action;
    if (check.rows.length > 0) {
      // Ya está en favoritos → quitar
      await db.query(
        'DELETE FROM movies.user_favorites WHERE user_id = $1 AND movie_id = $2',
        [userId, movieId]
      );
      action = 'REMOVED';
    } else {
      // No está en favoritos → agregar
      await db.query(
        'INSERT INTO movies.user_favorites (user_id, movie_id, added_at) VALUES ($1, $2, NOW())',
        [userId, movieId]
      );
      action = 'ADDED';

      // Registrar en timeline (MongoDB) solo cuando se agrega
      if (mongoose.connection.readyState === 1) {
        const movieResult = await db.query('SELECT title FROM movies.movie WHERE movie_id = $1', [movieId]);
        await Activity.create({
          userId: parseInt(userId),
          type: 'ADDED_TO_FAVORITES',
          details: {
            movieId: parseInt(movieId),
            movieTitle: movieResult.rows[0]?.title || 'Película desconocida'
          },
          timestamp: new Date()
        });
      }
    }

    res.json({ success: true, action });
  } catch (err) {
    console.error('Error al gestionar favoritos:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// En la sección donde defines el schema de Activity:

const activitySchema = new mongoose.Schema({
  userId: { type: Number, required: true },
  type: { 
    type: String, 
    required: true,
    enum: ['RATED_MOVIE', 'WROTE_REVIEW', 'ADDED_TO_FAVORITES'] // Agregar este tipo
  },
  details: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});
