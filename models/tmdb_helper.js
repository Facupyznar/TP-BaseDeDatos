const axios = require('axios');

const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = process.env.TMDB_BASE_URL || 'https://api.themoviedb.org/3';
const TMDB_IMAGE_BASE_URL = process.env.TMDB_IMAGE_BASE_URL || 'https://image.tmdb.org/t/p';
const TMDB_LANGUAGE = process.env.TMDB_LANGUAGE || 'en-US';

/**
 * Buscar película en TMDb por título y año (opcional)
 * @param {string} title - Título de la película
 * @param {number|string} year - Año de lanzamiento (opcional)
 * @returns {Promise<Object|null>} Datos de la película o null
 */
async function searchMovie(title, year = null) {
    if (!TMDB_API_KEY || TMDB_API_KEY === 'TU_API_KEY_AQUI') {
        console.warn('⚠️ TMDb API key no configurada. Las imágenes no estarán disponibles.');
        return null;
    }

    try {
        const params = {
            api_key: TMDB_API_KEY,
            query: title,
            language: TMDB_LANGUAGE
        };

        if (year) {
            params.year = year;
        }

        const response = await axios.get(`${TMDB_BASE_URL}/search/movie`, { params });

        if (response.data.results && response.data.results.length > 0) {
            return response.data.results[0]; // Retorna el primer resultado
        }

        return null;
    } catch (error) {
        console.error(`Error buscando película "${title}" en TMDb:`, error.message);
        return null;
    }
}

/**
 * Obtener URL completa de la imagen del poster
 * @param {string} posterPath - Path del poster (ej: /abc123.jpg)
 * @param {string} size - Tamaño (w92, w154, w185, w342, w500, w780, original)
 * @returns {string} URL completa de la imagen
 */
function getPosterUrl(posterPath, size = 'w342') {
    if (!posterPath) {
        return null;
    }
    return `${TMDB_IMAGE_BASE_URL}/${size}${posterPath}`;
}

/**
 * Obtener URL completa de la imagen del backdrop
 * @param {string} backdropPath - Path del backdrop
 * @param {string} size - Tamaño (w300, w780, w1280, original)
 * @returns {string} URL completa de la imagen
 */
function getBackdropUrl(backdropPath, size = 'w780') {
    if (!backdropPath) {
        return null;
    }
    return `${TMDB_IMAGE_BASE_URL}/${size}${backdropPath}`;
}

/**
 * Buscar y obtener poster de una película por título
 * @param {string} title - Título de la película
 * @param {number|string} year - Año de lanzamiento (opcional)
 * @param {string} size - Tamaño del poster
 * @returns {Promise<string|null>} URL del poster o null
 */
async function getMoviePoster(title, year = null, size = 'w342') {
    const movie = await searchMovie(title, year);
    if (movie && movie.poster_path) {
        return getPosterUrl(movie.poster_path, size);
    }
    return null;
}

/**
 * Enriquecer lista de películas con datos de TMDb (incluye posters)
 * @param {Array} movies - Array de películas con al menos {title, release_date}
 * @returns {Promise<Array>} Array de películas enriquecidas
 */
async function enrichMoviesWithPosters(movies) {
    if (!TMDB_API_KEY || TMDB_API_KEY === 'TU_API_KEY_AQUI') {
        // Si no hay API key, retornar movies sin cambios
        return movies.map(movie => ({
            ...movie,
            poster_url: null,
            tmdb_id: null
        }));
    }

    const enrichedMovies = await Promise.all(
        movies.map(async (movie) => {
            try {
                const year = movie.release_date ? new Date(movie.release_date).getFullYear() : null;
                const tmdbData = await searchMovie(movie.title, year);

                return {
                    ...movie,
                    poster_url: tmdbData?.poster_path ? getPosterUrl(tmdbData.poster_path) : null,
                    backdrop_url: tmdbData?.backdrop_path ? getBackdropUrl(tmdbData.backdrop_path) : null,
                    tmdb_id: tmdbData?.id || null,
                    tmdb_vote_average: tmdbData?.vote_average || null
                };
            } catch (error) {
                console.error(`Error enriqueciendo película "${movie.title}":`, error.message);
                return {
                    ...movie,
                    poster_url: null,
                    backdrop_url: null,
                    tmdb_id: null
                };
            }
        })
    );

    return enrichedMovies;
}

module.exports = {
    searchMovie,
    getPosterUrl,
    getBackdropUrl,
    getMoviePoster,
    enrichMoviesWithPosters
};

