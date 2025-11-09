// Helper para obtener información de personas (actores/directores) desde TMDB
const axios = require('axios');

const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';
const IMAGE_BASE_URL = 'https://image.tmdb.org/t/p';

/**
 * Busca una persona en TMDB por nombre
 */
async function searchPersonByName(personName) {
    if (!TMDB_API_KEY) return null;

    try {
        const response = await axios.get(`${TMDB_BASE_URL}/search/person`, {
            params: {
                api_key: TMDB_API_KEY,
                query: personName,
                language: 'es-ES'
            }
        });

        if (response.data.results && response.data.results.length > 0) {
            return response.data.results[0]; // Retorna el primer resultado
        }
        return null;
    } catch (error) {
        console.error(`Error buscando persona ${personName}:`, error.message);
        return null;
    }
}

/**
 * Obtiene detalles completos de una persona desde TMDB
 */
async function getPersonDetails(tmdbId) {
    if (!TMDB_API_KEY || !tmdbId) return null;

    try {
        const response = await axios.get(`${TMDB_BASE_URL}/person/${tmdbId}`, {
            params: {
                api_key: TMDB_API_KEY,
                language: 'es-ES'
            }
        });

        return response.data;
    } catch (error) {
        console.error(`Error obteniendo detalles de persona ${tmdbId}:`, error.message);
        return null;
    }
}

/**
 * Enriquece los datos de una persona con información de TMDB
 */
async function enrichPersonData(personName) {
    if (!personName) return null;

    try {
        // Buscar la persona
        const searchResult = await searchPersonByName(personName);
        if (!searchResult) return null;

        // Obtener detalles completos
        const details = await getPersonDetails(searchResult.id);
        if (!details) return null;

        return {
            tmdb_id: details.id,
            name: details.name,
            biography: details.biography || '',
            birthday: details.birthday || null,
            deathday: details.deathday || null,
            place_of_birth: details.place_of_birth || '',
            profile_url: details.profile_path
                ? `${IMAGE_BASE_URL}/w500${details.profile_path}`
                : null,
            known_for_department: details.known_for_department || '',
            gender: details.gender, // 1: femenino, 2: masculino
            popularity: details.popularity || 0
        };
    } catch (error) {
        console.error(`Error enriqueciendo datos de persona ${personName}:`, error.message);
        return null;
    }
}

/**
 * Calcula la edad a partir de una fecha de nacimiento
 */
function calculateAge(birthday, deathday = null) {
    if (!birthday) return null;

    const birthDate = new Date(birthday);
    const endDate = deathday ? new Date(deathday) : new Date();

    let age = endDate.getFullYear() - birthDate.getFullYear();
    const monthDiff = endDate.getMonth() - birthDate.getMonth();

    if (monthDiff < 0 || (monthDiff === 0 && endDate.getDate() < birthDate.getDate())) {
        age--;
    }

    return age;
}

module.exports = {
    enrichPersonData,
    calculateAge
};