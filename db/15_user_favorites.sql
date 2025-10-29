DROP TABLE IF EXISTS movies.user_favorites;

CREATE TABLE movies.user_favorites (
       user_id INTEGER NOT NULL,
       movie_id INTEGER NOT NULL,
       added_at TIMESTAMP DEFAULT NOW(),
       PRIMARY KEY (user_id, movie_id)
);