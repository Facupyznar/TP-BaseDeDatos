DROP TABLE IF EXISTS movies.movie_user;

CREATE TABLE movies.movie_user (
    user_id     INT NOT NULL REFERENCES movies.users(user_id)  ON DELETE CASCADE,
    movie_id    INT NOT NULL REFERENCES movies.movie(movie_id) ON DELETE CASCADE,
    rating      INT CHECK (rating BETWEEN 1 AND 5),
    opinion     VARCHAR(1000),
    created_at  TIMESTAMP DEFAULT now(),
    PRIMARY KEY (user_id, movie_id)
);

