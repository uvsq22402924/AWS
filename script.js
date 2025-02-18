// Fonction pour afficher les films sur la page
function displayMovies(movies) {
    const movieContainer = document.getElementById('movie-container');
    movieContainer.innerHTML = ''; // Réinitialiser le contenu de la section des films

    movies.forEach(movie => {
        const movieElement = document.createElement('div');
        movieElement.classList.add('movie');

        // Créer l'élément HTML pour chaque film
        const movieHTML = `
            <img src="https://image.tmdb.org/t/p/w500${movie.poster_path}" alt="${movie.title}" />
            <h3>${movie.title}</h3>
            <p>${movie.overview}</p>
            <p><strong>Release Date:</strong> ${movie.release_date}</p>
            <p><strong>Rating:</strong> ${movie.vote_average} (${movie.vote_count} votes)</p>
        `;

        movieElement.innerHTML = movieHTML;
        movieContainer.appendChild(movieElement);
    });
}

// Récupérer les films depuis l'API
async function fetchMovies() {
    try {
        const response = await fetch('https://api.themoviedb.org/3/movie/popular?api_key=4a7fa7389e9a4ceeef5a953ff90232df'); // Remplacer par l'URL de l'API
        const data = await response.json();
        displayMovies(data.results); // Passer les résultats à la fonction pour affichage
    } catch (error) {
        console.error('Erreur de récupération des films:', error);
    }
}

// Appeler la fonction pour récupérer et afficher les films au chargement de la page
document.addEventListener('DOMContentLoaded', fetchMovies);

class Movie {
    constructor(title, rating, imageUrl, summary) {
      this.title = title;
      this.rating = rating;
      this.imageUrl = imageUrl;
      this.summary = summary;
    }
  }
  
  class MovieView {
    static render(movie) {
      return `
        <div class="movie">
          <img src="${movie.imageUrl}" alt="${movie.title}">
          <div class="movie-details">
            <h2>${movie.title}</h2>
            <p><strong>Note:</strong> ${movie.rating}</p>
            <p><strong>Résumé:</strong> ${movie.summary}</p>
          </div>
        </div>
      `;
    }
  }