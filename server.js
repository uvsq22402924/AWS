const express = require('express');
const app = express();
const path = require('path');

// Middleware pour servir les fichiers statiques (CSS, images, JS)
app.use(express.static('public'));

// Route pour servir login.html
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Lancer le serveur
app.listen(3007, () => {
    console.log('Serveur en cours d\'exécution sur http://localhost:3007');
});

app.get('/acceuil', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'acceuil.html'));
});



