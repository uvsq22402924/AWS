import express from "express";
import path from 'path';
import session from "express-session";
import passport from "passport";
import { PrismaClient } from "@prisma/client";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dotenv from "dotenv";
import MongoStore from "connect-mongo";
import mongoose from "mongoose";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';




const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


dotenv.config();


const app = express();
const prisma = new PrismaClient();


// 📌 Connexion à MongoDB
mongoose.connect(process.env.DATABASE_URL).then(() => {
    console.log("✅ Connecté à MongoDB");
}).catch((err) => {
    console.error("❌ Erreur de connexion à MongoDB :", err);
});


// 📌 Utiliser cookie-parser
app.use(cookieParser());


// 📌 Configuration des sessions et de Passport
app.use(session({
    secret: process.env.SESSION_SECRET || "monsecret",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.DATABASE_URL,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60 // 14 jours
    }),
    cookie: { secure: false, maxAge: 14 * 24 * 60 * 60 * 1000 } // 14 jours
}));


app.use(passport.initialize());
app.use(passport.session());


// 📌 Middleware pour vérifier les cookies de session
app.use((req, res, next) => {
    console.log("Cookies de session :", req.cookies);
    next();
});


// 📌 Middleware pour associer la session à l'utilisateur
app.use(async (req, res, next) => {
    if (req.user) {
        const sessionExists = await mongoose.connection.db.collection('sessions').findOne({ "session.userId": req.user.id });


        if (!sessionExists) {
            req.session.userId = req.user.id; // 🔹 Associe la session à l'utilisateur
        }
    }
    next();
});


// 📌 Middleware
app.use(express.json());
app.use(express.static("public"));


// 📌 Middleware pour rediriger les utilisateurs authentifiés
const redirectIfAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect("/accueil_after_login.html");
    }
    next();
};


// 📌 Configuration de Google OAuth avec Passport.js
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    console.log("✅ Google OAuth Callback reçu :", profile);


    try {
        let user = await prisma.user.findUnique({
            where: { googleId: profile.id }
        });


        if (!user) {
            console.log("🆕 Nouvel utilisateur détecté, enregistrement...");
            user = await prisma.user.create({
                data: {
                    googleId: profile.id,
                    name: profile.displayName,
                    email: profile.emails[0].value,
                }
            });
        } else {
            console.log("🔄 Utilisateur déjà existant :", user.email);
        }


        return done(null, user);
    } catch (error) {
        console.error("❌ Erreur lors de l'authentification Google :", error);
        return done(error, null);
    }
}));


passport.serializeUser((user, done) => { //stocker un petit identifian
    console.log("🔄 Sérialisation de l'utilisateur :", user.id);
    done(null, user.id);
});


passport.deserializeUser(async (id, done) => { //Lors de chaque requête, cette méthode récupère l'utilisateur
//  à partir de l'identifiant stocké dans la session.
    console.log("🛠 Désérialisation de l'utilisateur :", id);
    try {
        const user = await prisma.user.findUnique({ where: { id } });
        done(null, user);
    } catch (error) {
        console.error("❌ Erreur lors de la désérialisation :", error);
        done(error, null);
    }
});


// 📌 Routes de gestion des pages HTML
app.get("/login", redirectIfAuthenticated, (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/accueil", (req, res) => res.sendFile(path.join(__dirname, "public", "accueil.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));


// 📌 Routes d'inscription et de connexion
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;


    // 📌 Vérification du mot de passe sécurisé
    const passwordError = validatePassword(password);
    if (passwordError) {
        return res.status(400).json({ message: passwordError });
    }


    // 📌 Vérifier si l'utilisateur existe déjà
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
        return res.status(400).json({ message: "Cet utilisateur existe déjà." });
    }


    // 📌 Hachage du mot de passe sécurisé
    const hashedPassword = await bcrypt.hash(password, 10);


    //  Création de l'utilisateur en base de données
    await prisma.user.create({
        data: { name, email, hashedPassword },
    });


    res.status(201).json({ message: "Inscription réussie avec mot de passe sécurisé !" });
});


app.post("/login", async (req, res) => { //req.login(user)
    const { email, password } = req.body;


    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
        return res.status(400).json({ message: "Email ou mot de passe incorrect." });
    }


    const isMatch = await bcrypt.compare(password, user.hashedPassword);
    if (!isMatch) {
        return res.status(400).json({ message: "Email ou mot de passe incorrect." });
    }


    // Vérifiez si l'utilisateur a déjà une session existante
    const existingSession = await mongoose.connection.collection('sessions').findOne({ "session.passport.user": user.id });
    if (existingSession) {
        req.sessionID = existingSession._id;
        req.sessionStore.get(req.sessionID, (err, session) => {
            if (err) {
                return res.status(500).json({ message: "Erreur lors de la récupération de la session." });
            }
            req.session = session;
            req.login(user, (err) => {
                if (err) {
                    return res.status(500).json({ message: "Erreur lors de la connexion." });
                }
                console.log("Session existante réutilisée pour l'utilisateur :", user.email);
                res.json({ message: "Connexion réussie !" });
            });
        });
    } else {
        req.login(user, (err) => {
            if (err) {
                return res.status(500).json({ message: "Erreur lors de la connexion." });
            }




            req.session.message = `Bienvenue ${user.name} !`; // 🔹 Ajoute un message en session






            console.log("Nouvelle session créée pour l'utilisateur :", user.email);
            res.json({ message: "Connexion réussie !" });
        });
    }
});


app.get("/profile", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Non authentifié" });
    }
    res.json(req.user);
});


app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Erreur lors de la déconnexion :", err);
            return res.status(500).json({ message: "Erreur de déconnexion" });
        }
        req.session.destroy((err) => {
            if (err) {
                console.error(" Erreur lors de la destruction de la session :", err);
                return res.status(500).json({ message: "Erreur de destruction de la session" });
            }
            res.redirect("/login");
        });
    });
});


//  Middleware pour vérifier si l'utilisateur est authentifié
const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
};


//  Route protégée (Exemple: Liste des films)
app.get("/movies", ensureAuthenticated, async (req, res) => {
    const movies = await prisma.movie.findMany();
    res.json(movies);
});


//  Routes d'authentification Google
app.get("/auth/google", (req, res, next) => {
    console.log("🔍 Redirection vers Google pour l'authentification...");
    passport.authenticate("google", { scope: ["profile", "email"], prompt: "select_account" })(req, res, next);
});


app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        console.log(" Authentification réussie pour :", req.user.email);
        res.redirect("/accueil_after_login.html");
    }
);


//  Route pour obtenir les informations de l'utilisateur actuel
app.get("/api/current", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Non authentifié" });
    }
    res.json(req.user);
});


// Démarrer le serveur
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Serveur en écoute sur http://localhost:${PORT}`));








app.get("/session-info", (req, res) => {
    if (req.session.message) {
        res.json({ message: req.session.message });
    } else {
        res.json({ message: "Aucun message trouvé en session." });
    }
});




function validatePassword(password) {
    if (password.length < 8) {
        return "Le mot de passe doit contenir au moins 8 caractères.";
    }
    if (!/[A-Z]/.test(password)) {
        return "Le mot de passe doit contenir au moins une lettre majuscule.";
    }
    if (!/[a-z]/.test(password)) {
        return "Le mot de passe doit contenir au moins une lettre minuscule.";
    }
    if (!/[0-9]/.test(password)) {
        return "Le mot de passe doit contenir au moins un chiffre.";
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        return "Le mot de passe doit contenir au moins un caractère spécial.";
    }
    return null; // Aucune erreur




}
import { ObjectId } from 'mongodb';
import axios from 'axios';
app.post("/watchlist", ensureAuthenticated, async (req, res) => {
    let { movieId } = req.body;
    const userId = req.user.id;


    console.log("Ajout à la watchlist - userId:", userId, "movieId:", movieId);


    // Vérifier que movieId est valide (s'il s'agit d'une chaîne numérique)
    if (!movieId || isNaN(movieId)) {
        return res.status(400).json({ message: "Invalid movieId" });
    }


    // Vérifier que userId est valide (si tu utilises MongoDB, tu peux vérifier ObjectId ici)
    if (!ObjectId.isValid(userId)) {
        return res.status(400).json({ message: "Invalid userId" });
    }


    try {
        // Récupérer les détails du film depuis TMDb
        const tmdbResponse = await axios.get(`https://api.themoviedb.org/3/movie/${movieId}`, {
            params: {
                api_key: process.env.TMDB_API_KEY, // Ta clé API TMDb
            },
        });


        const tmdbMovie = tmdbResponse.data;


        // Vérifier si le film existe sur TMDb
        if (!tmdbMovie) {
            return res.status(404).json({ message: "Film non trouvé sur TMDb" });
        }


        // Vérifier si ce film est déjà dans la watchlist pour cet utilisateur
        const existingEntry = await prisma.watchlist.findUnique({
            where: {
                userId_movieId: {
                    userId,  // Assure-toi que le `userId` est bien une chaîne ou un ObjectId valide selon la base
                    movieId, // Le `movieId` devrait être une chaîne, pas un ObjectId de MongoDB
                },
            },
        });


        if (existingEntry) {
            console.log("Le film est déjà dans la watchlist.");
            return res.status(400).json({ message: "Le film est déjà dans la watchlist." });
        }


        // Enregistrer le film dans la watchlist avec les détails (titre, image)
        const watchlistEntry = await prisma.watchlist.create({
            data: {
                userId,
                movieId, // Assure-toi que le `movieId` ici est une chaîne (pas un ObjectId)
                title: tmdbMovie.title,           // Ajouter le titre
                imageUrl: `https://image.tmdb.org/t/p/w500${tmdbMovie.poster_path}`, // Ajouter l'URL de l'image
                releaseDate: tmdbMovie.release_date, // Date de sortie
                rating: tmdbMovie.vote_average,     // Note du film
            }
        });


        console.log("Film ajouté à la watchlist:", watchlistEntry);
        res.status(201).json(watchlistEntry);
    } catch (error) {
        console.error("Erreur lors de l'ajout à la watchlist :", error);
        res.status(500).json({ message: "Erreur lors de l'ajout à la watchlist." });
    }
});


app.get('/watchlist', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;  // Utilisateur authentifié


    try {
        // Recherche des films dans la watchlist pour cet utilisateur
        const watchlist = await prisma.watchlist.findMany({
            where: { userId: userId },
            select: {
                title: true,    // On sélectionne les informations nécessaires
                imageUrl: true,  // On sélectionne l'image URL
                movieId: true,   // On garde aussi l'ID du film (pour pouvoir éventuellement supprimer)
                releaseDate: true, // Date de sortie du film
                rating: true,      // Note du film
            }
        });


        // Vérifier si la watchlist est vide
        if (watchlist.length === 0) {
            return res.status(404).json({ message: "Aucun film dans la watchlist." });
        }


        console.log("Watchlist des films:", watchlist);


        // Réponse avec les films dans la watchlist
        res.json(watchlist);
    } catch (error) {
        console.error("Erreur lors de la récupération de la watchlist :", error);
        return res.status(500).json({ message: "Erreur lors de la récupération de la watchlist." });
    }
});
app.delete("/watchlist", ensureAuthenticated, async (req, res) => {
    const { movieId } = req.body;  // Récupère l'ID du film à supprimer
    const userId = req.user.id;    // Récupère l'ID de l'utilisateur authentifié


    console.log("Suppression de la watchlist - userId:", userId, "movieId:", movieId);


    try {
        // Vérifie si le film existe déjà dans la watchlist de l'utilisateur
        const watchlistEntry = await prisma.watchlist.findUnique({
            where: {
                userId_movieId: {
                    userId: userId,   // Utilisateur actuel
                    movieId: movieId  // ID du film à supprimer
                }
            }
        });


        // Si le film n'est pas trouvé dans la watchlist
        if (!watchlistEntry) {
            console.log("Le film n'est pas dans la watchlist.");
            return res.status(404).json({ message: "Le film n'est pas dans la watchlist." });
        }


        // Supprimer le film de la watchlist
        await prisma.watchlist.delete({
            where: {
                userId_movieId: {
                    userId: userId,   // Utilisateur actuel
                    movieId: movieId  // ID du film à supprimer
                }
            }
        });


        console.log("Film supprimé de la watchlist.");
        return res.status(200).json({ message: "Film supprimé de la watchlist." });


    } catch (error) {
        console.error("Erreur lors de la suppression de la watchlist :", error);
        return res.status(500).json({ message: "Erreur lors de la suppression de la watchlist." });
    }
});



