import express from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";
import dotenv from "dotenv";



import nodemailer from "nodemailer";
import crypto from "crypto";




function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
        return "Le mot de passe doit contenir au moins 8 caractères.";
    }
    if (!hasUpperCase) {
        return "Le mot de passe doit contenir au moins une majuscule.";
    }
    if (!hasLowerCase) {
        return "Le mot de passe doit contenir au moins une minuscule.";
    }
    if (!hasNumber) {
        return "Le mot de passe doit contenir au moins un chiffre.";
    }
    if (!hasSpecialChar) {
        return "Le mot de passe doit contenir au moins un caractère spécial (@, #, $, etc.).";
    }

    return null; // Aucun problème détecté
}







dotenv.config();

// 📌 Gestion des chemins pour les modules ES
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const prisma = new PrismaClient();

// 📌 Configuration des sessions et de Passport
app.use(session({
    secret: process.env.SESSION_SECRET || "monsecret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
}));

app.use(passport.initialize());
app.use(passport.session());

// 📌 Middleware
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

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

passport.serializeUser((user, done) => {
    console.log("🔄 Sérialisation de l'utilisateur :", user.id);
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
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
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
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

    // 📌 Création de l'utilisateur en base de données
    await prisma.user.create({
        data: { name, email, hashedPassword },
    });

    res.status(201).json({ message: "Inscription réussie avec mot de passe sécurisé !" });
});


app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
        return res.status(400).json({ message: "Email ou mot de passe incorrect." });
    }

    const isMatch = await bcrypt.compare(password, user.hashedPassword);
    if (!isMatch) {
        return res.status(400).json({ message: "Email ou mot de passe incorrect." });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || "secret", { expiresIn: "1h" });

    res.json({ token });
});






app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
        return res.status(400).json({ message: "Email non trouvé" });
    }

    // Générer un token et une date d'expiration
    const token = crypto.randomBytes(32).toString("hex");
const expirationTime = new Date();
expirationTime.setHours(expirationTime.getHours() + 1); // Expiration dans 1h

console.log("📌 Token généré :", token);
console.log("📌 Expire à :", expirationTime);

    // Sauvegarder le token dans la base de données
    await prisma.user.update({
        where: { email },
        data: {
            resetPasswordToken: token,
            resetPasswordExpires: expirationTime,
        },
    });

    // Configuration de Nodemailer
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: process.env.EMAIL_USER, 
            pass: process.env.EMAIL_PASS,
        },
    });

    const resetLink = `http://localhost:5000/reset-password?token=${token}`;

    const mailOptions = {
        from: "FilmScope <no-reply@filmscope.com>",
        to: user.email,
        subject: "Réinitialisation de votre mot de passe",
        text: `Cliquez sur ce lien pour réinitialiser votre mot de passe : ${resetLink}`,
        html: `<p>Cliquez ici pour réinitialiser votre mot de passe : <a href="${resetLink}">${resetLink}</a></p>`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("❌ Erreur d'envoi d'email :", error);
            return res.status(500).json({ message: "Erreur lors de l'envoi de l'email" });
        }
        res.json({ message: "Email envoyé avec succès !" });
    });
});















app.post("/reset-password", async (req, res) => {
    const { token, password } = req.body;
    
    console.log("📌 Token reçu du client :", token);

    const user = await prisma.user.findFirst({
        where: {
            resetPasswordToken: token,
            resetPasswordExpires: { gte: new Date() },
        },
    });

    if (!user) {
        console.log("❌ Token invalide ou expiré !");
        return res.status(400).json({ message: "Token invalide ou expiré" });
    }

    console.log("✅ Utilisateur trouvé :", user.email);

    // Vérification de la sécurité du mot de passe
    const passwordError = validatePassword(password);
    if (passwordError) {
        console.log("❌ Mot de passe invalide :", passwordError);
        return res.status(400).json({ message: passwordError });
    }

    // Hasher le nouveau mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Mettre à jour l'utilisateur
    await prisma.user.update({
        where: { email: user.email },
        data: {
            hashedPassword,
            resetPasswordToken: null,
            resetPasswordExpires: null,
        },
    });

    console.log("✅ Mot de passe mis à jour !");
    res.json({ message: "Mot de passe mis à jour avec succès !" });
});


app.get("/reset-password/:token", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "reset-password.html"));
});










// 📌 Middleware pour vérifier le token JWT
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(403).json({ message: "Accès interdit. Aucun token fourni." });
    }

    jwt.verify(token.split(" ")[1], process.env.JWT_SECRET || "secret", (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Token invalide." });
        }
        req.userId = decoded.userId;
        next();
    });
};

// 📌 Route protégée (Exemple: Liste des films)
app.get("/movies", verifyToken, async (req, res) => {
    const movies = await prisma.movie.findMany();
    res.json(movies);
});

// 📌 Routes d'authentification Google
app.get("/auth/google", (req, res, next) => {
    console.log("🔍 Redirection vers Google pour l'authentification...");
    passport.authenticate("google", { scope: ["profile", "email"], prompt: "select_account" })(req, res, next);
});

app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        console.log("✅ Authentification réussie pour :", req.user.email);
        res.redirect("/accueil");
    }
);

app.get("/profile", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Non authentifié" });
    }
    res.json(req.user);
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("❌ Erreur lors de la déconnexion :", err);
            return res.status(500).json({ message: "Erreur de déconnexion" });
        }
        res.redirect("/login");
    });
});

// 📌 Démarrer le serveur (PLACÉ À LA FIN)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Serveur en écoute sur http://localhost:${PORT}`));



app.get("/reset-password", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "reset-password.html"));
});

import axios from "axios";  
dotenv.config();

// 📌 Endpoint pour récupérer les films populaires depuis TMDb
app.get("/api/films", async (req, res) => {
    try {
        const apiKey = process.env.TMDB_API_KEY; 
        const BASE_URL = "https://api.themoviedb.org/3";

        // Requête pour récupérer les films populaires
        const response = await axios.get(`${BASE_URL}/movie/popular?api_key=${API_KEY}&language=fr-FR`);
        
        // Envoyer les résultats des films en réponse
        res.json(response.data.results);
    } catch (error) {
        console.error("❌ Erreur lors de la récupération des films TMDb :", error);
        res.status(500).json({ message: "Erreur lors de la récupération des films." });
    }
});

// 📌 Exemple de route pour obtenir un film spécifique
app.get("/api/films/:id", async (req, res) => {
    const movieId = req.params.id;
    try {
        const apiKey = process.env.TMDB_API_KEY;
        const BASE_URL = "https://api.themoviedb.org/3";

        // Requête pour récupérer les détails d'un film par ID
        const response = await axios.get(`${BASE_URL}/movie/${movieId}?api_key=${API_KEY}&language=fr-FR`);

        // Envoyer les détails du film
        res.json(response.data);
    } catch (error) {
        console.error("❌ Erreur lors de la récupération du film par ID :", error);
        res.status(500).json({ message: "Erreur lors de la récupération du film." });
    }
});

app.get('/search', async (req, res) => {
    const query = req.query.query; // Récupère le terme de recherche depuis l'URL
    const apiKey = process.env.TMDB_API_KEY;

    try {
        const response = await axios.get(`https://api.themoviedb.org/3/search/movie?api_key=${apiKey}&query=${encodeURIComponent(query)}&language=fr-FR`);
        res.json(response.data); // Renvoie les résultats à la page HTML
    } catch (error) {
        console.error("Erreur de recherche TMDb :", error);
        res.status(500).json({ message: "Erreur lors de la recherche des films." });
    }
});
