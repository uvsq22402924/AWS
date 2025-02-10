import express from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

// Gestion des chemins pour les modules ES
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const prisma = new PrismaClient();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static("public")); // Servir les fichiers statiques (CSS, images, JS)

// 🔹 Servir les fichiers HTML
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/accueil", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "accueil.html"));
});

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "register.html"));
});

// 🔹 Route d'inscription (Register)
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
        return res.status(400).json({ message: "Cet utilisateur existe déjà." });
    }

    // Hasher le mot de passe avant stockage
    const hashedPassword = await bcrypt.hash(password, 10);

    // Créer l'utilisateur
    const user = await prisma.user.create({
        data: { name, email, hashedPassword },
    });

    res.status(201).json({ message: "Inscription réussie !" });
});

// 🔹 Route de connexion (Login)
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // Vérifier si l'utilisateur existe
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
        return res.status(400).json({ message: "Email ou mot de passe incorrect." });
    }

    // Vérifier le mot de passe
    const isMatch = await bcrypt.compare(password, user.hashedPassword);
    if (!isMatch) {
        return res.status(400).json({ message: "Email ou mot de passe incorrect." });
    }

    // Générer un token JWT
    const token = jwt.sign({ userId: user.id }, "secret", { expiresIn: "1h" });

    res.json({ token });
});

// 🔹 Middleware pour vérifier le token JWT
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(403).json({ message: "Accès interdit. Aucun token fourni." });
    }

    jwt.verify(token.split(" ")[1], "secret", (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Token invalide." });
        }
        req.userId = decoded.userId;
        next();
    });
};

// 🔹 Route protégée (Exemple: Liste des films)
app.get("/movies", verifyToken, async (req, res) => {
    const movies = await prisma.movie.findMany();
    res.json(movies);
});

// 🔹 Démarrer le serveur
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`🚀 Serveur en écoute sur http://localhost:${PORT}`));
