# Siyantek (صيانتك) — Carnet d'Entretien Automobile Web

Siyantek est une application Web SaaS moderne, bilingue (Français & Arabe), dédiée au suivi rigoureux de l'entretien automobile, à la gestion du kilométrage, des pièces de rechange, des dépenses et des rappels d'échéances techniques en Tunisie et dans le monde arabe.

---

## 🌟 Fonctionnalités Principales — gratuites, sans abonnement

- **Tableau de Bord Véhicule (Aperçu)** :
  - Visualisation immédiate de l'état du véhicule et de son compteur kilométrique.
  - Calcul dynamique de la prochaine maintenance (vidange, révision, freins).
  - Indicateur de progression avec statut en temps réel (À jour / À prévoir / En retard).
  - Mise à jour rapide du kilométrage avec validation stricte contre les valeurs décroissantes ou erronées.

- **Gestion Multi-Véhicules (Mes Véhicules)** :
  - Ajout, modification et consultation de plusieurs véhicules.
  - Prise en charge intégrale des plaques d'immatriculation tunisiennes et arabes (ex: `218 تونس 5678`).
  - Caractéristiques détaillées : Marque, Modèle, Année, Motorisation, Carburant, Kilométrage initial.

- **Carnet d'Entretien & Historique (Carnet & Historique)** :
  - Enregistrement détaillé des interventions : Vidange, Freinage, Pneumatiques, Visite technique, Batterie, etc.
  - Gestion des pièces de rechange avec références fabricant, quantités et coûts unitaires.
  - Niveaux de gravité des interventions : Entretien de routine, Réparation mineure, Réparation majeure, Intervention critique.
  - Recherche instantanée multi-critères, filtres par catégorie, statut et période.

- **Échéances & Rappels (Échéances & Rappels)** :
  - Programmation d'alertes par date calendaire et/ou par seuil kilométrique.
  - Types de rappels : Vidange moteur, Assurance automobile, Visite technique, Vignette fiscale, Courroie de distribution.
  - Marquage d'achèvement et archivage dans l'historique.

- **Rapports & Certificats PDF (Rapports)** :
  - Génération instantanée et export du carnet de bord officiel au format PDF haute fidélité.
  - Synthèse financière pour les démarches de revente ou de contrôle technique.
  - Exportation complète des données au format CSV (Excel) et JSON pour la portabilité.

---

## 🛡️ Architecture & Sécurité

- **Gestion des Sessions & Tokens Sécurisés** :
  - Utilisation de tokens de session cryptographiquement aléatoires de 256 bits (64 caractères hexadécimaux).
  - Stockage en base de données sous forme de hachage SHA-256 (aucun token en clair dans le fichier de données).
  - Support des cookies HttpOnly, Secure et SameSite pour la navigation Web avec en-têtes d'intégrité.
  - Révocation immédiate et complète de toutes les sessions actives lors d'un changement de mot de passe ou d'une déconnexion.

- **Chiffrement des Mots de Passe** :
  - Hachage cryptographique robuste avec `bcrypt` (12 tours de sel).
  - Aucune donnée ou compte de démonstration non sécurisé en production.

- **Protection IDOR & Isolation Multi-Tenant** :
  - Cloisonnement strict des requêtes par identifiant utilisateur (`userId`).
  - Impossibilité pour un utilisateur d'accéder, de modifier ou de supprimer les véhicules, factures, enregistrements ou rappels d'un autre utilisateur.

- **Contrôle des Flux & Résilience** :
  - Limitation de débit (Rate Limiting) avec fenêtres glissantes sur les routes d'authentification et de consultation.
  - En-têtes de sécurité stricts (`X-Content-Type-Options: nosniff`, `X-XSS-Protection`, `Referrer-Policy`).
  - Validation rigoureuse des entrées côté client et côté serveur.

- **Intégrité de la Base de Données** :
  - Écritures atomiques (`saveDB`) pour prévenir toute corruption de fichier lors des redémarrages.
  - Sauvegardes automatiques horodatées dans `data/backups/`.
  - Gabarit vierge de production (`data/siyantek-db.template.json`) sans données personnelles pré-remplies.

---

## Monétisation

Siyantek est configuré comme une application entièrement gratuite : aucun abonnement, achat intégré ou paiement manuel n’est proposé. Les anciennes références aux plans payants sont conservées uniquement pour compatibilité des données historiques. Une monétisation publicitaire peut être ajoutée ultérieurement après intégration et déclaration conformes aux règles Google Play.

<!-- Legacy payment integration notes retained below for reference only. -->
## Intégration historique des passerelles de paiement tunisiennes (désactivée)

L'application intègre l'architecture officielle pour les passerelles de paiement tunisiennes :
- **Konnect Tunisia** (`/api/webhooks/konnect`) :
  - Validation stricte des signatures HMAC-SHA256 avec comparaison en temps constant (`crypto.timingSafeEqual`).
  - Vérification obligatoire du montant en Dinars Tunisiens (TND) et de la référence de transaction.
  - Traitement idempotent évitant tout double déclenchement.
- **Flouci Tunisia** (`/api/webhooks/flouci`).
- **Garantie d'intégrité commerciale** :
  - Aucun abonnement Plus ou Pro n'est activé sans confirmation effective et vérifiée de la passerelle.
  - Si les clés de passerelle ne sont pas configurées, le système indique clairement l'état d'attente sans fausse promesse.

---

## 🚀 Démarrage & Commandes

### Prérequis
- Node.js 18+ ou 20+
- npm ou bun

### Installation
```bash
npm install
```

### Lancement en Développement
```bash
npm run dev
```
Le serveur démarre sur `http://localhost:3000`.

### Vérification & Linting
```bash
npm run lint
```

### Compilation pour Production
```bash
npm run build
```

---

## 🌐 Déploiement en Production

Pour déployer en environnement de production externe, configurez les variables d'environnement suivantes dans un fichier `.env` :

```env
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Clé secrète obligatoire pour la signature et l'intégrité des sessions (au moins 32 caractères)
JWT_SECRET=votre-cle-secrete-aleatoire-tres-longue-et-securisee-256-bit

# Passerelles de paiement (optionnelles)
KONNECT_API_KEY=
KONNECT_WALLET_ID=
KONNECT_WEBHOOK_SECRET=
FLOUCI_APP_TOKEN=
FLOUCI_APP_SECRET=
```

---

## 📄 Licence

Propriété exclusive de Siyantek. Tous droits réservés.


## Version Android (Capacitor)

Le projet inclut une configuration Capacitor 8 pour générer une application Android à partir de l'interface web. Capacitor 8 cible Android 16 (API 36), exigé pour les nouvelles applications Google Play depuis le 31 août 2026. Le serveur Node.js reste nécessaire pour les comptes, la synchronisation cloud et les données partagées.

### Préparation

1. Déployer le serveur Siyantek sur un domaine HTTPS stable.
2. Configurer `VITE_API_BASE_URL=https://votre-domaine-api.tn` dans l'environnement de compilation Android. Ne pas mettre de secret dans les variables `VITE_*`.
3. Ajouter `https://localhost` (origine WebView Capacitor Android) à `ALLOWED_ORIGINS` côté serveur si le client envoie cette origine. Capacitor 8 requiert Android Studio Otter 2025.2.1 ou plus récent et le SDK Android 36.
4. Installer les dépendances : `npm install`.
5. Générer le projet Android : `npm run android:add`.
6. Compiler et synchroniser : `npm run build:android`.
7. Ouvrir Android Studio : `npm run android:open`.
8. Dans Android Studio, générer un Android App Bundle (AAB) signé pour Google Play.

### Important avant publication

- Remplacer les coordonnées d'assistance de démonstration et confirmer l'adresse e-mail/WhatsApp officiels.
- Publier une politique de confidentialité réelle et compléter la fiche Data safety de Google Play selon les données effectivement collectées.
- Vérifier la suppression de compte et la suppression des données associées, les permissions, les notifications, les liens externes et le comportement hors ligne.
- Tester sur appareils physiques et sur les versions Android ciblées.
- Définir l'URL API de production avant chaque compilation Android. Sans serveur API joignable, les fonctions cloud et l'authentification ne fonctionneront pas.
- La configuration Capacitor ne constitue pas à elle seule un AAB signé ni une validation Google Play.
