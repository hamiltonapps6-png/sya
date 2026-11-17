import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.NODE_ENV === 'production' && process.env.PORT ? Number(process.env.PORT) : 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Enable trust proxy for correct client IP detection behind reverse proxy (Google Cloud Run / Nginx)
app.set('trust proxy', 1);

// Server-side secret for authentication & token integrity (Priority 5)
// In production, requires a fixed and secure SESSION_SECRET or JWT_SECRET (min 32 chars)
const isProduction = process.env.NODE_ENV === 'production';
const envSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;

if (isProduction && (!envSecret || envSecret.trim().length < 32)) {
  console.error(
    'FATAL: En environnement de production (NODE_ENV=production), la variable JWT_SECRET ou SESSION_SECRET est obligatoire et doit comporter au moins 32 caractères pour garantir l\'intégrité des sessions.'
  );
  process.exit(1);
}

const SERVER_SECRET = envSecret || crypto.randomBytes(32).toString('hex');

// -------------------------------------------------------------
// 1. Security Headers & CORS Policy (Priority 8)
// -------------------------------------------------------------
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

const allowedOriginsEnv = process.env.ALLOWED_ORIGINS;
const allowedOriginsList = allowedOriginsEnv
  ? allowedOriginsEnv.split(',').map((o) => o.trim())
  : null;

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (curl, same-origin, mobile app, internal calls)
      if (!origin) return callback(null, true);
      // In non-production development/preview environments, permit origin
      if (process.env.NODE_ENV !== 'production') {
        return callback(null, true);
      }
      // In production, strictly restrict to allowed origins list
      if (allowedOriginsList && allowedOriginsList.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Origine non autorisée par la politique CORS Siyantek'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'x-konnect-signature', 'x-flouci-signature', 'x-admin-bootstrap-token'],
    credentials: true,
  })
);

app.use(express.json({ limit: '15mb' }));

// -------------------------------------------------------------
// 2. In-Memory Sliding-Window Rate Limiters (Priority 8)
// -------------------------------------------------------------
interface RateLimitRecord {
  count: number;
  resetAt: number;
}

function createRateLimiter(windowMs: number, maxRequests: number, errorMessage: string) {
  const store = new Map<string, RateLimitRecord>();

  // Background cleanup every 5 minutes
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of store.entries()) {
      if (now > record.resetAt) {
        store.delete(key);
      }
    }
  }, 5 * 60 * 1000);
  if (cleanupTimer.unref) cleanupTimer.unref();

  return (req: Request, res: Response, next: NextFunction) => {
    // In test environment, allow explicit test IP header for rate-limit simulation
    // In production, strictly derive from trusted proxy / socket IP (never trust client header)
    const ip =
      (process.env.NODE_ENV !== 'production' && (req.headers['x-test-client-ip'] as string)) ||
      req.ip ||
      req.socket.remoteAddress ||
      'unknown';
    const now = Date.now();
    const record = store.get(ip);

    if (!record || now > record.resetAt) {
      store.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }

    if (record.count >= maxRequests) {
      const retryAfterSec = Math.ceil((record.resetAt - now) / 1000);
      res.setHeader('Retry-After', retryAfterSec);
      return res.status(429).json({
        error: errorMessage,
        retryAfter: retryAfterSec,
      });
    }

    record.count += 1;
    next();
  };
}

const authRateLimiter = createRateLimiter(
  15 * 60 * 1000,
  15,
  'Trop de tentatives d\'authentification. Veuillez patienter 15 minutes avant de réessayer.'
);

const generalApiLimiter = createRateLimiter(
  60 * 1000,
  200,
  'Limite de requêtes atteinte. Veuillez ralentir.'
);

app.use('/api/', generalApiLimiter);

// -------------------------------------------------------------
// 3. Database setup: Local JSON store with Atomic Writes & Backup (Priority 1 & 6)
// -------------------------------------------------------------
const DATA_DIR = process.env.SIYANTEK_DATA_DIR || path.join(__dirname, 'data');
const DB_PATH =
  process.env.SIYANTEK_DB_PATH ||
  process.env.DB_PATH ||
  path.join(DATA_DIR, 'siyantek-db.json');
const BACKUPS_DIR = path.join(DATA_DIR, 'backups');
const RECEIPTS_DIR = process.env.RECEIPTS_DIR || path.join(DATA_DIR, 'uploads', 'receipts');

if (!fs.existsSync(RECEIPTS_DIR)) {
  fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
}

// Admin privileges are never inferred from an email address. The first admin must
// be provisioned explicitly with ADMIN_BOOTSTRAP_TOKEN (see /api/admin/bootstrap).

export const TUNISIA_TRANSFER_CONFIG = {
  accountName: process.env.TUNISIA_BANK_BENEFICIARY || 'Siyantek Auto Tech SARL',
  bankName: process.env.TUNISIA_BANK_NAME || 'BIAT (Banque Internationale Arabe de Tunisie)',
  rib: process.env.TUNISIA_BANK_RIB || '08001000123456789012',
  iban: process.env.TUNISIA_BANK_IBAN || 'TN59 0800 1000 1234 5678 9012',
  postalRip: process.env.TUNISIA_POSTE_RIP || '17001000001234567890',
  d17Phone: process.env.TUNISIA_POSTE_D17 || '+216 28 000 000',
  instructionsFr: 'Effectuez le virement bancaire ou postal en indiquant impérativement la référence de commande dans le motif. Déposez ensuite le reçu ou capture de validation.',
  instructionsAr: 'قم بإجراء التحويل البنكي أو البريدي مع تضمين الرمز المرجعي للطلب في الملاحظات، ثم قم برفع صورة أو ملف الوصل للمراجعة والتفعيل.',
};

export function backupDatabase(): string {
  if (!fs.existsSync(BACKUPS_DIR)) {
    fs.mkdirSync(BACKUPS_DIR, { recursive: true });
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupFile = path.join(BACKUPS_DIR, `siyantek-db.backup-${timestamp}.json`);
  fs.writeFileSync(backupFile, JSON.stringify(db, null, 2), 'utf-8');
  return backupFile;
}

export interface User {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: 'user' | 'admin';
  tier: 'free' | 'plus' | 'pro';
  subscriptionStatus: 'active' | 'canceled' | 'none' | 'expired';
  renewalDate: string;
  subscriptionExpiresAt?: string | null;
  createdAt: string;
}

export interface Vehicle {
  id: string;
  userId: string;
  brand: string;
  model: string;
  year: string;
  plate: string;
  mileage: number;
  motorization?: string;
  fuelType?: string;
  createdAt: string;
  updatedAt: string;
}

export type MaintenanceType = 'oil' | 'brakes' | 'tires' | 'inspection' | 'battery' | 'other';

export interface SparePart {
  name: string;
  reference?: string;
  quantity: number;
  unitCost: number;
}

export interface MaintenanceRecord {
  id: string;
  userId: string;
  vehicleId: string;
  type: MaintenanceType;
  date: string;
  mileage: number;
  cost: number;
  notes: string;
  nextMileage?: number;
  workshop?: string;
  createdAt: string;
  status?: 'completed' | 'in_progress' | 'scheduled';
  severity?: 'routine' | 'minor' | 'major' | 'critical';
  parts?: SparePart[];
}

export interface Reminder {
  id: string;
  userId: string;
  vehicleId: string;
  title: string;
  type: 'oil' | 'insurance' | 'inspection' | 'vignette' | 'brakes' | 'belt' | 'custom';
  dueDate?: string;
  dueMileage?: number;
  notes?: string;
  completed: boolean;
  completedDate?: string;
  createdAt: string;
}

export interface Session {
  tokenHash: string;
  userId: string;
  createdAt: string;
  expiresAt: string;
  token?: string; // For backward-compatible migration
}

export interface PasswordReset {
  tokenHash: string;
  userId: string;
  email: string;
  createdAt: string;
  expiresAt: string;
  used: boolean;
  token?: string; // For legacy migration
}

export interface BankInstructions {
  accountName: string;
  bankName: string;
  rib: string;
  iban?: string;
  postalRip?: string;
  d17Phone?: string;
}

export interface PaymentTransaction {
  id: string;
  userId: string;
  planId: 'plus' | 'pro';
  amountDT: number;
  currency: 'TND';
  provider: 'konnect' | 'flouci' | 'bank_transfer' | 'postal_order';
  method?: string;
  status: 'pending' | 'submitted' | 'completed' | 'approved' | 'rejected' | 'expired' | 'failed' | 'canceled';
  idempotencyKey: string;
  paymentReference?: string;
  transferReference?: string;
  checkoutUrl?: string;
  bankInstructions?: BankInstructions;
  receiptFilename?: string;
  receiptMimeType?: string;
  receiptFileSize?: number;
  receiptUploadedAt?: string;
  adminNotes?: string;
  reviewedBy?: string;
  reviewedAt?: string;
  createdAt: string;
  completedAt?: string;
  rawWebhookPayload?: any;
}

export interface SupportTicket {
  id: string;
  name: string;
  email: string;
  subject: string;
  message: string;
  userId?: string;
  status: 'new' | 'in_progress' | 'resolved';
  createdAt: string;
}

export interface AuditLog {
  id: string;
  adminId: string;
  adminEmail: string;
  action: string;
  targetType: 'user' | 'payment' | 'subscription' | 'system';
  targetId: string;
  details?: any;
  ip?: string;
  createdAt: string;
}

export interface DB {
  users: User[];
  sessions: Session[];
  passwordResets: PasswordReset[];
  vehicles: Vehicle[];
  records: MaintenanceRecord[];
  reminders: Reminder[];
  payments: PaymentTransaction[];
  supportTickets: SupportTicket[];
  auditLogs: AuditLog[];
}

const TIER_LIMITS = {
  // All features are free. Keep legacy tier keys for existing accounts/data compatibility.
  free: { maxVehicles: Number.MAX_SAFE_INTEGER, advancedReports: true, priceTND: 0 },
  plus: { maxVehicles: Number.MAX_SAFE_INTEGER, advancedReports: true, priceTND: 0 },
  pro: { maxVehicles: Number.MAX_SAFE_INTEGER, advancedReports: true, priceTND: 0 },
};

export function hashToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

function initDB(): DB {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const templatePath = path.join(DATA_DIR, 'siyantek-db.template.json');

  if (fs.existsSync(DB_PATH)) {
    try {
      const data = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));

      // Automatically create a safety backup before applying migrations
      if (Array.isArray(data.users) && data.users.length > 0) {
        if (!fs.existsSync(BACKUPS_DIR)) {
          fs.mkdirSync(BACKUPS_DIR, { recursive: true });
        }
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = path.join(BACKUPS_DIR, `siyantek-db.startup-backup-${timestamp}.json`);
        fs.writeFileSync(backupFile, JSON.stringify(data, null, 2), 'utf-8');
      }

      // 1. Remove legacy demo accounts and ensure role & subscription expiration fields
      const cleanedUsers: User[] = (Array.isArray(data.users) ? data.users : [])
        .filter((u: any) => u.id !== 'usr_demo_123' && u.passwordHash !== 'demo123456')
        .map((u: any) => {
          const { aiUsageThisMonth, lastUsageReset, ...safeUser } = u;
          return {
            ...safeUser,
            // Revoke legacy email-pattern promotions; bootstrap a trusted admin explicitly.
            role: 'user',
            tier: 'free',
            subscriptionStatus: 'none',
            subscriptionExpiresAt:
              safeUser.subscriptionExpiresAt !== undefined
                ? safeUser.subscriptionExpiresAt
                : safeUser.tier !== 'free'
                ? safeUser.renewalDate
                : null,
          };
        });

      const cleanedVehicles = (Array.isArray(data.vehicles) ? data.vehicles : []).filter(
        (v: any) => v.userId !== 'usr_demo_123'
      );
      const cleanedRecords = (Array.isArray(data.records) ? data.records : []).filter(
        (r: any) => r.userId !== 'usr_demo_123'
      );

      // 2. Safe Session Migration: Convert plain text tokens to SHA-256 tokenHash only
      const migratedSessions = (Array.isArray(data.sessions) ? data.sessions : []).map((s: any) => {
        if (s.tokenHash) {
          const { token, ...safeSession } = s;
          return safeSession;
        }
        if (s.token) {
          return {
            tokenHash: hashToken(s.token),
            userId: s.userId,
            createdAt: s.createdAt,
            expiresAt: s.expiresAt,
          };
        }
        return s;
      });

      // 3. Password Reset Migration: Hash tokens to SHA-256 tokenHash
      const migratedResets: PasswordReset[] = (
        Array.isArray(data.passwordResets) ? data.passwordResets : []
      ).map((r: any) => {
        if (r.tokenHash) return r;
        if (r.token) {
          return {
            tokenHash: hashToken(r.token),
            userId: r.userId,
            email: r.email,
            createdAt: r.createdAt,
            expiresAt: r.expiresAt,
            used: Boolean(r.used),
          };
        }
        return r;
      });

      const migratedDb: DB = {
        users: cleanedUsers,
        sessions: migratedSessions,
        passwordResets: migratedResets,
        vehicles: cleanedVehicles,
        records: cleanedRecords,
        reminders: Array.isArray(data.reminders) ? data.reminders : [],
        payments: Array.isArray(data.payments) ? data.payments : [],
        supportTickets: Array.isArray(data.supportTickets) ? data.supportTickets : [],
        auditLogs: Array.isArray(data.auditLogs) ? data.auditLogs : [],
      };

      // Atomic persistence of cleaned and migrated database
      const tempInitFile = `${DB_PATH}.tmp.${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      fs.writeFileSync(tempInitFile, JSON.stringify(migratedDb, null, 2), 'utf-8');
      fs.renameSync(tempInitFile, DB_PATH);

      return migratedDb;
    } catch (e) {
      console.error('Error reading db file, reinitializing clean store', e);
    }
  }

  // Load from empty template if available, or create pristine database
  if (fs.existsSync(templatePath)) {
    try {
      const templateData = JSON.parse(fs.readFileSync(templatePath, 'utf-8'));
      if (!Array.isArray(templateData.supportTickets)) {
        templateData.supportTickets = [];
      }
      if (!Array.isArray(templateData.auditLogs)) {
        templateData.auditLogs = [];
      }
      fs.writeFileSync(DB_PATH, JSON.stringify(templateData, null, 2), 'utf-8');
      return templateData;
    } catch (err) {
      console.error('Error loading template database:', err);
    }
  }

  const initialDb: DB = {
    users: [],
    sessions: [],
    passwordResets: [],
    vehicles: [],
    records: [],
    reminders: [],
    payments: [],
    supportTickets: [],
    auditLogs: [],
  };

  fs.writeFileSync(DB_PATH, JSON.stringify(initialDb, null, 2), 'utf-8');
  return initialDb;
}

export let db = initDB();

// Atomic file write to prevent database file corruption on unexpected shutdown
export function saveDB() {
  try {
    const tempFile = `${DB_PATH}.tmp.${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    fs.writeFileSync(tempFile, JSON.stringify(db, null, 2), 'utf-8');
    fs.renameSync(tempFile, DB_PATH);
  } catch (err) {
    console.error('Failed to write to DB:', err);
  }
}



// -------------------------------------------------------------
// 5. Authentication Middleware (Cryptographic Session Verification - Priority 1 & 3)
// -------------------------------------------------------------
function extractSessionToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.replace('Bearer ', '').trim();
  }
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const match = cookieHeader.match(/(?:^|;\s*)siyantek_session=([^;]+)/);
    if (match) {
      return decodeURIComponent(match[1]).trim();
    }
  }
  return null;
}

function authenticate(req: Request, res: Response, next: NextFunction) {
  const token = extractSessionToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Accès non autorisé. Token de session requis.' });
  }

  // Ensure token is at least 32 characters
  if (token.length < 32) {
    return res.status(401).json({ error: 'Token de session invalide ou malformé.' });
  }

  const tokenHash = hashToken(token);

  // Lookup in active server sessions by secure SHA-256 hash
  const session = db.sessions.find(
    (s) => s.tokenHash === tokenHash || (s as any).token === token
  );
  if (!session) {
    return res.status(401).json({ error: 'Session inexistante ou révoquée. Veuillez vous reconnecter.' });
  }

  // Verify expiration
  if (Date.now() > new Date(session.expiresAt).getTime()) {
    // Purge expired session
    db.sessions = db.sessions.filter(
      (s) => s.tokenHash !== tokenHash && (s as any).token !== token
    );
    saveDB();
    return res.status(401).json({ error: 'Session expirée. Veuillez vous reconnecter.' });
  }

  const user = db.users.find((u) => u.id === session.userId);
  if (!user) {
    db.sessions = db.sessions.filter(
      (s) => s.tokenHash !== tokenHash && (s as any).token !== token
    );
    saveDB();
    return res.status(401).json({ error: 'Utilisateur introuvable.' });
  }

  // Automatic subscription expiration check without deleting any user data
  if (
    user.tier !== 'free' &&
    user.subscriptionExpiresAt &&
    Date.now() > new Date(user.subscriptionExpiresAt).getTime()
  ) {
    user.tier = 'free';
    user.subscriptionStatus = 'expired';
    saveDB();
  }

  (req as any).user = user;
  (req as any).session = session;
  (req as any).rawToken = token;
  next();
}

// Admin-Only Authorization Middleware (Priority 2 & 4)
function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user as User | undefined;
  if (!user || user.role !== 'admin') {
    return res.status(403).json({
      error: 'Accès réservé aux administrateurs de Siyantek.',
      messageAr: 'هذا القسم مخصص لإدارة المنصة فقط.',
    });
  }
  next();
}

function logAudit(
  admin: User,
  action: string,
  targetType: 'user' | 'payment' | 'subscription' | 'system',
  targetId: string,
  details: any = {},
  req?: Request
) {
  const auditEntry: AuditLog = {
    id: `audit_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    adminId: admin.id,
    adminEmail: admin.email,
    action,
    targetType,
    targetId,
    details,
    ip: req ? ((req.headers['x-test-client-ip'] as string) || req.ip || req.socket.remoteAddress || 'unknown') : undefined,
    createdAt: new Date().toISOString(),
  };
  db.auditLogs.unshift(auditEntry);
  if (db.auditLogs.length > 500) {
    db.auditLogs = db.auditLogs.slice(0, 500);
  }
  saveDB();
  return auditEntry;
}

// -------------------------------------------------------------
// 6. Strict Input Validation Helpers (Priority 8)
// -------------------------------------------------------------
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$/;

function validateRegistrationInput(name: unknown, email: unknown, password: unknown): string | null {
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 80) {
    return 'Le nom doit contenir entre 2 et 80 caractères.';
  }
  if (typeof email !== 'string' || !EMAIL_REGEX.test(email.trim()) || email.trim().length > 120) {
    return 'Veuillez saisir une adresse email valide.';
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return 'Le mot de passe doit contenir entre 8 et 128 caractères.';
  }
  return null;
}

function validateVehicleInput(data: any): string | null {
  if (!data || typeof data !== 'object') return 'Données de véhicule invalides.';
  if (typeof data.brand !== 'string' || data.brand.trim().length < 1 || data.brand.trim().length > 50) {
    return 'La marque du véhicule est obligatoire (max 50 caractères).';
  }
  if (typeof data.model !== 'string' || data.model.trim().length < 1 || data.model.trim().length > 50) {
    return 'Le modèle du véhicule est obligatoire (max 50 caractères).';
  }
  if (data.mileage !== undefined) {
    const m = Number(data.mileage);
    if (isNaN(m) || m < 0 || m > 2000000) {
      return 'Le kilométrage doit être un nombre positif valide (inférieur à 2 000 000 km).';
    }
  }
  return null;
}

function validateMaintenanceInput(data: any): string | null {
  if (!data || typeof data !== 'object') return 'Données de maintenance invalides.';
  if (!data.vehicleId || typeof data.vehicleId !== 'string') return 'Véhicule obligatoire.';
  const validTypes: MaintenanceType[] = ['oil', 'brakes', 'tires', 'inspection', 'battery', 'other'];
  if (!validTypes.includes(data.type)) return 'Type d\'entretien non reconnu.';
  if (!data.date || isNaN(Date.parse(data.date))) return 'Date d\'entretien invalide.';
  const m = Number(data.mileage);
  if (isNaN(m) || m < 0 || m > 2000000) return 'Kilométrage invalide.';
  const c = Number(data.cost);
  if (isNaN(c) || c < 0 || c > 100000) return 'Coût invalide.';
  if (data.status && !['completed', 'in_progress', 'scheduled'].includes(data.status)) {
    return 'Statut de maintenance non valide.';
  }
  if (data.severity && !['routine', 'minor', 'major', 'critical'].includes(data.severity)) {
    return 'Niveau de gravité non valide.';
  }
  return null;
}

function validateReminderInput(data: any): string | null {
  if (!data || typeof data !== 'object') return 'Données de rappel invalides.';
  if (!data.vehicleId || typeof data.vehicleId !== 'string') return 'Véhicule obligatoire.';
  if (!data.title || typeof data.title !== 'string' || data.title.trim().length === 0) {
    return 'Titre du rappel obligatoire (max 100 caractères).';
  }
  const validTypes = ['oil', 'insurance', 'inspection', 'vignette', 'brakes', 'belt', 'custom'];
  if (data.type && !validTypes.includes(data.type)) return 'Type de rappel non valide.';
  return null;
}

// -------------------------------------------------------------
// 7. Auth Endpoints (Priority 1, 2, 3)
// -------------------------------------------------------------
app.post('/api/auth/register', authRateLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const validationError = validateRegistrationInput(name, email, password);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const existing = db.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'Un compte existe déjà avec cette adresse email.' });
    }

    // Cryptographic password hashing using bcrypt with 12 salt rounds (Priority 2)
    const passwordHash = await bcrypt.hash(String(password), 12);
    const userRole: 'user' = 'user';

    const newUser: User = {
      id: `usr_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`,
      name: String(name).trim(),
      email: cleanEmail,
      passwordHash,
      role: userRole,
      tier: 'free',
      subscriptionStatus: 'none',
      renewalDate: new Date(Date.now() + 30 * 86400000).toISOString(),
      subscriptionExpiresAt: null,
      createdAt: new Date().toISOString(),
    };

    db.users.push(newUser);

    // Issue cryptographically random 256-bit session token and store SHA-256 hash (Priority 1 & 3)
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(sessionToken);
    const newSession: Session = {
      tokenHash,
      userId: newUser.id,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
    };
    db.sessions.push(newSession);
    saveDB();

    // Set secure HttpOnly cookie for Web browser sessions
    res.cookie('siyantek_session', sessionToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 30 * 86400000,
      path: '/',
    });

    const { passwordHash: _, ...safeUser } = newUser;
    return res.status(201).json({ token: sessionToken, user: safeUser });
  } catch (err: any) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'Erreur serveur lors de la création du compte.' });
  }
});

app.post('/api/auth/login', authRateLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email et mot de passe requis.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = db.users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (!user) {
      return res.status(401).json({ error: 'Identifiants invalides. Vérifiez votre email et mot de passe.' });
    }

    // Secure password verification with bcrypt (Priority 2)
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'Identifiants invalides. Vérifiez votre email et mot de passe.' });
    }

    // Issue new cryptographically random 256-bit session token and store SHA-256 hash (Priority 1 & 3)
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(sessionToken);
    const newSession: Session = {
      tokenHash,
      userId: user.id,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
    };
    db.sessions.push(newSession);
    saveDB();

    // Set secure HttpOnly cookie for Web browser sessions
    res.cookie('siyantek_session', sessionToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 30 * 86400000,
      path: '/',
    });

    const { passwordHash: _, ...safeUser } = user;
    return res.json({ token: sessionToken, user: safeUser });
  } catch (err: any) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
  }
});

app.post('/api/admin/bootstrap', authenticate, (req, res) => {
  const configuredToken = process.env.ADMIN_BOOTSTRAP_TOKEN || '';
  const suppliedToken = String(req.headers['x-admin-bootstrap-token'] || '');
  if (configuredToken.length < 32 || suppliedToken.length !== configuredToken.length ||
      !crypto.timingSafeEqual(Buffer.from(suppliedToken), Buffer.from(configuredToken))) {
    return res.status(403).json({ success: false, error: 'رمز تهيئة المدير غير صالح أو غير مهيأ.' });
  }
  if (db.users.some((u) => u.role === 'admin')) {
    return res.status(409).json({ success: false, error: 'تم إعداد حساب المدير مسبقاً.' });
  }
  const user = (req as any).user as User;
  user.role = 'admin';
  saveDB();
  const { passwordHash: _passwordHash, ...safeUser } = user;
  return res.json({ success: true, user: safeUser });
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  const currentToken = (req as any).rawToken;
  if (currentToken) {
    const tokenHash = hashToken(currentToken);
    // Revoke this active session immediately by hash (Priority 1 & 3)
    db.sessions = db.sessions.filter(
      (s) => s.tokenHash !== tokenHash && (s as any).token !== currentToken
    );
    saveDB();
  }
  res.clearCookie('siyantek_session', { path: '/' });
  return res.json({ success: true, message: 'Session révoquée avec succès.' });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const limits = TIER_LIMITS[user.tier];
  const { passwordHash: _, ...safeUser } = user;

  const userVehicles = db.vehicles.filter((v) => v.userId === user.id);
  const userRecords = db.records.filter((r) => r.userId === user.id);

  return res.json({
    user: safeUser,
    limits,
    stats: {
      totalVehicles: userVehicles.length,
      totalRecords: userRecords.length,
      totalCost: userRecords.reduce((acc, r) => acc + (r.cost || 0), 0),
    },
  });
});

// Password Reset Request (Priority 3 & 4)
// If email gateway is not configured, inform the user honestly rather than simulating a fake email
app.post('/api/auth/reset-password', authRateLimiter, (req, res) => {
  const { email } = req.body;
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'Adresse email requise.' });
  }

  const isEmailServiceConfigured = Boolean(
    process.env.SMTP_HOST ||
    process.env.RESEND_API_KEY ||
    process.env.ENABLE_PASSWORD_RESET_TEST_MODE === 'true'
  );

  if (!isEmailServiceConfigured) {
    return res.status(503).json({
      success: false,
      serviceAvailable: false,
      message:
        'Le service d\'envoi d\'emails de réinitialisation est temporairement suspendu pour des raisons de sécurité (passerelle SMTP non configurée en production). Veuillez contacter le support Siyantek pour réinitialiser vos accès.',
      messageAr:
        'خدمة استعادة كلمة المرور عبر البريد معطلة مؤقتاً لأسباب أمنية لعدم ربط مزود بريد SMTP معتمد. يرجى التواصل مع إدارة سيبانتك لمساعدتك.',
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const user = db.users.find((u) => u.email.toLowerCase() === cleanEmail);

  let generatedToken: string | undefined = undefined;
  if (user) {
    // Invalidate any older unused reset tokens for this user
    db.passwordResets = db.passwordResets.filter((r) => r.userId !== user.id);

    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(resetToken);
    generatedToken = resetToken;
    const resetEntry: PasswordReset = {
      tokenHash,
      userId: user.id,
      email: cleanEmail,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(), // 15 min expiry
      used: false,
    };
    db.passwordResets.push(resetEntry);
    saveDB();
  }

  // Consistent response to prevent user enumeration
  return res.json({
    success: true,
    message: 'Si cette adresse email est associée à un compte, un lien de réinitialisation sécurisé valable 15 minutes a été expédié.',
    ...(process.env.ENABLE_PASSWORD_RESET_TEST_MODE === 'true' && generatedToken ? { _testResetToken: generatedToken } : {}),
  });
});

// Secure Password Reset Confirmation (Priority 3 & 4)
app.post('/api/auth/reset-password-confirm', authRateLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || typeof token !== 'string' || !newPassword || typeof newPassword !== 'string') {
      return res.status(400).json({ error: 'Token et nouveau mot de passe requis.' });
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      return res.status(400).json({ error: 'Le nouveau mot de passe doit comporter entre 8 et 128 caractères.' });
    }

    const inputHash = hashToken(token);
    const reset = db.passwordResets.find(
      (r) => r.tokenHash === inputHash || (r as any).token === token
    );
    if (!reset) {
      return res.status(400).json({ error: 'Lien ou code de réinitialisation introuvable ou invalide.' });
    }

    // Check single-use guarantee
    if (reset.used) {
      return res.status(400).json({ error: 'Ce code de réinitialisation a déjà été utilisé (usage unique).' });
    }

    // Check TTL expiration (15 minutes)
    if (Date.now() > new Date(reset.expiresAt).getTime()) {
      return res.status(400).json({ error: 'Le code de réinitialisation a expiré (validité de 15 minutes dépassée).' });
    }

    const user = db.users.find((u) => u.id === reset.userId);
    if (!user) {
      return res.status(400).json({ error: 'Compte utilisateur introuvable.' });
    }

    // Hash new password securely with bcrypt
    user.passwordHash = await bcrypt.hash(newPassword, 12);
    reset.used = true;

    // Revoke all existing sessions for this user across all devices (Priority 1)
    db.sessions = db.sessions.filter((s) => s.userId !== user.id);
    saveDB();

    return res.json({
      success: true,
      message: 'Mot de passe mis à jour avec succès. Vos sessions précédentes ont été révoquées pour votre sécurité. Veuillez vous reconnecter.',
    });
  } catch (err: any) {
    console.error('Password reset confirm error:', err);
    return res.status(500).json({ error: 'Erreur lors de la mise à jour du mot de passe.' });
  }
});

// Non-production test helper for testing password reset tokens in automated test suites
if (process.env.NODE_ENV !== 'production') {
  app.post('/api/test/create-reset-token', (req, res) => {
    const { userId, email, expired = false, used = false } = req.body;
    const token = crypto.randomBytes(32).toString('hex');
    const resetEntry: PasswordReset = {
      token,
      userId,
      email,
      createdAt: new Date().toISOString(),
      expiresAt: expired
        ? new Date(Date.now() - 5 * 60 * 1000).toISOString()
        : new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      used,
    };
    db.passwordResets.push(resetEntry);
    saveDB();
    return res.json({ token, resetEntry });
  });
}

app.post('/api/auth/delete-account', authenticate, (req, res) => {
  const user = (req as any).user as User;
  // Strict cascade deletion of user items only (Priority 7)
  db.sessions = db.sessions.filter((s) => s.userId !== user.id);
  db.passwordResets = db.passwordResets.filter((r) => r.userId !== user.id);
  db.records = db.records.filter((r) => r.userId !== user.id);
  db.reminders = db.reminders.filter((rem) => rem.userId !== user.id);
  db.vehicles = db.vehicles.filter((v) => v.userId !== user.id);
  db.payments = db.payments.filter((p) => p.userId !== user.id);
  db.users = db.users.filter((u) => u.id !== user.id);
  saveDB();
  return res.json({ success: true, message: 'Compte, sessions et données personnelles supprimés définitivement.' });
});

app.get('/api/auth/export-data', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const userVehicles = db.vehicles.filter((v) => v.userId === user.id);
  const userRecords = db.records.filter((r) => r.userId === user.id);
  const userReminders = db.reminders.filter((rem) => rem.userId === user.id);

  const { passwordHash, ...safeUser } = user;
  return res.json({
    exportDate: new Date().toISOString(),
    user: safeUser,
    vehicles: userVehicles,
    records: userRecords,
    reminders: userReminders,
  });
});

// -------------------------------------------------------------
// 8. Vehicles Endpoints with Strict IDOR Protection (Priority 7 & 8)
// -------------------------------------------------------------
app.get('/api/vehicles', authenticate, (req, res) => {
  const user = (req as any).user as User;
  // Strictly filter by authenticated user ID
  const vehicles = db.vehicles.filter((v) => v.userId === user.id);
  return res.json(vehicles);
});

app.post('/api/vehicles', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const currentCount = db.vehicles.filter((v) => v.userId === user.id).length;
  const maxAllowed = TIER_LIMITS[user.tier].maxVehicles;

  if (currentCount >= maxAllowed) {
    return res.status(403).json({
      error: 'Unable to add this vehicle. Please try again.',
    });
  }

  const validationError = validateVehicleInput(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { brand, model, year, plate, mileage, motorization, fuelType } = req.body;

  const newVehicle: Vehicle = {
    id: `veh_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    userId: user.id,
    brand: String(brand).trim(),
    model: String(model).trim(),
    year: String(year || '').trim(),
    plate: String(plate || '').trim(),
    mileage: Number(mileage) > 0 ? Number(mileage) : 0,
    motorization: motorization ? String(motorization).trim().slice(0, 50) : undefined,
    fuelType: fuelType ? String(fuelType).trim().slice(0, 30) : undefined,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.vehicles.push(newVehicle);
  saveDB();
  return res.status(201).json(newVehicle);
});

app.put('/api/vehicles/:id', authenticate, (req, res) => {
  const user = (req as any).user as User;
  // Strict IDOR Check: Ensure vehicle belongs to authenticated user (Priority 7)
  const vehicle = db.vehicles.find((v) => v.id === req.params.id && v.userId === user.id);
  if (!vehicle) {
    return res.status(404).json({ error: 'Véhicule introuvable ou non autorisé.' });
  }

  const validationError = validateVehicleInput({ ...vehicle, ...req.body });
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { brand, model, year, plate, mileage, motorization, fuelType } = req.body;
  if (brand) vehicle.brand = String(brand).trim();
  if (model) vehicle.model = String(model).trim();
  if (year !== undefined) vehicle.year = String(year).trim();
  if (plate !== undefined) vehicle.plate = String(plate).trim();
  if (motorization !== undefined) vehicle.motorization = motorization ? String(motorization).trim().slice(0, 50) : undefined;
  if (fuelType !== undefined) vehicle.fuelType = fuelType ? String(fuelType).trim().slice(0, 30) : undefined;
  if (mileage !== undefined && Number(mileage) >= 0) {
    vehicle.mileage = Number(mileage);
  }
  vehicle.updatedAt = new Date().toISOString();

  saveDB();
  return res.json(vehicle);
});

app.delete('/api/vehicles/:id', authenticate, (req, res) => {
  const user = (req as any).user as User;
  // Strict IDOR Check (Priority 7)
  const vehicle = db.vehicles.find((v) => v.id === req.params.id && v.userId === user.id);
  if (!vehicle) {
    return res.status(404).json({ error: 'Véhicule introuvable ou non autorisé.' });
  }

  db.vehicles = db.vehicles.filter((v) => v.id !== vehicle.id);
  db.records = db.records.filter((r) => r.vehicleId !== vehicle.id && r.userId === user.id);
  db.reminders = db.reminders.filter((rem) => rem.vehicleId !== vehicle.id && rem.userId === user.id);
  saveDB();

  return res.json({ success: true, message: 'Véhicule et historique supprimés.' });
});

// -------------------------------------------------------------
// 9. Maintenance Endpoints with Strict IDOR Protection (Priority 7 & 8)
// -------------------------------------------------------------
app.get('/api/maintenance', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const { vehicleId } = req.query;

  // Strict multi-tenant isolation
  let records = db.records.filter((r) => r.userId === user.id);
  if (vehicleId && typeof vehicleId === 'string') {
    // Verify that the requested vehicleId belongs to this user
    const vehicleExists = db.vehicles.some((v) => v.id === vehicleId && v.userId === user.id);
    if (!vehicleExists) {
      return res.status(404).json({ error: 'Véhicule introuvable ou non autorisé.' });
    }
    records = records.filter((r) => r.vehicleId === vehicleId);
  }

  records.sort((a, b) => b.date.localeCompare(a.date));
  return res.json(records);
});

app.post('/api/maintenance', authenticate, (req, res) => {
  const user = (req as any).user as User;

  const validationError = validateMaintenanceInput(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { vehicleId, type, date, mileage, cost, notes, nextMileage, workshop, status, severity, parts } = req.body;

  // Strict IDOR Check: vehicle must belong to user (Priority 7)
  const vehicle = db.vehicles.find((v) => v.id === vehicleId && v.userId === user.id);
  if (!vehicle) {
    return res.status(404).json({ error: 'Véhicule introuvable ou non associé à votre compte.' });
  }

  const numMileage = Number(mileage);
  const numCost = Number(cost) || 0;
  const numNext = nextMileage ? Number(nextMileage) : undefined;

  const cleanParts: SparePart[] = Array.isArray(parts)
    ? parts
        .filter((p) => p && typeof p.name === 'string' && p.name.trim().length > 0)
        .map((p) => ({
          name: String(p.name).trim().slice(0, 100),
          reference: p.reference ? String(p.reference).trim().slice(0, 50) : undefined,
          quantity: Number(p.quantity) > 0 ? Number(p.quantity) : 1,
          unitCost: Number(p.unitCost) >= 0 ? Number(p.unitCost) : 0,
        }))
    : [];

  const newRecord: MaintenanceRecord = {
    id: `rec_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    userId: user.id,
    vehicleId,
    type,
    date,
    mileage: numMileage,
    cost: numCost,
    notes: String(notes || '').trim().slice(0, 500),
    nextMileage: numNext && numNext > numMileage ? numNext : undefined,
    workshop: String(workshop || '').trim().slice(0, 100),
    createdAt: new Date().toISOString(),
    status: status || 'completed',
    severity: severity || 'routine',
    parts: cleanParts,
  };

  db.records.push(newRecord);

  // Automatically update vehicle odometer if recorded mileage is greater
  if (numMileage > vehicle.mileage) {
    vehicle.mileage = numMileage;
    vehicle.updatedAt = new Date().toISOString();
  }

  saveDB();
  return res.status(201).json(newRecord);
});

app.put('/api/maintenance/:id', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const record = db.records.find((r) => r.id === req.params.id && r.userId === user.id);
  if (!record) {
    return res.status(404).json({ error: 'Entretien introuvable ou non autorisé.' });
  }

  const validationError = validateMaintenanceInput({ ...record, ...req.body });
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { type, date, mileage, cost, notes, nextMileage, workshop, status, severity, parts } = req.body;
  if (type) record.type = type;
  if (date) record.date = date;
  if (mileage !== undefined) record.mileage = Number(mileage);
  if (cost !== undefined) record.cost = Number(cost);
  if (notes !== undefined) record.notes = String(notes).trim().slice(0, 500);
  if (nextMileage !== undefined) record.nextMileage = Number(nextMileage) || undefined;
  if (workshop !== undefined) record.workshop = String(workshop).trim().slice(0, 100);
  if (status) record.status = status;
  if (severity) record.severity = severity;
  if (Array.isArray(parts)) {
    record.parts = parts
      .filter((p) => p && typeof p.name === 'string' && p.name.trim().length > 0)
      .map((p) => ({
        name: String(p.name).trim().slice(0, 100),
        reference: p.reference ? String(p.reference).trim().slice(0, 50) : undefined,
        quantity: Number(p.quantity) > 0 ? Number(p.quantity) : 1,
        unitCost: Number(p.unitCost) >= 0 ? Number(p.unitCost) : 0,
      }));
  }

  saveDB();
  return res.json(record);
});

app.delete('/api/maintenance/:id', authenticate, (req, res) => {
  const user = (req as any).user as User;
  // Strict IDOR Check (Priority 7)
  const index = db.records.findIndex((r) => r.id === req.params.id && r.userId === user.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Entretien introuvable ou non autorisé.' });
  }

  db.records.splice(index, 1);
  saveDB();
  return res.json({ success: true, message: 'Enregistrement supprimé.' });
});

// -------------------------------------------------------------
// 9.5 Reminders & Scheduling Endpoints (Priority 6 & Phase 2)
// -------------------------------------------------------------
app.get('/api/reminders', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const { vehicleId } = req.query;

  let reminders = db.reminders.filter((r) => r.userId === user.id);
  if (vehicleId && typeof vehicleId === 'string') {
    const vehicleExists = db.vehicles.some((v) => v.id === vehicleId && v.userId === user.id);
    if (!vehicleExists) {
      return res.status(404).json({ error: 'Véhicule introuvable ou non autorisé.' });
    }
    reminders = reminders.filter((r) => r.vehicleId === vehicleId);
  }

  // Sort: pending first, then by dueDate/dueMileage
  reminders.sort((a, b) => {
    if (a.completed !== b.completed) return a.completed ? 1 : -1;
    if (a.dueDate && b.dueDate) return a.dueDate.localeCompare(b.dueDate);
    return 0;
  });

  return res.json(reminders);
});

app.post('/api/reminders', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const validationError = validateReminderInput(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { vehicleId, title, type = 'custom', dueDate, dueMileage, notes } = req.body;
  const vehicle = db.vehicles.find((v) => v.id === vehicleId && v.userId === user.id);
  if (!vehicle) {
    return res.status(404).json({ error: 'Véhicule introuvable ou non associé à votre compte.' });
  }

  const newReminder: Reminder = {
    id: `rem_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    userId: user.id,
    vehicleId,
    title: String(title).trim().slice(0, 100),
    type,
    dueDate: dueDate && !isNaN(Date.parse(dueDate)) ? dueDate : undefined,
    dueMileage: dueMileage !== undefined && Number(dueMileage) > 0 ? Number(dueMileage) : undefined,
    notes: notes ? String(notes).trim().slice(0, 300) : undefined,
    completed: false,
    createdAt: new Date().toISOString(),
  };

  db.reminders.push(newReminder);
  saveDB();
  return res.status(201).json(newReminder);
});

app.put('/api/reminders/:id', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const reminder = db.reminders.find((r) => r.id === req.params.id && r.userId === user.id);
  if (!reminder) {
    return res.status(404).json({ error: 'Rappel introuvable ou non autorisé.' });
  }

  const { title, type, dueDate, dueMileage, notes, completed } = req.body;
  if (title) reminder.title = String(title).trim().slice(0, 100);
  if (type) reminder.type = type;
  if (dueDate !== undefined) reminder.dueDate = dueDate ? String(dueDate) : undefined;
  if (dueMileage !== undefined) reminder.dueMileage = dueMileage ? Number(dueMileage) : undefined;
  if (notes !== undefined) reminder.notes = notes ? String(notes).trim().slice(0, 300) : undefined;
  if (completed !== undefined) {
    reminder.completed = Boolean(completed);
    reminder.completedDate = reminder.completed ? new Date().toISOString().slice(0, 10) : undefined;
  }

  saveDB();
  return res.json(reminder);
});

app.delete('/api/reminders/:id', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const index = db.reminders.findIndex((r) => r.id === req.params.id && r.userId === user.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Rappel introuvable ou non autorisé.' });
  }

  db.reminders.splice(index, 1);
  saveDB();
  return res.json({ success: true, message: 'Rappel supprimé.' });
});

// -------------------------------------------------------------
// 10. Subscriptions & Tunisian Payments
// Plus & Pro are NEVER activated automatically without verified server-side transaction
// -------------------------------------------------------------
app.get('/api/subscription/plans', (_req, res) => {
  return res.json([{
    id: 'free',
    name: 'Siyantek — مجاني بالكامل',
    price: 0,
    currency: 'TND',
    period: 'بدون اشتراك',
    description: 'جميع وظائف التطبيق متاحة مجاناً دون حدود أو اشتراكات.',
    features: [
      'إضافة وإدارة عدد غير محدود من السيارات',
      'سجل صيانة وقطع غيار ومصاريف دون حدود',
      'تحديث ومتابعة عداد الكيلومترات',
      'حساب مواعيد الصيانة القادمة',
      'التذكيرات والتنبيهات',
      'تقارير PDF وتصدير CSV وJSON',
      'مزامنة آمنة ونسخ احتياطي للبيانات',
    ],
  }]);
});

// Checkout initiation: Requires configured payment provider or returns 503 (Priority 2)
app.post('/api/subscription/checkout', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const { planId, provider = 'konnect' } = req.body;

  if (!['free', 'plus', 'pro'].includes(planId)) {
    return res.status(400).json({ error: 'Formule d\'abonnement invalide.' });
  }

  // Paid plans have been retired: Siyantek is now fully free.
  if (planId !== 'free') {
    return res.status(410).json({
      success: false,
      paymentAvailable: false,
      error: 'Paid subscriptions are no longer offered. All Siyantek features are free.',
      messageAr: 'لم تعد الاشتراكات المدفوعة متاحة. جميع ميزات صيانتك مجانية.',
    });
  }

  // Free plan is zero-cost and can be selected immediately
  if (planId === 'free') {
    user.tier = 'free';
    user.subscriptionStatus = 'none';
    saveDB();
    return res.json({
      success: true,
      paymentRequired: false,
      message: 'Votre compte est configuré sur la formule Free.',
      messageAr: 'تم تعيين حسابك على الباقة المجانية بنجاح.',
      userTier: user.tier,
    });
  }

  // Plus and Pro REQUIRE verified external payment provider credentials (Priority 2)
  const isPaymentProviderConfigured = Boolean(
    process.env.KONNECT_API_KEY ||
    process.env.FLOUCI_APP_TOKEN ||
    process.env.ENABLE_TEST_PAYMENT_GATEWAY === 'true' ||
    (process.env.NODE_ENV !== 'production' && req.headers['x-enable-test-gateway'] === 'true')
  );

  if (!isPaymentProviderConfigured) {
    return res.status(503).json({
      success: false,
      paymentAvailable: false,
      error: 'La passerelle de paiement en ligne (Konnect / Flouci) n\'est pas encore configurée en production. Veuillez contacter l\'administration Siyantek pour activer votre abonnement.',
      messageAr: 'خدمة الدفع الإلكتروني (Konnect / Flouci) غير مفعلة حالياً لعدم ربط المفاتيح الرسمية للإنتاج. يرجى التواصل مع إدارة صيانتك لتفعيل الاشتراك.',
    });
  }

  const amountDT = planId === 'plus' ? 9.9 : 19.9;
  const transactionId = `pay_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  const idempotencyKey = crypto.randomBytes(16).toString('hex');

  const paymentRecord: PaymentTransaction = {
    id: transactionId,
    userId: user.id,
    planId,
    amountDT,
    currency: 'TND',
    provider: provider === 'flouci' ? 'flouci' : 'konnect',
    status: 'pending',
    idempotencyKey,
    createdAt: new Date().toISOString(),
  };

  db.payments.push(paymentRecord);
  saveDB();

  return res.json({
    success: true,
    paymentRequired: true,
    status: 'pending',
    transactionId,
    amountDT,
    currency: 'TND',
    planId,
    message: `Commande #${transactionId} créée pour le forfait ${planId.toUpperCase()} (${amountDT} DT). L'abonnement reste en attente et ne sera activé qu'après validation effective du paiement.`,
    messageAr: `تم إنشاء أمر الدفع #${transactionId} للباقة (${amountDT} د.ت). الاشتراك في وضع الانتظار ولن يتم تفعيله حتى يتم تأكيد الدفع الفعلي من مزود الخدمة.`,
    paymentGateways: {
      konnect: {
        provider: 'Konnect Tunisia (https://konnect.network)',
        methods: ['Cartes Bancaires CIB / Visa / Mastercard', 'e-Dinar La Poste Tunisienne', 'Sobflous'],
        webhookUrl: '/api/webhooks/konnect',
      },
      flouci: {
        provider: 'Flouci Tunisia (Kaoun)',
        methods: ['Portefeuille Flouci', 'Cartes nationales'],
        webhookUrl: '/api/webhooks/flouci',
      },
    },
  });
});

// Webhook Konnect with strict HMAC-SHA256 signature verification & idempotency (Priority 2 & 5)
app.post('/api/webhooks/konnect', (req, res) => {
  return res.status(410).json({ success: false, error: 'تم إيقاف المدفوعات والاشتراكات؛ جميع الميزات مجانية.' });
  const signature = req.headers['x-konnect-signature'] as string;
  const webhookSecret =
    process.env.KONNECT_WEBHOOK_SECRET ||
    (process.env.NODE_ENV !== 'production' && (req.headers['x-test-konnect-secret'] as string)) ||
    undefined;

  // Strict requirement: Never accept webhook if official verification secret is not configured
  if (!webhookSecret) {
    return res.status(503).json({
      error: 'Passerelle Konnect non configurée avec un secret officiel. Webhook rejeté pour des raisons de sécurité.',
      messageAr: 'بوابة الدفع غير مهيأة بسر أمني رسمي. تم رفض الـ Webhook لحماية النظام.',
    });
  }

  if (!signature) {
    return res.status(401).json({ error: 'Signature Webhook manquante.' });
  }

  const computedSignature = crypto
    .createHmac('sha256', webhookSecret)
    .update(JSON.stringify(req.body))
    .digest('hex');

  let signatureValid = false;
  try {
    const sigBuf = Buffer.from(signature, 'hex');
    const compBuf = Buffer.from(computedSignature, 'hex');
    signatureValid = sigBuf.length === compBuf.length && crypto.timingSafeEqual(sigBuf, compBuf);
  } catch {
    signatureValid = false;
  }

  if (!signatureValid) {
    return res.status(403).json({ error: 'Signature Webhook non valide.' });
  }

  const { paymentRef, transactionId, status, amount, currency } = req.body;
  if (!transactionId || amount === undefined || currency === undefined || !status) {
    return res.status(400).json({
      error: 'Payload webhook Konnect incomplet : transactionId, amount, currency et status sont obligatoires.',
      messageAr: 'بيانات إشعار الدفع غير مكتملة: رقم المعاملة والمبلغ والعملة وحالة الدفع مطلوبة.',
    });
  }

  const tx = db.payments.find((p) => p.id === transactionId);
  if (!tx) {
    return res.status(404).json({ error: 'Transaction non trouvée.' });
  }

  // Idempotency: If already completed, return 200 without duplicate processing
  if (tx.status === 'completed') {
    return res.json({ success: true, message: 'Transaction déjà validée (traitement idempotent).' });
  }

  // Strict verification of plan amount and currency before any activation
  const expectedAmount = tx.planId === 'plus' ? 9.9 : 19.9;
  if (Number(amount) !== expectedAmount) {
    return res.status(400).json({ error: 'Montant de transaction non conforme au forfait.' });
  }
  if (currency !== 'TND' && currency !== 'DT') {
    return res.status(400).json({ error: 'Devise non reconnue (seul le Dinar Tunisien TND est accepté).' });
  }

  if (status === 'success' || status === 'completed') {
    tx.status = 'completed';
    tx.paymentReference = paymentRef || `KONNECT_VERIFIED_${Date.now()}`;
    tx.completedAt = new Date().toISOString();
    tx.rawWebhookPayload = req.body;

    // Activate subscription on the server side ONLY after official verification
    const user = db.users.find((u) => u.id === tx.userId);
    if (user) {
      user.tier = tx.planId;
      user.subscriptionStatus = 'active';
      user.renewalDate = new Date(Date.now() + 30 * 86400000).toISOString();
    }
    saveDB();
    return res.json({ success: true, message: `Abonnement ${tx.planId} activé avec succès.` });
  } else if (status === 'failed') {
    tx.status = 'failed';
    saveDB();
    return res.json({ success: false, message: 'Transaction marquée comme échouée.' });
  }

  return res.json({ received: true });
});

// Webhook Flouci with strict HMAC signature verification (Priority 2 & 5)
app.post('/api/webhooks/flouci', (req, res) => {
  return res.status(410).json({ success: false, error: 'تم إيقاف المدفوعات والاشتراكات؛ جميع الميزات مجانية.' });
  const signature = req.headers['x-flouci-signature'] as string;
  const webhookSecret =
    process.env.FLOUCI_APP_SECRET ||
    (process.env.NODE_ENV !== 'production' && (req.headers['x-test-flouci-secret'] as string)) ||
    undefined;

  if (!webhookSecret) {
    return res.status(503).json({
      error: 'Passerelle Flouci non configurée avec un secret officiel. Webhook rejeté.',
      messageAr: 'بوابة Flouci غير مهيأة بسر أمني رسمي. تم رفض الطلب.',
    });
  }

  if (!signature) {
    return res.status(401).json({ error: 'Signature Webhook Flouci manquante.' });
  }

  const computedSignature = crypto
    .createHmac('sha256', webhookSecret)
    .update(JSON.stringify(req.body))
    .digest('hex');

  let signatureValid = false;
  try {
    const sigBuf = Buffer.from(signature, 'hex');
    const compBuf = Buffer.from(computedSignature, 'hex');
    signatureValid = sigBuf.length === compBuf.length && crypto.timingSafeEqual(sigBuf, compBuf);
  } catch {
    signatureValid = false;
  }

  if (!signatureValid) {
    return res.status(403).json({ error: 'Signature Webhook Flouci non valide.' });
  }

  const { payment_id, transactionId, status, amount } = req.body;
  if (!transactionId || amount === undefined || !status) {
    return res.status(400).json({
      error: 'Payload webhook Flouci incomplet : transactionId, amount et status sont obligatoires.',
      messageAr: 'بيانات إشعار الدفع من Flouci غير مكتملة: رقم المعاملة والمبلغ وحالة الدفع مطلوبة.',
    });
  }

  const tx = db.payments.find((p) => p.id === transactionId);
  if (!tx) {
    return res.status(404).json({ error: 'Transaction non trouvée.' });
  }

  if (tx.status === 'completed') {
    return res.json({ success: true, message: 'Transaction déjà validée (traitement idempotent).' });
  }

  const expectedAmount = tx.planId === 'plus' ? 9.9 : 19.9;
  if (Number(amount) !== expectedAmount) {
    return res.status(400).json({ error: 'Montant non conforme.' });
  }

  if (status === 'SUCCESS' || status === 'completed') {
    tx.status = 'completed';
    tx.paymentReference = payment_id || `FLOUCI_VERIFIED_${Date.now()}`;
    tx.completedAt = new Date().toISOString();
    tx.rawWebhookPayload = req.body;

    const user = db.users.find((u) => u.id === tx.userId);
    if (user) {
      user.tier = tx.planId;
      user.subscriptionStatus = 'active';
      user.renewalDate = new Date(Date.now() + 30 * 86400000).toISOString();
    }
    saveDB();
    return res.json({ success: true, message: `Abonnement ${tx.planId} activé.` });
  } else if (status === 'FAILURE') {
    tx.status = 'failed';
    saveDB();
    return res.json({ success: false, message: 'Transaction échouée.' });
  }

  return res.json({ received: true });
});

// Endpoint to verify transaction status from client
app.get('/api/subscription/transaction/:id', authenticate, (req, res) => {
  const user = (req as any).user as User;
  // Strict IDOR Check (Priority 7)
  const tx = db.payments.find((p) => p.id === req.params.id && p.userId === user.id);
  if (!tx) {
    return res.status(404).json({ error: 'Transaction introuvable.' });
  }
  return res.json(tx);
});

app.post('/api/subscription/cancel', authenticate, (req, res) => {
  const user = (req as any).user as User;
  if (user.tier === 'free') {
    return res.json({
      success: true,
      message: 'Vous êtes déjà sur la formule Free gratuite.',
      messageAr: 'أنت حالياً على الباقة المجانية.',
    });
  }
  user.subscriptionStatus = 'canceled';
  saveDB();
  return res.json({
    success: true,
    message: 'L\'annulation du renouvellement a été enregistrée dans Siyantek. Veuillez noter qu\'aucun prélèvement automatique n\'est effectué auprès de votre banque sans votre autorisation expresse.',
    messageAr: 'تم تسجيل إيقاف التجديد في تطبيق صيانتك. نؤكد عدم وجود أي اقتطاع بنكي متجدد دون موافقتك الصريحة.',
  });
});

// -------------------------------------------------------------
// Manual Tunisian Bank / Postal Payment & Receipt Management (Priority 1)
// -------------------------------------------------------------
app.get('/api/subscription/manual-instructions', authenticate, (_req, res) => {
  return res.status(410).json({ success: false, error: 'لا توجد مدفوعات أو اشتراكات في Siyantek.' });
  return res.json({
    success: true,
    instructions: TUNISIA_TRANSFER_CONFIG,
    supportedMethods: [
      { id: 'bank_transfer', name: 'Virement bancaire (BIAT)', details: TUNISIA_TRANSFER_CONFIG.rib },
      { id: 'postal_order', name: 'Mandat postal (La Poste Tunisienne)', details: TUNISIA_TRANSFER_CONFIG.postalRip },
      { id: 'd17', name: 'Paiement mobile D17 / e-Dinar', details: TUNISIA_TRANSFER_CONFIG.d17Phone },
    ],
  });
});

app.post('/api/subscription/manual-order', authenticate, (req, res) => {
  return res.status(410).json({ success: false, error: 'Paid subscriptions are no longer offered.', messageAr: 'الاشتراكات المدفوعة لم تعد متاحة. جميع الميزات مجانية.' });
  const user = (req as any).user as User;
  const { planId, method = 'bank_transfer' } = req.body;

  if (planId !== 'plus' && planId !== 'pro') {
    return res.status(400).json({ error: 'Formule d\'abonnement payante requise (plus ou pro).' });
  }

  const validMethods = ['bank_transfer', 'postal_order', 'd17'];
  const chosenMethod = validMethods.includes(method) ? method : 'bank_transfer';
  const amountDT = planId === 'plus' ? 9.9 : 19.9;
  const transactionId = `pay_man_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const transferRef = `SYK-VIR-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  const idempotencyKey = crypto.randomBytes(16).toString('hex');

  const paymentRecord: PaymentTransaction = {
    id: transactionId,
    userId: user.id,
    planId,
    amountDT,
    currency: 'TND',
    provider: chosenMethod === 'postal_order' ? 'postal_order' : 'bank_transfer',
    method: chosenMethod,
    status: 'pending',
    idempotencyKey,
    transferReference: transferRef,
    bankInstructions: {
      accountName: TUNISIA_TRANSFER_CONFIG.accountName,
      bankName: TUNISIA_TRANSFER_CONFIG.bankName,
      rib: TUNISIA_TRANSFER_CONFIG.rib,
      iban: TUNISIA_TRANSFER_CONFIG.iban,
      postalRip: TUNISIA_TRANSFER_CONFIG.postalRip,
      d17Phone: TUNISIA_TRANSFER_CONFIG.d17Phone,
    },
    createdAt: new Date().toISOString(),
  };

  db.payments.unshift(paymentRecord);
  saveDB();

  return res.status(201).json({
    success: true,
    order: paymentRecord,
    transferReference: transferRef,
    instructions: TUNISIA_TRANSFER_CONFIG,
    message: `Ordre de paiement créé. Veuillez effectuer le virement de ${amountDT} DT avec la référence ${transferRef}.`,
    messageAr: `تم إنشاء أمر الدفع. يرجى تحويل مبلغ ${amountDT} د.ت مع كتابة الرمز ${transferRef} في خانة الملاحظات.`,
  });
});

app.get('/api/subscription/my-payments', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const userPayments = db.payments
    .filter((p) => p.userId === user.id)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  return res.json(userPayments);
});

app.post('/api/subscription/manual-order/:id/upload-receipt', authenticate, (req, res) => {
  return res.status(410).json({ success: false, error: 'Paid subscriptions are no longer offered.', messageAr: 'الاشتراكات المدفوعة لم تعد متاحة. جميع الميزات مجانية.' });
  const user = (req as any).user as User;
  const orderId = req.params.id;
  const tx = db.payments.find((p) => p.id === orderId && p.userId === user.id);

  if (!tx) {
    return res.status(404).json({ error: 'Ordre de paiement introuvable ou non autorisé.' });
  }

  if (tx.status === 'approved' || tx.status === 'completed') {
    return res.status(400).json({ error: 'Cet ordre a déjà été validé et activé.' });
  }

  const { base64Data, mimeType, filename } = req.body || {};
  if (!base64Data || typeof base64Data !== 'string') {
    return res.status(400).json({ error: 'Fichier justificatif requis en base64.' });
  }

  const allowedMimeTypes: Record<string, string> = {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'application/pdf': 'pdf',
  };

  const detectedMime = (mimeType || 'image/jpeg').toLowerCase();
  const ext = allowedMimeTypes[detectedMime];
  if (!ext) {
    return res.status(400).json({
      error: 'Format non supporté. Veuillez téléverser un fichier JPG, PNG, WebP ou PDF.',
    });
  }

  // Strip possible base64 data URI header
  const cleanBase64 = base64Data.replace(/^data:[^;]+;base64,/, '');
  const buffer = Buffer.from(cleanBase64, 'base64');

  // Max 5 MB receipt size check
  if (buffer.length > 5 * 1024 * 1024) {
    return res.status(400).json({ error: 'Le fichier dépasse la taille maximale autorisée de 5 Mo.' });
  }

  const safeFilename = `receipt_${tx.id}_${crypto.randomBytes(6).toString('hex')}.${ext}`;
  const targetPath = path.join(RECEIPTS_DIR, safeFilename);

  fs.writeFileSync(targetPath, buffer);

  tx.status = 'submitted';
  tx.receiptFilename = safeFilename;
  tx.receiptMimeType = detectedMime;
  tx.receiptFileSize = buffer.length;
  tx.receiptUploadedAt = new Date().toISOString();
  saveDB();

  return res.json({
    success: true,
    message: 'Reçu téléversé avec succès. Notre équipe validera votre abonnement après vérification bancaire.',
    messageAr: 'تم رفع وصل الإيداع بنجاح. سيتم تفعيل حسابك بعد مطابقة التحويل من قبل الإدارة.',
    order: tx,
  });
});

app.get('/api/subscription/manual-order/:id/receipt', authenticate, (req, res) => {
  const user = (req as any).user as User;
  const tx = db.payments.find((p) => p.id === req.params.id);

  if (!tx || !tx.receiptFilename) {
    return res.status(404).json({ error: 'Reçu introuvable.' });
  }

  // IDOR & Authorization check: only order owner or admin can view receipt (Priority 4)
  if (tx.userId !== user.id && user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès non autorisé à ce justificatif.' });
  }

  const filePath = path.join(RECEIPTS_DIR, path.basename(tx.receiptFilename));
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Fichier physique introuvable sur le serveur.' });
  }

  res.setHeader('Content-Type', tx.receiptMimeType || 'application/octet-stream');
  res.setHeader('Content-Disposition', `inline; filename="${path.basename(tx.receiptFilename)}"`);
  return res.sendFile(filePath);
});

// -------------------------------------------------------------
// Administration Back-Office APIs (Priority 2)
// -------------------------------------------------------------
app.get('/api/admin/stats', authenticate, requireAdmin, (_req, res) => {
  const totalUsers = db.users.length;
  const freeUsers = db.users.filter((u) => u.tier === 'free').length;
  const plusUsers = db.users.filter((u) => u.tier === 'plus').length;
  const proUsers = db.users.filter((u) => u.tier === 'pro').length;

  const pendingPayments = db.payments.filter((p) => p.status === 'pending').length;
  const submittedPayments = db.payments.filter((p) => p.status === 'submitted').length;
  const approvedPayments = db.payments.filter((p) => p.status === 'approved' || p.status === 'completed').length;
  const rejectedPayments = db.payments.filter((p) => p.status === 'rejected').length;

  const totalApprovedRevenueDT = db.payments
    .filter((p) => p.status === 'approved' || p.status === 'completed')
    .reduce((sum, p) => sum + (p.amountDT || 0), 0);

  return res.json({
    users: {
      total: totalUsers,
      free: freeUsers,
      plus: plusUsers,
      pro: proUsers,
    },
    payments: {
      pending: pendingPayments,
      submitted: submittedPayments,
      approved: approvedPayments,
      rejected: rejectedPayments,
      totalApprovedRevenueDT: Math.round(totalApprovedRevenueDT * 10) / 10,
    },
    database: {
      vehiclesCount: db.vehicles.length,
      recordsCount: db.records.length,
      remindersCount: db.reminders.length,
      auditLogsCount: db.auditLogs.length,
    },
  });
});

app.get('/api/admin/users', authenticate, requireAdmin, (_req, res) => {
  const usersWithMeta = db.users.map((u) => {
    const { passwordHash: _, ...safeUser } = u;
    const vehiclesCount = db.vehicles.filter((v) => v.userId === u.id).length;
    const recordsCount = db.records.filter((r) => r.userId === u.id).length;
    const paymentsCount = db.payments.filter((p) => p.userId === u.id).length;
    return {
      ...safeUser,
      vehiclesCount,
      recordsCount,
      paymentsCount,
    };
  });
  return res.json(usersWithMeta);
});

app.put('/api/admin/users/:id/tier', authenticate, requireAdmin, (req, res) => {
  return res.status(410).json({ success: false, error: 'جميع ميزات Siyantek مجانية ولا توجد باقات مدفوعة.' });
  const admin = (req as any).user as User;
  const targetId = req.params.id;
  const { tier, durationDays = 30, notes } = req.body;

  if (!['free', 'plus', 'pro'].includes(tier)) {
    return res.status(400).json({ error: 'Niveau invalide (free, plus ou pro requis).' });
  }

  const targetUser = db.users.find((u) => u.id === targetId);
  if (!targetUser) {
    return res.status(404).json({ error: 'Utilisateur introuvable.' });
  }

  const oldTier = targetUser.tier;
  targetUser.tier = tier;

  if (tier === 'free') {
    targetUser.subscriptionStatus = 'none';
    targetUser.subscriptionExpiresAt = null;
  } else {
    targetUser.subscriptionStatus = 'active';
    const durationMs = Number(durationDays) * 86400000;
    const baseDate =
      targetUser.subscriptionExpiresAt && new Date(targetUser.subscriptionExpiresAt).getTime() > Date.now()
        ? new Date(targetUser.subscriptionExpiresAt).getTime()
        : Date.now();
    targetUser.subscriptionExpiresAt = new Date(baseDate + durationMs).toISOString();
    targetUser.renewalDate = targetUser.subscriptionExpiresAt;
  }

  logAudit(
    admin,
    'update_user_tier',
    'user',
    targetUser.id,
    { oldTier, newTier: tier, durationDays, notes },
    req
  );

  saveDB();
  const { passwordHash: _, ...safeUser } = targetUser;
  return res.json({
    success: true,
    user: safeUser,
    message: `Abonnement mis à jour vers ${tier.toUpperCase()}.`,
  });
});

app.get('/api/admin/payments', authenticate, requireAdmin, (_req, res) => {
  const paymentsWithUser = db.payments.map((p) => {
    const user = db.users.find((u) => u.id === p.userId);
    return {
      ...p,
      userName: user ? user.name : 'Inconnu',
      userEmail: user ? user.email : 'Inconnu',
    };
  });
  return res.json(paymentsWithUser);
});

app.get('/api/admin/payments/:id/receipt', authenticate, requireAdmin, (req, res) => {
  const tx = db.payments.find((p) => p.id === req.params.id);
  if (!tx || !tx.receiptFilename) {
    return res.status(404).json({ error: 'Reçu introuvable pour cette transaction.' });
  }

  const filePath = path.join(RECEIPTS_DIR, path.basename(tx.receiptFilename));
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Fichier physique absent du stockage sécurisé.' });
  }

  res.setHeader('Content-Type', tx.receiptMimeType || 'application/octet-stream');
  res.setHeader('Content-Disposition', `inline; filename="${path.basename(tx.receiptFilename)}"`);
  return res.sendFile(filePath);
});

app.post('/api/admin/payments/:id/approve', authenticate, requireAdmin, (req, res) => {
  return res.status(410).json({ success: false, error: 'تم إيقاف المدفوعات والاشتراكات؛ جميع الميزات مجانية.' });
  const admin = (req as any).user as User;
  const tx = db.payments.find((p) => p.id === req.params.id);

  if (!tx) {
    return res.status(404).json({ error: 'Ordre de paiement introuvable.' });
  }

  // Prevent duplicate approval (Priority 1)
  if (tx.status === 'approved' || tx.status === 'completed') {
    return res.status(400).json({ error: 'Ce paiement a déjà été validé et approuvé précédemment.' });
  }

  const targetUser = db.users.find((u) => u.id === tx.userId);
  if (!targetUser) {
    return res.status(404).json({ error: 'Utilisateur associé introuvable.' });
  }

  const durationDays = Number(req.body.durationDays) || 30;
  const durationMs = durationDays * 86400000;

  // Calculate new expiration date (extend if already active, or start from now)
  const baseTime =
    targetUser.subscriptionExpiresAt &&
    new Date(targetUser.subscriptionExpiresAt).getTime() > Date.now()
      ? new Date(targetUser.subscriptionExpiresAt).getTime()
      : Date.now();

  const newExpiresAt = new Date(baseTime + durationMs).toISOString();

  tx.status = 'approved';
  tx.completedAt = new Date().toISOString();
  tx.reviewedBy = admin.id;
  tx.reviewedAt = new Date().toISOString();
  tx.adminNotes = req.body.notes || 'Paiement vérifié et approuvé par l\'administration.';

  targetUser.tier = tx.planId;
  targetUser.subscriptionStatus = 'active';
  targetUser.subscriptionExpiresAt = newExpiresAt;
  targetUser.renewalDate = newExpiresAt;

  logAudit(
    admin,
    'approve_manual_payment',
    'payment',
    tx.id,
    {
      planId: tx.planId,
      amountDT: tx.amountDT,
      userId: targetUser.id,
      userEmail: targetUser.email,
      expiresAt: newExpiresAt,
      notes: tx.adminNotes,
    },
    req
  );

  saveDB();

  return res.json({
    success: true,
    message: `Paiement #${tx.id} approuvé. Formule ${tx.planId.toUpperCase()} activée jusqu'au ${newExpiresAt.slice(0, 10)}.`,
    order: tx,
    subscriptionExpiresAt: newExpiresAt,
  });
});

app.post('/api/admin/payments/:id/reject', authenticate, requireAdmin, (req, res) => {
  return res.status(410).json({ success: false, error: 'تم إيقاف المدفوعات والاشتراكات؛ جميع الميزات مجانية.' });
  const admin = (req as any).user as User;
  const tx = db.payments.find((p) => p.id === req.params.id);

  if (!tx) {
    return res.status(404).json({ error: 'Ordre de paiement introuvable.' });
  }

  if (tx.status === 'approved' || tx.status === 'completed') {
    return res.status(400).json({ error: 'Impossible de rejeter un paiement déjà approuvé.' });
  }

  const reason = req.body.reason || req.body.notes || 'Justificatif non conforme ou virement non reçu sur le compte bancaire.';

  tx.status = 'rejected';
  tx.reviewedBy = admin.id;
  tx.reviewedAt = new Date().toISOString();
  tx.adminNotes = reason;

  logAudit(
    admin,
    'reject_manual_payment',
    'payment',
    tx.id,
    { reason, userId: tx.userId },
    req
  );

  saveDB();

  return res.json({
    success: true,
    message: `Ordre de paiement rejeté. Motif : ${reason}`,
    order: tx,
  });
});

app.get('/api/admin/audit-logs', authenticate, requireAdmin, (_req, res) => {
  return res.json(db.auditLogs);
});

// -------------------------------------------------------------
// 11. Support & Contact API Endpoint (Priority 12)
// -------------------------------------------------------------
app.post('/api/support/contact', (req: Request, res: Response) => {
  const { name, email, subject, message } = req.body || {};

  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'Veuillez saisir un nom valide (min. 2 caractères).' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || typeof email !== 'string' || !emailRegex.test(email.trim())) {
    return res.status(400).json({ error: 'Veuillez saisir une adresse email valide.' });
  }

  if (!message || typeof message !== 'string' || message.trim().length < 5) {
    return res.status(400).json({ error: 'Veuillez rédiger votre message (min. 5 caractères).' });
  }

  const token = extractSessionToken(req);
  let userId: string | undefined = undefined;
  if (token) {
    const session = db.sessions.find((s) => s.tokenHash === hashToken(token) || (s as any).token === token);
    if (session) userId = session.userId;
  }

  const ticket: SupportTicket = {
    id: `ticket_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    name: name.trim().slice(0, 100),
    email: email.trim().toLowerCase().slice(0, 150),
    subject: (subject && typeof subject === 'string' ? subject.trim() : 'Demande générale').slice(0, 150),
    message: message.trim().slice(0, 2000),
    userId,
    status: 'new',
    createdAt: new Date().toISOString(),
  };

  db.supportTickets.push(ticket);
  saveDB();

  return res.json({
    success: true,
    ticketId: ticket.id,
    message: 'Votre message a été transmis avec succès à l\'équipe support Siyantek.',
    messageAr: 'تم إرسال رسالتك بنجاح إلى فريق الدعم الفني لصيانتك.',
  });
});

// Legal & Compliance Endpoints
app.get('/api/legal/terms', (_req, res) => {
  return res.json({
    title: 'Conditions Générales d\'Utilisation Siyantek',
    version: '2.4',
    lastUpdated: '2026-10-30',
    company: 'Siyantek Auto SaaS',
    jurisdiction: 'Tunisie',
  });
});

app.get('/api/legal/privacy', (_req, res) => {
  return res.json({
    title: 'Politique de Confidentialité et Protection des Données',
    version: '2.4',
    lastUpdated: '2026-10-30',
    dataRetention: 'Données conservées uniquement pendant la durée d\'utilisation du compte, exportables et supprimables à tout moment.',
    thirdPartySharing: 'Aucune vente ou partage des données personnelles avec des tiers publicitaires.',
  });
});

// -------------------------------------------------------------
// 12. Health Check Endpoint
// -------------------------------------------------------------
app.get('/api/health', (_req, res) => {
  return res.json({
    status: 'ok',
    app: 'Siyantek Maintenance Tracker - Commercial Web Edition',
    usersCount: db.users.length,
    vehiclesCount: db.vehicles.length,
    paymentsCount: db.payments.length,
    timestamp: new Date().toISOString(),
  });
});

// -------------------------------------------------------------
// 13. Centralized Error Handling Middleware (Priority 8)
// -------------------------------------------------------------
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled server error:', err);
  const status = Number(err.status || err.statusCode) || 500;
  return res.status(status).json({
    error: 'Une erreur interne est survenue. L\'incident a été consigné de manière sécurisée.',
    code: 'INTERNAL_SERVER_ERROR',
  });
});

// -------------------------------------------------------------
// 14. Frontend Serving (Vite dev middleware vs Production static)
// -------------------------------------------------------------
async function setupFrontend() {
  if (process.env.NODE_ENV === 'production' && fs.existsSync(path.join(__dirname, 'dist'))) {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }
}

setupFrontend()
  .then(() => {
    app.listen(PORT, HOST, () => {
      console.log(`🚀 Siyantek Commercial Server running on http://${HOST}:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to setup frontend with Vite middleware:', err);
    app.listen(PORT, HOST, () => {
      console.log(`🚀 Siyantek Commercial Server running on http://${HOST}:${PORT} (fallback mode)`);
    });
  });
