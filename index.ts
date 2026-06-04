import pkg from 'pg';
import cors from 'cors';
import express, { type Response, type Request } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// tipo personalizado
// elimina errores de typescript
declare module 'express-serve-static-core' {
  interface Request {
    user?: { id: number; roles: string[] };
  }
}

// Desde este secreto generamos los tokens
// para que los usuarios puedan iniciar sesión
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';

// revisa si la petición está hecha por un usuario
// que ha iniciado sesión
const authenticate = (req: Request, res: Response, next: any) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'No token provided ' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { id: number, roles: string[] };
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// revisa si el usuario que inició sesión tiene
// rol de admin
const requireAdmin = (req: Request, res: Response, next: any) => {
  if (!req.user || !req.user.roles.includes('admin')) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  next();
};

const { Pool } = pkg;
const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// API POST para registrarse
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // calcula el hash de la contraseña
    // para guardar el hash y no la contraseña en caso
    // de ataques
    const hash = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      `INSERT INTO users (name, email, hash) VALUES ($1, $2, $3) RETURNING id`,
      [name, email, hash]
    );
    const userId = userResult.rows[0].id;

    // se le asigna el rol de "player" (jugador) al usuario nuevo
    const roleResult = await pool.query(`SELECT id FROM roles WHERE name = 'player'`);
    const roleId = roleResult.rows[0].id;

    await pool.query(
      `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
      [userId, roleId]
    );

    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed. Email might already exist.' });
  }
});

// API POST para iniciar sesión
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // query para obtener info del usuario
    const userResult = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    // si no existe, responder con codigo 400 + mensaje
    if (userResult.rows.length === 0) return res.status(400).json({ error: 'User not found' });

    const user = userResult.rows[0];

    // comparar el hash de la contraseña con el hash guardado
    const isValid = await bcrypt.compare(password, user.hash);

    // si no es válido, responder con error 400
    if (!isValid) return res.status(400).json({ error: 'Invalid password' });

    // query para obtener los roles del usuario
    const rolesResult = await pool.query(`
      SELECT r.name FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = $1
    `, [user.id]);

    // crear lista de roles
    const roles = rolesResult.rows.map((row: any) => row.name);

    // firmar la información del usuario + roles con el secreto
    // se le asigna una duración de 7 días
    const token = jwt.sign({ id: user.id, roles }, JWT_SECRET, { expiresIn: '7d' })

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, roles } });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// API GET para obtener la lista de canchas
app.get('/api/fields', async (_, res) => {
  try {
    const query = `
      SELECT
        f.id,
        f.owner_id AS "ownerId",
        u.name AS "ownerName",
        f.name,
        f.location,
        CAST(f.latitude AS FLOAT),
        CAST(f.longitude AS FLOAT),
        f.surface,
        f.price,
        f.image,
        CAST(f.rating AS FLOAT),
        f.capacity
      FROM fields f
      JOIN users u ON f.owner_id = u.id
    `;

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error fetching fields' });
  }
});


// API POST para obtener reservas de un usuario loggeado
app.post('/api/reservations', authenticate, async (req, res) => {
  try {
    const { fieldId, date, hour, price } = req.body;

    const playerId = req.user!.id;

    const result = await pool.query(`
      INSERT INTO reservations (field_id, player_id, date, hour, price, status)
      VALUES ($1, $2, $3, $4, $5, 'confirmed') RETURNING *
    `, [fieldId, playerId, date, hour, price]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create reservation' });
  }
});

// API POST para crear canchas de futbol
// se necesita rol de admin
app.post('/api/fields', authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, location, latitude, longitude, surface, price, image, rating, capacity } = req.body;

    const ownerId = req.user!.id;

    const result = await pool.query(`
      INSERT INTO fields
      (owner_id, name, location, latitude, longitude, surface, price, image, rating, capacity)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *
    `, [ownerId, name, location, latitude, longitude, surface, price, image, rating, capacity]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create field' });
  }
});

app.get('/api/reservations', async (req, res) => {
  try {
    const query = `

      SELECT 
        r.id, 
        r.field_id AS "fieldId", 
        f.name AS "fieldName",
        r.player_id AS "playerId", 
        u.name AS "playerName", 
        TO_CHAR(r.date, 'YYYY-MM-DD') AS date, 
        TO_CHAR(r.hour, 'HH24:MI') AS hour, 
        r.price, 
        r.status
      FROM reservations r
      JOIN users u ON r.player_id = u.id
      JOIN fields f ON r.field_id = f.id
      ORDER BY r.date DESC, r.hour ASC
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error fetching reservations' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Furbito API backend running at port ${PORT}`);
});
