import pkg from 'pg';
import cors from 'cors';
import express, { type Response, type Request } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

declare module 'express-serve-static-core' {
  interface Request {
    user?: { id: number; roles: string[] };
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';

const authenticate = (req: Request, res: Response, next: any) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { id: number, roles: string[] };
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const requireAdmin = (req: Request, res: Response, next: any) => {
  // Asumiendo que el dueño de la cancha también necesita estos permisos
  if (!req.user || (!req.user.roles.includes('admin') && !req.user.roles.includes('owner'))) {
    return res.status(403).json({ error: 'Admin or Owner access required' });
  }
  next();
};

const { Pool } = pkg;
const app = express();

app.use(cors({
  origin: [
    "http://localhost:8080",
    "https://furbito.iknacx.dev",
  ],
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
}));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Horas por defecto para generar la disponibilidad
const HOURS = [
  "09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00",
  "16:00", "17:00", "18:00", "19:00", "20:00", "21:00", "22:00", "23:00",
];

// --- AUTH ---

app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    const hash = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      `INSERT INTO users (name, email, phone, hash) VALUES ($1, $2, $3, $4) RETURNING id`,
      [name, email, phone, hash]
    );
    const userId = userResult.rows[0].id;

    const roleResult = await pool.query(`SELECT id FROM roles WHERE name = 'player'`);
    const roleId = roleResult.rows[0].id;

    await pool.query(
      `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
      [userId, roleId]
    );

    res.status(201).json({ message: 'User created successfully' });
  } catch (err: any) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email or phone already exists.' });
    }
    res.status(500).json({ error: 'Signup failed.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userResult = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    
    if (userResult.rows.length === 0) return res.status(400).json({ error: 'User not found' });

    const user = userResult.rows[0];
    const isValid = await bcrypt.compare(password, user.hash);

    if (!isValid) return res.status(400).json({ error: 'Invalid password' });

    const rolesResult = await pool.query(`
      SELECT r.name FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = $1
    `, [user.id]);

    const roles = rolesResult.rows.map((row: any) => row.name);
    const token = jwt.sign({ id: user.id, roles }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, roles } });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// --- USUARIOS ---

app.patch('/api/users/me', authenticate, async (req: Request, res: Response) => {
  try {
    const userId = req.user!.id; 
    const { name, email, phone } = req.body;

    const updates: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (name !== undefined) { updates.push(`name = $${paramIndex++}`); values.push(name); }
    if (email !== undefined) { updates.push(`email = $${paramIndex++}`); values.push(email); }
    if (phone !== undefined) { updates.push(`phone = $${paramIndex++}`); values.push(phone); }

    if (updates.length === 0) return res.status(400).json({ error: 'No data provided to update' });
    values.push(userId);

    const query = `
      UPDATE users 
      SET ${updates.join(', ')} 
      WHERE id = $${paramIndex} 
      RETURNING id, name, email, phone
    `;

    const result = await pool.query(query, values);
    res.json(result.rows[0]);
  } catch (err: any) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(409).json({ error: 'The provided email or phone number is already registered.' });
    }
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});

// --- CANCHAS ---

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

app.post('/api/fields', authenticate, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); // Iniciar transacción

    const { name, location, latitude, longitude, surface, price, image, rating, capacity } = req.body;
    const ownerId = req.user!.id;

    // 1. Crear la cancha
    const fieldResult = await client.query(`
      INSERT INTO fields
      (owner_id, name, location, latitude, longitude, surface, price, image, rating, capacity)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *
    `, [ownerId, name, location, latitude, longitude, surface, price, image, rating, capacity]);

    const fieldId = fieldResult.rows[0].id;

    // 2. Generar horarios por defecto (Ej: Para los próximos 14 días)
    const today = new Date();
    
    for (let i = 0; i < 14; i++) {
      const currentDate = new Date(today);
      currentDate.setDate(today.getDate() + i);
      const dateString = currentDate.toISOString().split('T')[0];

      for (const startStr of HOURS) {
        // Calcular hora de término asumiendo bloques de 1 hora
        const startHour = parseInt(startStr.split(':')[0], 10);
        const endHour = startHour === 23 ? 0 : startHour + 1;
        const endStr = `${endHour.toString().padStart(2, '0')}:00`;

        await client.query(`
          INSERT INTO schedules (field_id, date, start_time, end_time, price, status)
          VALUES ($1, $2, $3, $4, $5, 'available')
        `, [fieldId, dateString, startStr, endStr, null]); 
        // price=null para que herede el de la cancha
      }
    }

    await client.query('COMMIT'); // Confirmar transacción
    res.status(201).json(fieldResult.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK'); // Revertir todo si hay error
    console.error(err);
    res.status(500).json({ error: 'Failed to create field and schedules' });
  } finally {
    client.release();
  }
});

// --- HORARIOS (SCHEDULES) ---

app.get('/api/fields/:id/schedules', async (req: Request, res: Response) => {
  try {
    const fieldId = req.params.id;
    const { date } = req.query;

    let query = `
      SELECT 
          fs.id AS schedule_id,
          TO_CHAR(fs.date, 'YYYY-MM-DD') AS date,
          TO_CHAR(fs.start_time, 'HH24:MI') AS start_time,
          TO_CHAR(fs.end_time, 'HH24:MI') AS end_time,
          COALESCE(fs.price, f.price) AS final_price,
          fs.status
      FROM schedules fs
      JOIN fields f ON fs.field_id = f.id
      WHERE f.id = $1
    `;
    
    const queryParams: any[] = [fieldId];

    if (date) {
        query += ` AND fs.date = $2`;
        queryParams.push(date);
    }

    query += ` ORDER BY fs.date ASC, fs.start_time ASC`;

    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error fetching schedules' });
  }
});

app.post('/api/fields/:fieldId/schedules', authenticate, requireAdmin, async (req: Request, res: Response) => {
  try {
    const fieldId = req.params.fieldId;
    const { date, startTime, endTime, price, status } = req.body;

    const result = await pool.query(`
      INSERT INTO schedules (field_id, date, start_time, end_time, price, status)
      VALUES ($1, $2, $3, $4, $5, $6) 
      RETURNING *
    `, [fieldId, date, startTime, endTime, price || null, status || 'available']);

    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Schedule block already exists.' });
    }
    res.status(500).json({ error: 'Failed to create schedule' });
  }
});

app.patch('/api/schedules/:id', authenticate, requireAdmin, async (req: Request, res: Response) => {
  try {
    const scheduleId = req.params.id;
    const { status, price } = req.body;

    const updates: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (status !== undefined) {
      const validStatuses = ['available', 'reserved', 'closed', 'maintenance'];
      if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });
      updates.push(`status = $${paramIndex++}`);
      values.push(status);
    }

    if (price !== undefined) {
      updates.push(`price = $${paramIndex++}`);
      values.push(price); 
    }

    if (updates.length === 0) return res.status(400).json({ error: 'No data to update' });
    values.push(scheduleId);
    
    const query = `UPDATE schedules SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`;
    const result = await pool.query(query, values);

    if (result.rowCount === 0) return res.status(404).json({ error: 'Schedule not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update schedule' });
  }
});

app.delete('/api/schedules/:id', authenticate, requireAdmin, async (req: Request, res: Response) => {
  try {
    const scheduleId = req.params.id;
    const result = await pool.query(`DELETE FROM schedules WHERE id = $1 RETURNING id`, [scheduleId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Schedule not found' });
    res.json({ message: 'Schedule deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete schedule' });
  }
});

// --- RESERVAS ---

app.get('/api/reservations', async (req, res) => {
  try {
    const query = `
      SELECT 
        r.id, 
        r.field_id AS "fieldId", 
        f.name AS "fieldName",
        r.player_id AS "playerId", 
        u.name AS "playerName", 
        r.schedule_id AS "scheduleId",
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

app.post('/api/reservations', authenticate, async (req: Request, res: Response) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { fieldId, scheduleId, date, hour, price } = req.body;
    const playerId = req.user!.id;

    // Insertar la reserva
    const result = await client.query(`
      INSERT INTO reservations (field_id, player_id, schedule_id, date, hour, price, status)
      VALUES ($1, $2, $3, $4, $5, $6, 'confirmed') RETURNING *
    `, [fieldId, playerId, scheduleId || null, date, hour, price]);

    // Actualizar el estado del horario a reservado
    if (scheduleId) {
      await client.query(`
        UPDATE schedules SET status = 'reserved' WHERE id = $1
      `, [scheduleId]);
    }

    await client.query('COMMIT');
    res.status(201).json(result.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Failed to create reservation' });
  } finally {
    client.release();
  }
});

app.delete('/api/reservations/:id', authenticate, async (req: Request, res: Response) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const reservationId = req.params.id;

    const reservationResult = await client.query(`
      DELETE FROM reservations WHERE id = $1 RETURNING schedule_id
    `, [reservationId]);

    if (reservationResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Reservation not found' });
    }

    const scheduleId = reservationResult.rows[0].schedule_id;
    if (scheduleId) {
      await client.query(`
        UPDATE schedules SET status = 'available' WHERE id = $1
      `, [scheduleId]);
    }

    await client.query('COMMIT');
    res.json({ message: 'Reservation canceled successfully' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Failed to cancel reservation' });
  } finally {
    client.release();
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Furbito API backend running at port ${PORT}`);
});
