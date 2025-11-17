import bcrypt from 'bcryptjs';
import { HttpError } from '../../utils/errors.js';
import { assertSupabase } from '../../utils/supabase.js';
import { ensureAdmin, sanitizeUser } from '../../utils/auth.js';
import { config } from '../../config.js';

async function routes(fastify, _opts, done) {
  fastify.post('/login', async (request, reply) => {
    const { username, password } = request.body ?? {};
    if (!username || !password) {
      return reply.code(400).send({ message: 'Usuario y contraseña requeridos' });
    }

    if (config.authMode === 'local') {
      const user = config.localUsers.find((u) => u.username === username && u.password === password);
      if (!user) {
        throw new HttpError(401, 'Credenciales inválidas');
      }
      const payload = {
        id: user.username,
        username: user.username,
        role: user.role ?? 'ADMIN',
        status: 'ACTIVE',
        require_password_change: false,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      const token = fastify.jwt.sign({ sub: payload.id, username: payload.username, role: payload.role });
      return reply.send({ token, user: payload });
    }

    const { data: user, error } = await fastify.supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .maybeSingle();
    if (error) {
      request.log.error(error);
      throw new HttpError(500, 'Error consultando usuario');
    }
    if (!user) {
      throw new HttpError(401, 'Credenciales inválidas');
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      throw new HttpError(401, 'Credenciales inválidas');
    }
    const token = fastify.jwt.sign({ sub: user.id, username: user.username, role: user.role });
    reply.send({ token, user: sanitizeUser(user) });
  });

  fastify.get('/me', { preHandler: fastify.authenticate }, async (request) => {
    if (config.authMode === 'local') {
      const user = config.localUsers.find((u) => u.username === request.user.username);
      if (!user) throw new HttpError(404, 'Usuario no encontrado');
      return {
        id: user.username,
        username: user.username,
        role: user.role ?? 'ADMIN',
        status: 'ACTIVE',
        created_at: new Date().toISOString(),
      };
    }
    const { data, error } = await fastify.supabase
      .from('users')
      .select('id, username, role, status, created_at')
      .eq('id', request.user.sub)
      .maybeSingle();
    if (error) throw new HttpError(500, 'No se pudo cargar el usuario');
    return data;
  });

  fastify.get('/users', { preHandler: fastify.authenticate }, async (request) => {
    ensureAdmin(request);
    if (config.authMode === 'local') {
      return config.localUsers.map((user) => ({
        id: user.username,
        username: user.username,
        role: user.role ?? 'ADMIN',
        status: 'ACTIVE',
        created_at: new Date().toISOString(),
      }));
    }
    const { data, error } = await fastify.supabase
      .from('users')
      .select('id, username, role, status, created_at')
      .order('created_at', { ascending: false });
    if (error) throw new HttpError(500, 'No se pudo listar usuarios');
    return data;
  });

  fastify.post('/users', { preHandler: fastify.authenticate }, async (request, reply) => {
    ensureAdmin(request);
    if (config.authMode === 'local') {
      throw new HttpError(400, 'En modo local edita LOCAL_USERS en el backend');
    }
    const { username, password, role = 'EMPLOYEE' } = request.body ?? {};
    if (!username || !password) {
      throw new HttpError(400, 'Usuario y contraseña requeridos');
    }
    const password_hash = await bcrypt.hash(password, 10);
    const result = await fastify.supabase
      .from('users')
      .insert({ username, password_hash, role, status: 'ACTIVE' })
      .select('id, username, role, status, created_at')
      .single();
    const data = assertSupabase(result, 'No se pudo crear el usuario');
    reply.code(201).send(data);
  });

  done();
}

export default routes;
