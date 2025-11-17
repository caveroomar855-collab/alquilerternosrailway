import fastifyPlugin from 'fastify-plugin';
import fastifyJwt from '@fastify/jwt';
import { config } from '../config.js';

const localDeviceUser = {
  sub: 'local-device',
  username: 'Penguin Local',
  role: 'ADMIN',
};

async function authPlugin(fastify) {
  await fastify.register(fastifyJwt, {
    secret: config.jwtSecret,
    sign: { expiresIn: config.jwtExpiresIn },
  });

  fastify.decorate('authenticate', async (request) => {
    const authHeader = request.headers.authorization;
    if (authHeader) {
      try {
        await request.jwtVerify();
        return;
      } catch (err) {
        request.log.warn({ err }, 'Invalid token, defaulting to local-device user');
      }
    }
    request.user = { ...localDeviceUser };
  });
}

export default fastifyPlugin(authPlugin);
