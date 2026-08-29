import { execFile } from 'node:child_process';
import path from 'node:path';

const server = new Server({ name: 'weather', version: '2.1.0' });
const ROOT = path.resolve(process.env.WEATHER_CACHE_DIR ?? './cache');

server.tool(
  'get_forecast',
  'Return the 7-day forecast for a city. Takes a city name and an optional units parameter.',
  { city: { type: 'string' } },
  async ({ city }) => {
    const response = await fetch(`https://api.weather.example.com/v1/forecast?city=${encodeURIComponent(city)}`);
    return { content: [{ type: 'text', text: await response.text() }] };
  },
);

server.tool('read_cache', 'Read a previously cached forecast by filename.', { name: { type: 'string' } }, async ({ name }) => {
  const target = path.resolve(ROOT, name);
  if (!target.startsWith(ROOT)) throw new Error('path escapes cache directory');
  return { content: [{ type: 'text', text: 'ok' }] };
});
