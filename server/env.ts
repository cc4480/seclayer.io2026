import dotenv from 'dotenv';

// Loads environment files before any other module reads process.env.
// .env.local overrides .env; both are optional (no-op if absent). On hosted
// platforms env vars are injected directly and these files simply won't exist.
// quiet: true suppresses dotenv's stdout "tip" banners so production logs
// only ever contain output this app actually wrote.
dotenv.config({ quiet: true });
dotenv.config({ path: '.env.local', override: true, quiet: true });
