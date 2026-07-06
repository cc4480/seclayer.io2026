import dotenv from 'dotenv';

// Loads environment files before any other module reads process.env.
// .env.local overrides .env; both are optional (no-op if absent). On hosted
// platforms env vars are injected directly and these files simply won't exist.
dotenv.config();
dotenv.config({ path: '.env.local', override: true });
