-- T3-Backup-Exposure-001 fixture backup. This file simulates an automated
-- daily database backup stored in a publicly-readable location (in the real
-- vulnerability class: an S3 bucket with public-read ACL and no encryption
-- at rest). Local use only — never expose this fixture to the internet.
--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';

--
-- Data for table: profiles
--

COPY public.profiles (id, user_id, email, sensitive_data) FROM stdin;
11111111-1111-1111-1111-111111111111	aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa	alice@tier3.test	alice-ssn-078-05-1120
22222222-2222-2222-2222-222222222222	bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb	bob@tier3.test	bob-ssn-078-05-1121
\.

--
-- Data for table: session_tokens
--

COPY public.session_tokens (id, user_id, token, created_at) FROM stdin;
33333333-3333-3333-3333-333333333333	aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa	fake-plaintext-session-token-alice	2026-01-15 03:00:00+00
44444444-4444-4444-4444-444444444444	bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb	fake-plaintext-session-token-bob	2026-01-15 03:00:00+00
\.

-- End of backup
