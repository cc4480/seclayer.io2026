import crypto from "node:crypto";

// Identifies THIS process for the lifetime of its boot.
//
// Exists because a fleet is otherwise opaque from outside: with several
// replicas behind one domain there is no way to tell which one served a request
// or ran a scan, so "the work is distributed" cannot be verified and a single
// misbehaving replica cannot be singled out. Health reports it, and the scan
// worker stamps its log lines with it.
//
// Random per boot rather than RAILWAY_REPLICA_ID: it only has to differ between
// processes, and this way it leaks nothing about the platform underneath.
export const INSTANCE_ID = crypto.randomBytes(4).toString("hex");
