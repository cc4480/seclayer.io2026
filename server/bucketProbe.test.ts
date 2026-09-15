import { test } from "node:test";
import assert from "node:assert/strict";
import { extractBucketUrls, classifyBucketListing } from "./bucketProbe.js";

// --- extractBucketUrls ------------------------------------------------------

test("extractBucketUrls finds S3 virtual-hosted and path-style buckets", () => {
  const html = `
    <img src="https://my-assets.s3.amazonaws.com/logo.png">
    <link href="https://prod-uploads.s3.us-west-2.amazonaws.com/style.css">
    fetch("https://s3.eu-central-1.amazonaws.com/legacy-bucket/data.json")
  `;
  const refs = extractBucketUrls(html);
  const buckets = refs.filter((r) => r.provider === "s3").map((r) => r.bucket).sort();
  assert.deepEqual(buckets, ["legacy-bucket", "my-assets", "prod-uploads"]);
  const one = refs.find((r) => r.bucket === "my-assets")!;
  assert.match(one.listUrl, /list-type=2/);
});

test("extractBucketUrls finds GCS (path and virtual-hosted) and Azure buckets", () => {
  const html = `
    a="https://storage.googleapis.com/app-public-bucket/x.png";
    b="https://user-uploads.storage.googleapis.com/y.png";
    c="https://myacct.blob.core.windows.net/media/z.png";
  `;
  const refs = extractBucketUrls(html);
  assert.ok(refs.some((r) => r.provider === "gcs" && r.bucket === "app-public-bucket"));
  assert.ok(refs.some((r) => r.provider === "gcs" && r.bucket === "user-uploads"));
  const az = refs.find((r) => r.provider === "azure")!;
  assert.equal(az.bucket, "myacct/media");
  assert.match(az.listUrl, /restype=container&comp=list/);
});

test("extractBucketUrls dedupes and caps at four", () => {
  const many = Array.from({ length: 8 }, (_, i) => `https://bucket-num-${i}.s3.amazonaws.com/o`).join(" ");
  const dupes = "https://same-bucket.s3.amazonaws.com/a https://same-bucket.s3.amazonaws.com/b";
  assert.equal(extractBucketUrls(many).length, 4);
  assert.equal(extractBucketUrls(dupes).length, 1);
});

test("extractBucketUrls returns nothing for content with no bucket URLs", () => {
  assert.deepEqual(extractBucketUrls('<a href="https://example.com/about">x</a>'), []);
  assert.deepEqual(extractBucketUrls(""), []);
});

// --- classifyBucketListing: the false-positive-critical oracle --------------

test("classifyBucketListing: S3 200 + ListBucketResult is open, and samples a key", () => {
  const body = `<?xml version="1.0"?><ListBucketResult><Contents><Key>secrets/db.env</Key></Contents></ListBucketResult>`;
  assert.deepEqual(classifyBucketListing("s3", 200, body), { open: true, sample: "secrets/db.env" });
});

test("classifyBucketListing: S3 403 AccessDenied is secured (no finding)", () => {
  const denied = `<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>`;
  assert.deepEqual(classifyBucketListing("s3", 403, denied), { open: false });
});

test("classifyBucketListing: a 200 that is not a listing document is NOT open", () => {
  // e.g. a bucket that returns its index.html or an SPA shell on the root.
  assert.deepEqual(classifyBucketListing("s3", 200, "<!DOCTYPE html><html>...</html>"), { open: false });
});

test("classifyBucketListing: GCS storage#objects JSON is open, and samples a name", () => {
  const json = `{"kind": "storage#objects","items":[{"name":"uploads/passport.jpg"}]}`;
  assert.deepEqual(classifyBucketListing("gcs", 200, json), { open: true, sample: "uploads/passport.jpg" });
});

test("classifyBucketListing: GCS 403 error JSON is secured", () => {
  assert.deepEqual(classifyBucketListing("gcs", 403, `{"error":{"code":403,"message":"does not have storage.objects.list"}}`), { open: false });
});

test("classifyBucketListing: Azure EnumerationResults is open", () => {
  const xml = `<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>private/report.pdf</Name></Blob></Blobs></EnumerationResults>`;
  assert.deepEqual(classifyBucketListing("azure", 200, xml), { open: true, sample: "private/report.pdf" });
});

test("classifyBucketListing: an open bucket with no visible key is still open, without a sample", () => {
  assert.deepEqual(classifyBucketListing("s3", 200, "<ListBucketResult></ListBucketResult>"), { open: true, sample: undefined });
});

test("classifyBucketListing: a non-200 is never open regardless of body", () => {
  assert.deepEqual(classifyBucketListing("s3", 500, "<ListBucketResult>"), { open: false });
});
