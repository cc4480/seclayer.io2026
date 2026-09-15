// Open cloud-storage-bucket probe. Vibe-coder apps routinely reference their own
// object-storage buckets in served content (asset URLs, upload targets). A
// bucket URL is public BY DESIGN — like a Firebase config — so its presence is
// never the flaw. The flaw is when the bucket permits an ANONYMOUS LIST: then
// anyone who reads the (public) bucket URL out of the page can enumerate every
// object in it. We prove exactly that by GETting the bucket's list endpoint with
// NO credentials and checking for the provider's listing document.
//
// Read-only (a GET or two per discovered bucket) and — like server/firebaseProbe
// and server/credentialChainProbe — the bucket origin is one the scanned app's
// OWN content named, never a guess: no bucket-name brute-forcing. Reuses
// safeFetch's SSRF allow/deny logic unchanged.
import { safeFetch } from "./ssrf.js";
import { SCANNER_USER_AGENT } from "./config.js";
import { renderRawRequest, windowAround } from "./evidence.js";
import type { ExploitEvidence } from "../src/types.js";

export type BucketProvider = "s3" | "gcs" | "azure";

export interface BucketRef {
  provider: BucketProvider;
  bucket: string;
  // The anonymous LIST endpoint we probe (already provider-shaped).
  listUrl: string;
  // Human label for the bucket, for the finding text.
  display: string;
}

// S3: virtual-hosted (<bucket>.s3.amazonaws.com, <bucket>.s3.<region>.amazonaws.com,
// <bucket>.s3-<region>.amazonaws.com) and path-style (s3[.-]<region>.amazonaws.com/<bucket>).
const S3_VHOST_RE = /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-]?(?:[a-z0-9-]+\.)?amazonaws\.com/gi;
const S3_PATH_RE = /https?:\/\/(s3[.-]?(?:[a-z0-9-]+\.)?amazonaws\.com)\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?=[/"'\s?]|$)/gi;
// GCS: path-style (storage.googleapis.com/<bucket>) and virtual-hosted (<bucket>.storage.googleapis.com).
const GCS_PATH_RE = /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])(?=[/"'\s?]|$)/gi;
const GCS_VHOST_RE = /https?:\/\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com/gi;
// Azure Blob: <account>.blob.core.windows.net/<container>.
const AZURE_RE = /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?)(?=[/"'\s?]|$)/gi;

// Storage service hostnames themselves — never treated as a bucket name.
const RESERVED = new Set(["s3", "www", "storage", "assets", "static", "cdn"]);

function s3ListUrl(host: string, bucket?: string): string {
  return bucket
    ? `https://${host}/${bucket}?list-type=2&max-keys=5`
    : `https://${host}/?list-type=2&max-keys=5`;
}

// Pulls distinct bucket references out of served content, capped at 4.
export function extractBucketUrls(bodyText: string): BucketRef[] {
  if (!bodyText) return [];
  const out: BucketRef[] = [];
  const seen = new Set<string>();
  const add = (ref: BucketRef) => {
    const k = `${ref.provider}:${ref.bucket}`;
    if (seen.has(k) || RESERVED.has(ref.bucket.toLowerCase())) return;
    seen.add(k);
    if (out.length < 4) out.push(ref);
  };
  let m: RegExpExecArray | null;

  S3_VHOST_RE.lastIndex = 0;
  while ((m = S3_VHOST_RE.exec(bodyText)) !== null) {
    const host = m[0].replace(/^https?:\/\//i, "");
    add({ provider: "s3", bucket: m[1], listUrl: s3ListUrl(host), display: `${m[1]} (S3)` });
  }
  S3_PATH_RE.lastIndex = 0;
  while ((m = S3_PATH_RE.exec(bodyText)) !== null) {
    add({ provider: "s3", bucket: m[2], listUrl: s3ListUrl(m[1], m[2]), display: `${m[2]} (S3)` });
  }
  GCS_PATH_RE.lastIndex = 0;
  while ((m = GCS_PATH_RE.exec(bodyText)) !== null) {
    add({ provider: "gcs", bucket: m[1], listUrl: `https://storage.googleapis.com/storage/v1/b/${m[1]}/o?maxResults=5`, display: `${m[1]} (Google Cloud Storage)` });
  }
  GCS_VHOST_RE.lastIndex = 0;
  while ((m = GCS_VHOST_RE.exec(bodyText)) !== null) {
    add({ provider: "gcs", bucket: m[1], listUrl: `https://storage.googleapis.com/storage/v1/b/${m[1]}/o?maxResults=5`, display: `${m[1]} (Google Cloud Storage)` });
  }
  AZURE_RE.lastIndex = 0;
  while ((m = AZURE_RE.exec(bodyText)) !== null) {
    const listUrl = `https://${m[1]}.blob.core.windows.net/${m[2]}?restype=container&comp=list`;
    add({ provider: "azure", bucket: `${m[1]}/${m[2]}`, listUrl, display: `${m[1]}/${m[2]} (Azure Blob)` });
  }

  return out;
}

export interface BucketVerdict {
  open: boolean;
  // A sample object name from the listing, when one is present.
  sample?: string;
}

// Pure classifier — the false-positive-critical decision, unit-tested without a
// network. A public listing returns the provider's listing document at HTTP 200;
// a secured bucket returns 403/401 (S3 <Code>AccessDenied</Code>, GCS a JSON
// error, Azure ResourceNotFound/AuthorizationFailure). ONLY the listing document
// counts as proof.
export function classifyBucketListing(provider: BucketProvider, status: number, text: string): BucketVerdict {
  if (status !== 200 || !text) return { open: false };
  if (provider === "s3" || provider === "azure") {
    const marker = provider === "s3" ? "<ListBucketResult" : "<EnumerationResults";
    if (!text.includes(marker)) return { open: false };
    const key = /<(?:Key|Name)>([^<]+)<\/(?:Key|Name)>/.exec(text);
    return { open: true, sample: key ? key[1] : undefined };
  }
  // GCS JSON API: a public-listable bucket returns { "kind": "storage#objects", … }.
  if (!/"kind"\s*:\s*"storage#objects"/.test(text)) return { open: false };
  const name = /"name"\s*:\s*"([^"]+)"/.exec(text);
  return { open: true, sample: name ? name[1] : undefined };
}

async function timedGet(url: string, headers: Record<string, string>): Promise<{ res: Response; text: string } | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return { res, text: await res.text().catch(() => "") };
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

// Probes each discovered bucket for anonymous listing. Returns an apiSec-shaped
// finding on the first open bucket, else null. `refs` are pre-extracted by the
// caller (see extractBucketUrls).
export async function probeOpenBuckets(
  refs: BucketRef[],
  headers: Record<string, string>,
): Promise<any | null> {
  const ua = headers["User-Agent"] || SCANNER_USER_AGENT;
  for (const ref of refs.slice(0, 4)) {
    const r = await timedGet(ref.listUrl, { "User-Agent": ua });
    if (!r) continue;
    const verdict = classifyBucketListing(ref.provider, r.res.status, r.text);
    if (!verdict.open) continue;

    const proof = verdict.sample
      ? (r.text.includes(verdict.sample) ? verdict.sample : r.text.slice(0, 200))
      : r.text.slice(0, 200);
    const attackResponse =
      `HTTP/1.1 ${r.res.status} ${r.res.statusText}\n\n` +
      windowAround(r.text, Math.max(0, r.text.indexOf(proof)), proof.length, 1200);

    const evidence: ExploitEvidence = {
      method: "oracle",
      attack: { request: renderRawRequest("GET", ref.listUrl, {}), response: attackResponse },
      signal: {
        quote: proof,
        offsetInResponse: Math.max(0, attackResponse.indexOf(proof)),
        why: `An unauthenticated list request to the ${ref.display} bucket returned its object listing (HTTP 200), which only happens when the bucket permits anonymous listing — a locked-down bucket answers with HTTP 403/401 and an access-denied document.`,
      },
      demonstration: `We requested ${ref.listUrl} with NO credentials and the bucket returned an object listing${verdict.sample ? ` (e.g. "${verdict.sample}")` : ""} — a public enumeration the bucket policy should have denied.`,
      reproduction: `curl -s "${ref.listUrl}"`,
      capturedAt: new Date().toISOString(),
    };

    return {
      testName: `Public Cloud Storage Bucket Listing (${ref.display})`,
      payload: ref.listUrl,
      severity: verdict.sample ? "high" : "medium",
      description: `The cloud storage bucket ${ref.display}, referenced by this application's own content, allows an unauthenticated LIST of its objects — anyone can enumerate every object key in it${verdict.sample ? `, e.g. "${verdict.sample}"` : ""}. (The bucket URL being public is expected; the permissive LIST permission is the flaw.) Enumerable keys often lead directly to readable objects.`,
      fix: `Remove the anonymous/public LIST (and, unless intended, READ) permission from this bucket. On S3, block public access and drop the "s3:ListBucket" grant to "*"/AllUsers; on GCS, remove "allUsers"/"allAuthenticatedUsers" from the bucket IAM; on Azure, set the container's public access level to "Private". Then confirm an unauthenticated list returns HTTP 403.`,
      evidence,
    };
  }
  return null;
}
