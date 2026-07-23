// Client-safe view of a user's personal DeepSeek key: whether one is set and a
// masked preview (never the raw key). Shared by the PUT route that sets it and
// /api/auth/me. maskKey shows only a prefix + last 4 chars, so the preview can
// be displayed without ever exposing a usable credential.
import { maskKey } from "../dbCrypto.js";

export function deepseekKeyStatus(key: string | null): { deepseekKeySet: boolean; deepseekKeyPreview: string | null } {
  return {
    deepseekKeySet: !!key,
    deepseekKeyPreview: key ? maskKey(key) : null,
  };
}
