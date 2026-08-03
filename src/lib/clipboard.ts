// Wraps navigator.clipboard.writeText so a rejected write (blocked permission,
// insecure context, unfocused tab) can't be mistaken for success by a caller
// that only checked for a thrown exception, nor left as an unhandled rejection.
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
