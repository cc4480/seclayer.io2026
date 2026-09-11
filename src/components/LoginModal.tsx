import React, { useState, useEffect, useRef } from 'react';
import { Shield, Mail, RefreshCw, X, ArrowRight, AlertTriangle, KeyRound } from 'lucide-react';

// Google Identity Services attaches itself to window.google once its script
// loads. Declared loosely rather than pulling in @types/google.one-tap for the
// three fields this component touches.
declare global {
  interface Window {
    google?: any;
  }
}

const GSI_SRC = 'https://accounts.google.com/gsi/client';

// Long enough that a second request is a considered act rather than an
// impatient double-click. The server allows five codes per address per hour and
// each new code kills the previous one, so a user who taps resend four times
// while the first email is still in flight would lock themselves out of the
// address for an hour and be holding a code that no longer works.
const RESEND_COOLDOWN_SECONDS = 30;

interface LoginModalProps {
  onClose: () => void;
}

export default function LoginModal({ onClose }: LoginModalProps) {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [step, setStep] = useState<'email' | 'code'>('email');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [devCode, setDevCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const [googleClientId, setGoogleClientId] = useState<string | null>(null);
  const googleButtonRef = useRef<HTMLDivElement | null>(null);
  const codeInputRef = useRef<HTMLInputElement | null>(null);

  // Ask the server whether Google sign-in is configured. When it isn't, the
  // whole block below never renders and this modal is exactly as it was.
  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/providers')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (!cancelled && d?.googleClientId) setGoogleClientId(d.googleClientId); })
      .catch(() => { /* Google sign-in stays hidden; the code flow is unaffected */ });
    return () => { cancelled = true; };
  }, []);

  // Tick the resend cooldown down to zero.
  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  // Put the cursor in the code field the moment that step appears — the user
  // has just come back from their mail client and the only thing left to do is
  // type six digits.
  useEffect(() => {
    if (step === 'code') codeInputRef.current?.focus();
  }, [step]);

  // Load the GIS script once the client id is known, then render Google's own
  // button into the div below. The button must be rendered by GIS itself — a
  // hand-built button can't produce a credential.
  useEffect(() => {
    if (!googleClientId) return;
    let cancelled = false;

    const onCredential = async (response: { credential?: string }) => {
      if (!response?.credential) return;
      setIsSubmitting(true);
      setError(null);
      try {
        const res = await fetch('/api/auth/google', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ credential: response.credential }),
        });
        if (res.ok) {
          // The session cookie is set; reload so the app boots authenticated.
          window.location.reload();
          return;
        }
        const data = await res.json().catch(() => ({}));
        setError(data.message || 'Could not sign in with Google. Please try again.');
      } catch {
        setError('Network error signing in with Google. Please try again.');
      } finally {
        setIsSubmitting(false);
      }
    };

    const init = () => {
      if (cancelled || !window.google?.accounts?.id || !googleButtonRef.current) return;
      window.google.accounts.id.initialize({ client_id: googleClientId, callback: onCredential });
      window.google.accounts.id.renderButton(googleButtonRef.current, {
        theme: 'filled_black', size: 'large', width: 320, text: 'continue_with', shape: 'rectangular',
      });
    };

    if (window.google?.accounts?.id) { init(); return () => { cancelled = true; }; }

    // Reuse the tag if a previous mount already added it.
    let script = document.querySelector<HTMLScriptElement>(`script[src="${GSI_SRC}"]`);
    if (!script) {
      script = document.createElement('script');
      script.src = GSI_SRC;
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }
    script.addEventListener('load', init);
    return () => { cancelled = true; script?.removeEventListener('load', init); };
  }, [googleClientId]);

  const requestCode = async () => {
    setIsSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/request-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.message || 'Could not send the sign-in code. Please try again.');
        return;
      }
      // devCode is only returned when no email provider is configured (dev/demo).
      setDevCode(data.devCode || null);
      setCode('');
      setStep('code');
      setCooldown(RESEND_COOLDOWN_SECONDS);
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes('@')) return;
    await requestCode();
  };

  const handleCodeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const digits = code.replace(/[\s-]/g, '');
    if (digits.length !== 6) return;

    setIsSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code: digits })
      });
      if (res.ok) {
        // The session cookie is set; reload so the app boots authenticated.
        window.location.reload();
        return;
      }
      const data = await res.json().catch(() => ({}));
      setError(data.message || 'That code is not valid. Request a new one and try again.');
      setCode('');
      codeInputRef.current?.focus();
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const startOver = () => {
    setStep('email');
    setCode('');
    setDevCode(null);
    setError(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm" onClick={onClose}>
      <div
        className="relative w-full max-w-md bg-[#0c0c0e] border border-[#27272a] p-8 rounded shadow-2xl space-y-6"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Sign in to Seclayer"
        id="login-modal-root"
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 rounded text-[#52525b] hover:text-white transition-colors cursor-pointer"
          aria-label="Close sign-in dialog"
          id="login-modal-close"
        >
          <X className="w-4 h-4" aria-hidden="true" />
        </button>

        <div className="text-center space-y-2">
          <div className="inline-flex p-2 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e] mb-2">
            <Shield className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold font-mono text-white">Sign in to Seclayer</h2>
          <p className="text-[#a1a1aa] text-xs max-w-xs mx-auto font-mono">
            {step === 'email' ? (
              <>Enter your email and we'll send a 6-digit sign-in code. New emails receive <strong className="text-[#22c55e]">5 starting scan credits</strong>.</>
            ) : (
              <>Enter the 6-digit code we sent to <strong className="text-white break-all">{email}</strong>.</>
            )}
          </p>
        </div>

        {step === 'code' ? (
          <form onSubmit={handleCodeSubmit} className="space-y-4">
            <div>
              <label htmlFor="login-modal-code" className="text-[10px] font-mono text-[#52525b] uppercase block mb-1.5 ml-1">
                Sign-in code
              </label>
              <div className="flex bg-black border border-[#27272a] rounded p-2.5 focus-within:border-[#22c55e] transition-colors">
                <KeyRound className="w-4 h-4 text-[#52525b] mr-2 shrink-0 self-center" aria-hidden="true" />
                <input
                  id="login-modal-code"
                  ref={codeInputRef}
                  // `one-time-code` is what lets a browser and phone keyboard
                  // offer the code straight from the notification, and
                  // inputMode="numeric" brings up the digit pad rather than a
                  // full keyboard. Not type="number": that renders spinners,
                  // silently strips leading zeros on some browsers, and a code
                  // is a string of digits, not a quantity.
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  // Room for the "123 456" spacing the email uses; the server
                  // strips separators so pasting it verbatim works.
                  maxLength={7}
                  required
                  placeholder="123456"
                  aria-describedby="login-modal-code-help"
                  className="bg-transparent text-white text-lg font-mono tracking-[0.35em] w-full focus:outline-none placeholder:text-[#3f3f46] placeholder:tracking-[0.35em]"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  disabled={isSubmitting}
                />
              </div>
              <p id="login-modal-code-help" className="text-[10px] font-mono text-[#52525b] mt-1.5 ml-1">
                Expires in 10 minutes. Spaces don't matter.
              </p>
            </div>

            {devCode && (
              <div className="text-center text-[11px] font-mono text-[#22c55e] bg-[#22c55e]/5 border border-[#22c55e]/25 rounded p-2.5" id="login-modal-devcode">
                Dev mode — no email provider configured. Your code is <strong className="tracking-widest">{devCode}</strong>
              </div>
            )}

            {error && (
              <div className="flex items-start space-x-2 text-[11px] font-mono text-red-400 bg-red-500/5 border border-red-500/25 rounded p-2.5" role="alert">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting || code.replace(/[\s-]/g, '').length !== 6}
              className="w-full py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono tracking-widest uppercase font-bold rounded transition-all flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              id="login-modal-verify"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                  <span>Verifying...</span>
                </>
              ) : (
                <>
                  <span>Sign in</span>
                  <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                </>
              )}
            </button>

            <div className="flex items-center justify-between text-[10px] font-mono">
              <button
                type="button"
                onClick={startOver}
                className="text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
                id="login-modal-change-email"
              >
                Use a different email
              </button>
              <button
                type="button"
                onClick={requestCode}
                disabled={isSubmitting || cooldown > 0}
                className="text-[#22c55e] hover:text-[#4ade80] transition-colors disabled:text-[#3f3f46] disabled:cursor-not-allowed cursor-pointer"
                id="login-modal-resend"
              >
                {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend code'}
              </button>
            </div>
          </form>
        ) : (
          <>
            {/* Rendered by Google Identity Services itself; absent entirely when
                GOOGLE_CLIENT_ID isn't configured on the server. */}
            {googleClientId && (
              <div className="space-y-4">
                <div ref={googleButtonRef} className="flex justify-center" id="google-signin-button" />
                <div className="flex items-center gap-3" aria-hidden="true">
                  <span className="h-px flex-1 bg-[#27272a]" />
                  <span className="text-[10px] font-mono text-[#52525b] uppercase tracking-wider">or</span>
                  <span className="h-px flex-1 bg-[#27272a]" />
                </div>
              </div>
            )}

          <form onSubmit={handleEmailSubmit} className="space-y-4">
            <div>
              <label htmlFor="login-modal-email" className="text-[10px] font-mono text-[#52525b] uppercase block mb-1.5 ml-1">Email address</label>
              <div className="flex bg-black border border-[#27272a] rounded p-2.5 focus-within:border-[#22c55e] transition-colors">
                <Mail className="w-4 h-4 text-[#52525b] mr-2 shrink-0 self-center" aria-hidden="true" />
                <input
                  id="login-modal-email"
                  type="email"
                  autoComplete="email"
                  required
                  placeholder="name@company.com"
                  className="bg-transparent text-white text-xs font-mono w-full focus:outline-none"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isSubmitting}
                />
              </div>
            </div>

            {error && (
              <div className="flex items-start space-x-2 text-[11px] font-mono text-red-400 bg-red-500/5 border border-red-500/25 rounded p-2.5" role="alert">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting || !email.includes('@')}
              className="w-full py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono tracking-widest uppercase font-bold rounded transition-all flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              id="login-modal-submit"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                  <span>Sending code...</span>
                </>
              ) : (
                <>
                  <span>Send sign-in code</span>
                  <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                </>
              )}
            </button>
          </form>
          </>
        )}

      </div>
    </div>
  );
}
