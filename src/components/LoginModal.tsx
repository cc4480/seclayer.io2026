import React, { useState } from 'react';
import { Shield, Mail, Check, RefreshCw, X, ArrowRight, AlertTriangle } from 'lucide-react';

interface LoginModalProps {
  onClose: () => void;
}

export default function LoginModal({ onClose }: LoginModalProps) {
  const [email, setEmail] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isMagicLinkSent, setIsMagicLinkSent] = useState(false);
  const [devLink, setDevLink] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes('@')) return;

    setIsSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/request-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.message || 'Could not send the sign-in link. Please try again.');
        return;
      }
      // devLink is only returned when no email provider is configured (dev/demo).
      setDevLink(data.devLink || null);
      setIsMagicLinkSent(true);
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm" onClick={onClose}>
      <div
        className="relative w-full max-w-md bg-[#0c0c0e] border border-[#27272a] p-8 rounded shadow-2xl space-y-6"
        onClick={(e) => e.stopPropagation()}
        id="login-modal-root"
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 rounded text-[#52525b] hover:text-white transition-colors cursor-pointer"
          id="login-modal-close"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="text-center space-y-2">
          <div className="inline-flex p-2 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e] mb-2">
            <Shield className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold font-mono text-white">Sign in to Seclayer</h2>
          <p className="text-[#a1a1aa] text-xs max-w-xs mx-auto font-mono">
            Enter your email and we'll send a secure sign-in link. New emails receive <strong className="text-[#22c55e]">5 starting scan credits</strong>.
          </p>
        </div>

        {isMagicLinkSent ? (
          <div className="bg-[#22c55e]/5 border border-[#22c55e]/25 p-5 rounded text-center space-y-3 text-[#22c55e]">
            <Check className="w-6 h-6 mx-auto bg-[#22c55e] text-black rounded-full p-1" />
            <span className="text-xs font-mono font-bold block uppercase tracking-wider">Check your email</span>
            <p className="text-[11px] text-[#a1a1aa] font-mono">
              We sent a sign-in link to <strong className="text-white">{email}</strong>. It is valid for 15 minutes and can be used once.
            </p>
            {devLink && (
              <a
                href={devLink}
                className="inline-flex items-center justify-center space-x-2 w-full py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-[11px] font-mono tracking-widest uppercase font-bold rounded transition-all cursor-pointer"
                id="login-modal-devlink"
              >
                <span>Dev mode: open sign-in link</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </a>
            )}
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-[10px] font-mono text-[#52525b] uppercase block mb-1.5 ml-1">Email address</label>
              <div className="flex bg-black border border-[#27272a] rounded p-2.5 focus-within:border-[#22c55e] transition-colors">
                <Mail className="w-4 h-4 text-[#52525b] mr-2 shrink-0 self-center" />
                <input
                  type="email"
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
              <div className="flex items-start space-x-2 text-[11px] font-mono text-red-400 bg-red-500/5 border border-red-500/25 rounded p-2.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
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
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Sending link...</span>
                </>
              ) : (
                <>
                  <span>Send sign-in link</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>
        )}

      </div>
    </div>
  );
}
