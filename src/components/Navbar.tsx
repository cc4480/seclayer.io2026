import React, { useState, useEffect } from 'react';
import { Shield, Key, Coins, LogOut, ArrowRight, User } from 'lucide-react';
import { motion } from 'motion/react';

interface NavbarProps {
  currentView: string;
  onNavigate: (view: string, arg?: string) => void;
  userEmail: string;
  credits: number;
  onLogout: () => void;
  onLoginClick: () => void;
}

export default function Navbar({
  currentView,
  onNavigate,
  userEmail,
  credits,
  onLogout,
  onLoginClick
}: NavbarProps) {
  const [engineStatus, setEngineStatus] = useState<{status: string, version: string} | null>(null);

  useEffect(() => {
    fetch('/api/system/health')
      .then(res => res.json())
      .then(data => setEngineStatus(data))
      .catch(() => setEngineStatus({ status: 'Offline', version: 'v0.0.0-error' }));
  }, []);

  return (
    <nav className="border-b border-[#27272a] bg-[#09090b]/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Logo and Tagline */}
        <div 
          onClick={() => onNavigate('landing')}
          className="flex items-center space-x-3 cursor-pointer group relative"
          id="navbar-brand-logo"
        >
          <div className={`relative w-9 h-9 flex items-center justify-center bg-[#22c55e]/10 border border-[#22c55e]/30 rounded transition-all duration-1000 ${engineStatus?.status === 'Online' ? 'shadow-[0_0_15px_rgba(34,197,94,0.3)]' : ''}`}>
            {engineStatus?.status === 'Online' && (
              <div className="absolute inset-0 bg-[#22c55e] opacity-20 rounded animate-ping"></div>
            )}
            <Shield className="w-5 h-5 text-[#22c55e] group-hover:scale-110 transition-transform duration-300 relative z-10" />
            <div className="absolute inset-0 bg-[#22c55e]/10 mix-blend-color-dodge opacity-0 group-hover:opacity-100 transition-opacity z-10" />
          </div>
          <div>
            <div className="flex items-baseline space-x-0.5">
              <span className="font-mono text-xl font-bold tracking-tighter text-[#22c55e]">
                <span className="opacity-50 text-white transition-opacity group-hover:opacity-80">[</span>sec<span className="opacity-50 text-white transition-opacity group-hover:opacity-80">]</span>layer
              </span>
            </div>
          </div>
          
          {/* Hover Tooltip */}
          <div className="absolute top-full left-0 mt-2 flex flex-col items-start bg-[#09090b] border border-[#27272a] rounded-md px-3 py-2 text-xs font-mono text-[#a1a1aa] whitespace-nowrap shadow-xl z-50 pointer-events-none opacity-0 group-hover:opacity-100 translate-y-1 group-hover:translate-y-0 transition-all duration-200">
            <div className="flex items-center space-x-2">
              <span className={`w-1.5 h-1.5 rounded-full ${engineStatus?.status === 'Online' ? 'bg-[#22c55e] shadow-[0_0_5px_#22c55e]' : 'bg-red-500 shadow-[0_0_5px_red]'}`}></span>
              <span className="text-white">Engine: {engineStatus ? engineStatus.status : 'Loading...'}</span>
            </div>
            <div className="mt-1 text-[#52525b] opacity-80 pl-3.5">{engineStatus ? engineStatus.version : '...'}</div>
          </div>
        </div>

        {/* Center menu */}
        <div className="hidden md:flex items-center space-x-6">
          <button
            onClick={() => onNavigate('landing')}
            className={`font-mono text-xs uppercase tracking-widest transition-all ${
              currentView === 'landing' ? 'text-[#22c55e]' : 'text-[#a1a1aa] hover:text-white'
            }`}
            id="nav-link-home"
          >
            Home
          </button>
          <button
            onClick={() => onNavigate('dashboard')}
            className={`font-mono text-xs uppercase tracking-widest transition-all ${
              currentView === 'dashboard' ? 'text-[#22c55e]' : 'text-[#a1a1aa] hover:text-white'
            }`}
            id="nav-link-dashboard"
          >
            Console
          </button>
        </div>

        {/* Right side information (Credits, Profile, Actions) */}
        <div className="flex items-center space-x-4">
          {userEmail ? (
            <>
              {/* Credits Indicator */}
              <div 
                onClick={() => onNavigate('dashboard')}
                className="flex items-center space-x-2 bg-[#0c0c0e] border border-[#27272a] hover:border-[#22c55e]/45 rounded-md px-3 py-1.5 transition-all text-[#a1a1aa] cursor-pointer text-xs font-mono"
                id="navbar-credits-pill"
              >
                <Coins className="w-3.5 h-3.5 text-[#22c55e]" />
                <span>
                  Credits: <strong className="text-[#22c55e]">{credits}</strong>
                </span>
              </div>

              {/* User Email Info / Sign Out */}
              <div className="flex items-center space-x-3 border-l border-[#27272a] pl-4">
                <div className="hidden lg:flex flex-col items-end text-right">
                  <span className="text-xs text-[#a1a1aa] font-mono flex items-center space-x-1.5">
                    <User className="w-3 h-3 text-[#52525b]" />
                    <span>{userEmail}</span>
                  </span>
                </div>
                <button
                  onClick={onLogout}
                  className="p-1.5 rounded bg-[#18181b] border border-[#27272a] text-[#a1a1aa] hover:text-[#f87171] hover:border-[#f87171]/20 transition-all"
                  title="Sign Out"
                  id="navbar-logout-btn"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            </>
          ) : (
            <button
              onClick={onLoginClick}
              className="px-4 py-2 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono tracking-wider font-bold rounded transition-all shadow-md flex items-center space-x-2"
              id="navbar-login-btn"
            >
              <span>Get Started</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </nav>
  );
}
