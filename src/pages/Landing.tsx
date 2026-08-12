import HeroSection from '../components/landing/HeroSection.js';
import PricingSection from '../components/landing/PricingSection.js';
import McpSection from '../components/landing/McpSection.js';
import SampleReportSection from '../components/landing/SampleReportSection.js';
import FaqSection from '../components/landing/FaqSection.js';

interface LandingProps {
  onStartTrial: (initialUrl: string) => void;
  onNavigate: (view: string, arg?: string) => void;
  onSelectPack: (packName: 'single' | 'pack5' | 'pack20') => void;
}

export default function Landing({ onStartTrial, onNavigate, onSelectPack }: LandingProps) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] selection:bg-[#22c55e]/30 selection:text-[#22c55e]">
      <HeroSection onStartTrial={onStartTrial} />
      <PricingSection onSelectPack={onSelectPack} />
      <McpSection onNavigate={onNavigate} />
      <SampleReportSection />
      <FaqSection />

      {/* Footer */}
      <footer className="border-t border-[#27272a] bg-[#0c0c0e] py-12 text-[#a1a1aa] text-xs font-mono text-center">
        <div className="max-w-7xl mx-auto px-6 space-y-4">
          <p className="text-[11px]">Domain: <strong className="text-white">seclayerio.ai</strong> • Stack: React + Express + DeepSeek AI</p>
          <p className="text-[#52525b]">© 2026 Seclayer Penetration Technologies. All rights reserved. Support: hello@seclayerio.ai</p>
        </div>
      </footer>
    </div>
  );
}
