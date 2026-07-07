import React from 'react';

interface BrowserFrameProps {
  url: string;
  children: React.ReactNode;
}

// Wraps captured content in faux browser chrome (traffic-light dots + an address
// bar) so a screenshot reads as "this is the live site", not a raw image.
export default function BrowserFrame({ url, children }: BrowserFrameProps) {
  return (
    <div className="rounded-lg overflow-hidden border border-[#27272a] bg-[#0c0c0e]">
      <div className="flex items-center gap-2 px-3 py-2 bg-[#18181b] border-b border-[#27272a]">
        <div className="flex gap-1.5 shrink-0">
          <span className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[#febc2e]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
        </div>
        <div className="flex-1 min-w-0 mx-2">
          <div className="bg-[#0c0c0e] border border-[#27272a] rounded px-2.5 py-1 text-[11px] font-mono text-zinc-400 truncate text-center">
            {url}
          </div>
        </div>
        <span className="w-2.5 h-2.5 shrink-0" />
      </div>
      {children}
    </div>
  );
}
