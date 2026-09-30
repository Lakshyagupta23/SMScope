import React from 'react';
import { cn } from '../lib/utils';

interface GlitchButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  tag?: string;
}

export function GlitchButton({ children, tag = "R25", className, ...props }: GlitchButtonProps) {
  return (
    <button className={cn("cybr-btn", className)} {...props}>
      {children}<span aria-hidden>_</span>
      <span aria-hidden className="cybr-btn__glitch">{children}_</span>
      <span aria-hidden className="cybr-btn__tag">{tag}</span>
    </button>
  );
}
