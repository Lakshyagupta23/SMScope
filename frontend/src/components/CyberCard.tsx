import React from 'react';
import { cn } from '../lib/utils';
import { BorderTrail } from '@/components/motion-primitives/border-trail';

interface CyberCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  trailColor?: string;
}

export function CyberCard({ children, className, trailColor, ...props }: CyberCardProps) {
  return (
    <div className={cn("cyber-card flex flex-col", className)} {...props}>
      <div className="cyber-card-decor"></div>
      <div className="cyber-card-decor-bottom"></div>
      {trailColor && <BorderTrail className={trailColor} size={120} />}
      <div className="relative z-10 w-full h-full flex flex-col">
        {children}
      </div>
    </div>
  );
}
