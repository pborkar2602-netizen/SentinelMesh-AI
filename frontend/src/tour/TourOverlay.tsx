import React, { useEffect, useState, useRef } from 'react';
import { TOUR_STEPS, TourStep } from './steps';

interface TourOverlayProps {
  isOpen: boolean;
  onClose: () => void;
}

export const TourOverlay: React.FC<TourOverlayProps> = ({ isOpen, onClose }) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [targetRect, setTargetRect] = useState<DOMRect | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  const step: TourStep = TOUR_STEPS[currentStepIndex];

  // Update target rect and scroll into view when step changes
  useEffect(() => {
    if (!isOpen) return;

    const updateRect = () => {
      const el = document.getElementById(step.targetId);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
        setTimeout(() => {
          const rect = el.getBoundingClientRect();
          setTargetRect(rect);
        }, 350);
      } else {
        setTargetRect(null);
      }
    };

    updateRect();
    window.addEventListener('resize', updateRect);
    window.addEventListener('scroll', updateRect);

    return () => {
      window.removeEventListener('resize', updateRect);
      window.removeEventListener('scroll', updateRect);
    };
  }, [currentStepIndex, isOpen, step.targetId]);

  // Keyboard controls
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      } else if (e.key === 'ArrowRight' || e.key === ' ') {
        e.preventDefault();
        handleNext();
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        handlePrev();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, currentStepIndex]);

  if (!isOpen) return null;

  const handleNext = () => {
    if (currentStepIndex < TOUR_STEPS.length - 1) {
      setCurrentStepIndex(prev => prev + 1);
    } else {
      onClose();
    }
  };

  const handlePrev = () => {
    if (currentStepIndex > 0) {
      setCurrentStepIndex(prev => prev - 1);
    }
  };

  // Card positioning logic
  const cardStyle: React.CSSProperties = {
    position: 'fixed',
    zIndex: 99999,
    width: '380px',
    maxWidth: 'calc(100vw - 32px)',
  };

  if (targetRect) {
    const spaceBelow = window.innerHeight - targetRect.bottom;
    const spaceAbove = targetRect.top;
    const padding = 16;

    if (spaceBelow >= 240 || spaceBelow >= spaceAbove) {
      // Position below target
      cardStyle.top = `${Math.min(window.innerHeight - 260, targetRect.bottom + padding)}px`;
      cardStyle.left = `${Math.max(16, Math.min(window.innerWidth - 396, targetRect.left + (targetRect.width / 2) - 190))}px`;
    } else {
      // Position above target
      cardStyle.bottom = `${Math.min(window.innerHeight - 100, window.innerHeight - targetRect.top + padding)}px`;
      cardStyle.left = `${Math.max(16, Math.min(window.innerWidth - 396, targetRect.left + (targetRect.width / 2) - 190))}px`;
    }
  } else {
    // Center if element not found
    cardStyle.top = '50%';
    cardStyle.left = '50%';
    cardStyle.transform = 'translate(-50%, -50%)';
  }

  return (
    <div ref={overlayRef} className="fixed inset-0 z-[99990] pointer-events-auto" data-testid="guided-tour-overlay">
      {/* Dark backdrop with blur */}
      <div 
        className="absolute inset-0 bg-[#06080F]/75 backdrop-blur-sm transition-opacity duration-300"
        onClick={onClose}
      />

      {/* Spotlight cutout border around targeted element */}
      {targetRect && (
        <div
          className="absolute pointer-events-none rounded-xl transition-all duration-300 ring-2 ring-emerald-400/80 shadow-[0_0_35px_rgba(52,211,153,0.35)]"
          style={{
            top: `${Math.max(0, targetRect.top - 8)}px`,
            left: `${Math.max(0, targetRect.left - 8)}px`,
            width: `${targetRect.width + 16}px`,
            height: `${targetRect.height + 16}px`,
          }}
        />
      )}

      {/* Tour Step Card */}
      <div
        style={cardStyle}
        className="bg-[#0D121F]/95 border border-white/15 rounded-2xl p-5 shadow-2xl backdrop-blur-xl animate-in fade-in zoom-in-95 duration-200"
        onClick={e => e.stopPropagation()}
      >
        {/* Header with badge and step counter */}
        <div className="flex items-center justify-between gap-2 mb-3">
          <span className="text-[11px] font-mono tracking-wider uppercase px-2.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold">
            {step.badge || `Step ${currentStepIndex + 1}`}
          </span>
          <span className="text-xs text-slate-400 font-mono">
            {currentStepIndex + 1} / {TOUR_STEPS.length}
          </span>
        </div>

        {/* Title */}
        <h3 className="text-base font-semibold text-white tracking-tight mb-2">
          {step.title}
        </h3>

        {/* Description */}
        <p className="text-sm text-slate-300 leading-relaxed mb-5">
          {step.description}
        </p>

        {/* Action Controls */}
        <div className="flex items-center justify-between pt-3 border-t border-white/10">
          <button
            onClick={onClose}
            className="text-xs font-mono text-slate-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-white/5"
          >
            Skip tour (Esc)
          </button>

          <div className="flex items-center gap-2">
            {currentStepIndex > 0 && (
              <button
                onClick={handlePrev}
                className="text-xs font-medium px-3 py-1.5 rounded-lg border border-white/15 bg-white/5 text-slate-200 hover:bg-white/10 transition-colors"
              >
                Back
              </button>
            )}
            <button
              onClick={handleNext}
              className="text-xs font-medium px-3.5 py-1.5 rounded-lg bg-emerald-500 text-slate-950 font-semibold hover:bg-emerald-400 transition-colors shadow-lg shadow-emerald-500/20"
            >
              {currentStepIndex === TOUR_STEPS.length - 1 ? 'Finish' : 'Next →'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
