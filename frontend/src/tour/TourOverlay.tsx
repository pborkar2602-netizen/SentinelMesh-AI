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
  const cardRef = useRef<HTMLDivElement>(null);
  const [cardHeight, setCardHeight] = useState(320);

  const step: TourStep = TOUR_STEPS[currentStepIndex];

  // Measure card height whenever step changes or modal opens
  useEffect(() => {
    if (!isOpen) return;
    const measure = () => {
      if (cardRef.current) {
        const h = cardRef.current.offsetHeight;
        if (h > 60) setCardHeight(h);
      }
    };
    measure();
    const t = setTimeout(measure, 50);
    return () => clearTimeout(t);
  }, [currentStepIndex, isOpen]);

  // Update target rect and scroll into view when step changes
  useEffect(() => {
    if (!isOpen) return;

    const el = document.getElementById(step.targetId);
    if (el) {
      el.classList.add('in');
      let parent = el.parentElement;
      while (parent) {
        if (parent.classList.contains('rv')) parent.classList.add('in');
        parent = parent.parentElement;
      }
      if (step.targetId !== 'hd') {
        const scrollBlock = step.position === 'top' ? 'end' : step.position === 'bottom' ? 'start' : 'center';
        el.scrollIntoView({ behavior: 'smooth', block: scrollBlock, inline: 'nearest' });
      }
    }

    const updateBoundingBox = () => {
      const element = document.getElementById(step.targetId);
      if (element) {
        setTargetRect(element.getBoundingClientRect());
      } else {
        setTargetRect(null);
      }
    };

    updateBoundingBox();
    const t1 = setTimeout(updateBoundingBox, 80);
    const t2 = setTimeout(updateBoundingBox, 200);
    const t3 = setTimeout(updateBoundingBox, 450);
    const t4 = setTimeout(updateBoundingBox, 800);

    window.addEventListener('resize', updateBoundingBox);
    window.addEventListener('scroll', updateBoundingBox, { passive: true });

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      window.removeEventListener('resize', updateBoundingBox);
      window.removeEventListener('scroll', updateBoundingBox);
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

  // Safe clamping calculations
  const PADDING = 16;
  const CARD_WIDTH = Math.min(400, window.innerWidth - PADDING * 2);
  const measuredHeight = Math.max(260, Math.min(window.innerHeight - PADDING * 2, cardHeight));

  const cardStyle: React.CSSProperties = {
    position: 'fixed',
    zIndex: 99999,
    width: `${CARD_WIDTH}px`,
    maxWidth: `calc(100vw - ${PADDING * 2}px)`,
    maxHeight: `calc(100vh - ${PADDING * 2}px)`,
    overflowY: 'auto',
  };

  if (targetRect) {
    const spaceBelow = window.innerHeight - targetRect.bottom;
    const spaceAbove = targetRect.top;

    let computedTop = PADDING;
    let computedLeft = targetRect.left + (targetRect.width / 2) - (CARD_WIDTH / 2);

    if (step.position === 'right' && (targetRect.right + PADDING + CARD_WIDTH <= window.innerWidth - PADDING)) {
      computedLeft = targetRect.right + PADDING;
      computedTop = Math.max(PADDING, Math.min(targetRect.top, window.innerHeight - measuredHeight - PADDING));
    } else if (step.position === 'left' && (targetRect.left - PADDING - CARD_WIDTH >= PADDING)) {
      computedLeft = targetRect.left - CARD_WIDTH - PADDING;
      computedTop = Math.max(PADDING, Math.min(targetRect.top, window.innerHeight - measuredHeight - PADDING));
    } else if (step.position === 'top' && spaceAbove >= measuredHeight + PADDING * 1.5) {
      computedTop = targetRect.top - measuredHeight - PADDING;
    } else if (step.position === 'bottom' && spaceBelow >= measuredHeight + PADDING * 1.5) {
      computedTop = targetRect.bottom + PADDING;
    } else if (spaceBelow >= measuredHeight + PADDING) {
      computedTop = targetRect.bottom + PADDING;
    } else if (spaceAbove >= measuredHeight + PADDING) {
      computedTop = targetRect.top - measuredHeight - PADDING;
    } else {
      // Pick direction with more available vertical room
      if (spaceBelow >= spaceAbove) {
        computedTop = targetRect.bottom + PADDING;
      } else {
        computedTop = targetRect.top - measuredHeight - PADDING;
      }
    }

    // Absolute viewport clamp: Never allow card to cross top or bottom viewport limits
    // For non-hero elements, keep at least 72px from top edge to avoid navigation bar collision
    const minTop = step.targetId === 'hd' ? PADDING : 72;
    const maxTop = Math.max(minTop, window.innerHeight - measuredHeight - PADDING);
    const clampedTop = Math.max(minTop, Math.min(maxTop, computedTop));

    const maxLeft = Math.max(PADDING, window.innerWidth - CARD_WIDTH - PADDING);
    const minLeft = PADDING;
    const clampedLeft = Math.max(minLeft, Math.min(maxLeft, computedLeft));

    cardStyle.top = `${clampedTop}px`;
    cardStyle.left = `${clampedLeft}px`;
  } else {
    // Center if element not found
    cardStyle.top = '50%';
    cardStyle.left = '50%';
    cardStyle.transform = 'translate(-50%, -50%)';
  }

  return (
    <div ref={overlayRef} className="fixed inset-0 z-[99990] pointer-events-auto" data-testid="guided-tour-overlay">
      {/* Click outside to close */}
      <div 
        className="absolute inset-0 cursor-default"
        onClick={onClose}
      />

      {/* Real Spotlight Cutout with crystal-clear center & dark outer shadow */}
      {targetRect && (
        <div
          className="fixed pointer-events-none rounded-2xl transition-all duration-300 ring-2 ring-emerald-400/90 shadow-[0_0_0_9999px_rgba(6,8,15,0.78),0_0_35px_rgba(52,211,153,0.45)] z-[99992]"
          style={{
            top: `${Math.max(4, targetRect.top - 6)}px`,
            left: `${Math.max(4, targetRect.left - 6)}px`,
            width: `${Math.min(window.innerWidth - 8, Math.max(30, targetRect.width + 12))}px`,
            height: `${Math.max(20, targetRect.height + 12)}px`,
          }}
        />
      )}
      {!targetRect && (
        <div className="fixed inset-0 bg-[#06080F]/78 z-[99991]" />
      )}

      {/* Tour Step Card */}
      <div
        ref={cardRef}
        data-testid="tour-card"
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
