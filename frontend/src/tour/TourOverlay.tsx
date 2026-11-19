import React, { useEffect, useState, useRef } from 'react';
import { TOUR_STEPS, TourStep } from './steps';
import { useDetailLevel } from '../context/DetailContext';

interface TourOverlayProps {
  isOpen: boolean;
  onClose: () => void;
}

export const TourOverlay: React.FC<TourOverlayProps> = ({ isOpen, onClose }) => {
  const { detailLevel } = useDetailLevel();
  const activeSteps = TOUR_STEPS.filter(
    (s) => !s.levels || s.levels.includes(detailLevel)
  );

  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [targetRect, setTargetRect] = useState<DOMRect | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const [measuredCardHeight, setMeasuredCardHeight] = useState(280);

  // Reset index when detailLevel changes
  useEffect(() => {
    setCurrentStepIndex(0);
  }, [detailLevel]);

  const safeIndex = Math.min(currentStepIndex, Math.max(0, activeSteps.length - 1));
  const step: TourStep = activeSteps[safeIndex] || TOUR_STEPS[0];

  // When tour is open, ensure document.body has .tour-active and all .rv elements are revealed
  useEffect(() => {
    if (isOpen) {
      document.body.classList.add('tour-active');
      document.querySelectorAll('.rv').forEach((el) => el.classList.add('in'));
    } else {
      document.body.classList.remove('tour-active');
    }
    return () => {
      document.body.classList.remove('tour-active');
    };
  }, [isOpen]);

  // Measure card height
  useEffect(() => {
    if (!isOpen) return;
    const measure = () => {
      if (cardRef.current) {
        const h = cardRef.current.offsetHeight;
        if (h > 60) setMeasuredCardHeight(h);
      }
    };
    measure();
    const t = setTimeout(measure, 50);
    return () => clearTimeout(t);
  }, [safeIndex, isOpen, step]);

  // Target element resolution & scrolling
  useEffect(() => {
    if (!isOpen) return;

    let el = document.getElementById(step.targetId);
    if (!el && (step.targetId === 'hero-badge' || step.targetId === 'hd')) {
      el = document.getElementById('hero-badge') || document.getElementById('hd') || document.getElementById('home');
    }

    if (el) {
      el.classList.add('in');
      let parent = el.parentElement;
      while (parent) {
        if (parent.classList.contains('rv')) parent.classList.add('in');
        parent = parent.parentElement;
      }
      el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
    }

    const updateBoundingBox = () => {
      let element = document.getElementById(step.targetId);
      if (!element && (step.targetId === 'hero-badge' || step.targetId === 'hd')) {
        element = document.getElementById('hero-badge') || document.getElementById('hd') || document.getElementById('home');
      }
      if (element) {
        const rect = element.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          setTargetRect(rect);
          return;
        }
      }
      setTargetRect(null);
    };

    updateBoundingBox();
    const t1 = setTimeout(updateBoundingBox, 100);
    const t2 = setTimeout(updateBoundingBox, 300);
    const t3 = setTimeout(updateBoundingBox, 600);

    window.addEventListener('resize', updateBoundingBox);
    window.addEventListener('scroll', updateBoundingBox, { passive: true });

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      window.removeEventListener('resize', updateBoundingBox);
      window.removeEventListener('scroll', updateBoundingBox);
    };
  }, [safeIndex, isOpen, step.targetId]);

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
  }, [isOpen, safeIndex, activeSteps.length]);

  if (!isOpen) return null;

  const handleNext = () => {
    if (safeIndex < activeSteps.length - 1) {
      setCurrentStepIndex((prev) => prev + 1);
    } else {
      onClose();
    }
  };

  const handlePrev = () => {
    if (safeIndex > 0) {
      setCurrentStepIndex((prev) => prev - 1);
    }
  };

  // Safe clamping calculations
  const PADDING = 16;
  const CARD_WIDTH = Math.min(420, window.innerWidth - PADDING * 2);
  const cardH = Math.max(200, Math.min(window.innerHeight - PADDING * 2, measuredCardHeight));
  const winH = window.innerHeight;
  const winW = window.innerWidth;
  const maxTop = Math.max(PADDING, winH - cardH - PADDING);
  const maxLeft = Math.max(PADDING, winW - CARD_WIDTH - PADDING);

  const cardStyle: React.CSSProperties = {
    position: 'fixed',
    zIndex: 99999,
    width: `${CARD_WIDTH}px`,
    maxWidth: `calc(100vw - ${PADDING * 2}px)`,
    maxHeight: `calc(100vh - ${PADDING * 2}px)`,
    overflowY: 'auto',
  };

  if (targetRect) {
    let computedTop = PADDING;
    let computedLeft = targetRect.left + (targetRect.width / 2) - (CARD_WIDTH / 2);

    const roomBelow = winH - targetRect.bottom >= cardH + PADDING;
    const roomAbove = targetRect.top >= cardH + PADDING;
    const roomRight = winW - targetRect.right >= CARD_WIDTH + PADDING;
    const roomLeft = targetRect.left >= CARD_WIDTH + PADDING;

    if (step.position === 'right' && roomRight) {
      computedLeft = targetRect.right + PADDING;
      computedTop = targetRect.top;
    } else if (step.position === 'left' && roomLeft) {
      computedLeft = targetRect.left - CARD_WIDTH - PADDING;
      computedTop = targetRect.top;
    } else if (step.position === 'top' && roomAbove) {
      computedTop = targetRect.top - cardH - PADDING;
    } else if (step.position === 'bottom' && roomBelow) {
      computedTop = targetRect.bottom + PADDING;
    } else if (roomBelow) {
      computedTop = targetRect.bottom + PADDING;
    } else if (roomAbove) {
      computedTop = targetRect.top - cardH - PADDING;
    } else {
      // Pick direction with more available vertical room
      computedTop = (winH - targetRect.bottom >= targetRect.top)
        ? targetRect.bottom + PADDING
        : targetRect.top - cardH - PADDING;
    }

    // Absolute viewport clamp: Never allow card to cross viewport edges
    const clampedTop = Math.max(PADDING, Math.min(maxTop, computedTop));
    const clampedLeft = Math.max(PADDING, Math.min(maxLeft, computedLeft));

    cardStyle.top = `${clampedTop}px`;
    cardStyle.left = `${clampedLeft}px`;
  } else {
    // Center if element not found
    cardStyle.top = `${Math.max(PADDING, (winH - cardH) / 2)}px`;
    cardStyle.left = `${Math.max(PADDING, (winW - CARD_WIDTH) / 2)}px`;
  }

  return (
    <div ref={overlayRef} className="fixed inset-0 z-[99990] pointer-events-auto" data-testid="guided-tour-overlay">
      {/* Click outside to close */}
      <div 
        className="absolute inset-0 cursor-default"
        onClick={onClose}
      />

      {/* Spotlight Cutout with soft glow and clear backdrop */}
      {targetRect && (
        <div
          className="fixed pointer-events-none rounded-2xl transition-all duration-300 ring-2 ring-emerald-400/80 shadow-[0_0_0_9999px_rgba(8,12,24,0.65),0_0_30px_rgba(52,211,153,0.35)] z-[99992]"
          style={{
            top: `${Math.max(4, targetRect.top - 6)}px`,
            left: `${Math.max(4, targetRect.left - 6)}px`,
            width: `${Math.min(window.innerWidth - 8, Math.max(30, targetRect.width + 12))}px`,
            height: `${Math.max(20, targetRect.height + 12)}px`,
          }}
        />
      )}
      {!targetRect && (
        <div className="fixed inset-0 bg-[#080C18]/65 backdrop-blur-[2px] z-[99991]" />
      )}

      {/* Tour Step Card */}
      <div
        ref={cardRef}
        data-testid="tour-card"
        style={cardStyle}
        className="bg-[#0B101D]/95 border border-white/20 rounded-2xl p-5 shadow-2xl backdrop-blur-xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header with badge and step counter */}
        <div className="flex items-center justify-between gap-2 mb-3">
          <span className="text-[11px] font-mono tracking-wider uppercase px-2.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold">
            {step.badge || `Step ${safeIndex + 1}`}
          </span>
          <span className="text-xs text-slate-400 font-mono">
            {safeIndex + 1} / {activeSteps.length}
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
            {safeIndex > 0 && (
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
              {safeIndex === activeSteps.length - 1 ? 'Finish' : 'Next →'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
