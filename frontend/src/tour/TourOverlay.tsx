import React, { useEffect, useState, useRef } from 'react';
import { TOUR_STEPS, TourStep } from './steps';

interface TourOverlayProps {
  isOpen: boolean;
  currentRoute: string;
  onNavigate: (path: string) => void;
  onClose: () => void;
}

export const TourOverlay: React.FC<TourOverlayProps> = ({
  isOpen,
  currentRoute,
  onNavigate,
  onClose,
}) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(() => {
    const routeIdx = TOUR_STEPS.findIndex((s) => s.route === currentRoute);
    return routeIdx >= 0 ? routeIdx : 0;
  });
  const [targetRect, setTargetRect] = useState<DOMRect | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const [measuredCardHeight, setMeasuredCardHeight] = useState(280);
  const prevOpenRef = useRef(false);

  // Context-aware start: when tour opens, jump to the first step matching currentRoute
  useEffect(() => {
    if (isOpen && !prevOpenRef.current) {
      const routeIdx = TOUR_STEPS.findIndex((s) => s.route === currentRoute);
      if (routeIdx >= 0) {
        setCurrentStepIndex(routeIdx);
      }
    }
    prevOpenRef.current = isOpen;
  }, [isOpen, currentRoute]);

  const safeIndex = Math.min(currentStepIndex, Math.max(0, TOUR_STEPS.length - 1));
  const step: TourStep = TOUR_STEPS[safeIndex] || TOUR_STEPS[0];

  // Body tour class cleanup
  useEffect(() => {
    if (isOpen) {
      document.body.classList.add('tour-active');
    } else {
      document.body.classList.remove('tour-active');
    }
    return () => {
      document.body.classList.remove('tour-active');
    };
  }, [isOpen]);

  // Auto-navigate when step belongs to a different route
  useEffect(() => {
    if (!isOpen) return;
    if (step.route !== currentRoute) {
      onNavigate(step.route);
    }
  }, [isOpen, step.route, currentRoute, onNavigate]);

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
    const t = setTimeout(measure, 60);
    return () => clearTimeout(t);
  }, [safeIndex, isOpen, step]);

  // Resolve target bounding box on active route
  useEffect(() => {
    if (!isOpen) return;

    let cancelled = false;

    const findTargetElement = (): HTMLElement | null => {
      let el = document.getElementById(step.targetId);
      if (!el && step.targetId === 'known-issues-header') {
        el = document.getElementById('known-issues-list');
      }
      return el;
    };

    const updateBoundingBox = () => {
      if (cancelled) return;
      const element = findTargetElement();
      if (element) {
        const rect = element.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          setTargetRect(rect);
          return rect;
        }
      }
      setTargetRect(null);
      return null;
    };

    const scrollTargetIntoView = () => {
      if (cancelled) return;
      const el = findTargetElement();
      if (el) {
        el.scrollIntoView({ behavior: 'auto', block: 'center', inline: 'nearest' });
        const rect = el.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          setTargetRect(rect);
        }
      }
    };

    scrollTargetIntoView();
    const timers = [
      setTimeout(scrollTargetIntoView, 60),
      setTimeout(scrollTargetIntoView, 200),
      setTimeout(scrollTargetIntoView, 450),
      setTimeout(updateBoundingBox, 750),
      setTimeout(updateBoundingBox, 1200),
    ];

    let ro: ResizeObserver | null = null;
    const el = findTargetElement();
    if (el && typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(() => {
        if (!cancelled) {
          updateBoundingBox();
        }
      });
      ro.observe(el);
      if (el.parentElement) {
        ro.observe(el.parentElement);
      }
    }

    window.addEventListener('resize', updateBoundingBox);
    window.addEventListener('scroll', updateBoundingBox, { passive: true });

    return () => {
      cancelled = true;
      timers.forEach(clearTimeout);
      if (ro) ro.disconnect();
      window.removeEventListener('resize', updateBoundingBox);
      window.removeEventListener('scroll', updateBoundingBox);
    };
  }, [safeIndex, isOpen, step.targetId, currentRoute]);

  const handleNext = () => {
    if (safeIndex < TOUR_STEPS.length - 1) {
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
  }, [isOpen, safeIndex]);

  if (!isOpen) return null;

  const PADDING = 16;
  const CARD_WIDTH = Math.min(430, window.innerWidth - PADDING * 2);
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
    let computedLeft = targetRect.left + targetRect.width / 2 - CARD_WIDTH / 2;

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
      computedTop =
        winH - targetRect.bottom >= targetRect.top
          ? targetRect.bottom + PADDING
          : targetRect.top - cardH - PADDING;
    }

    cardStyle.top = `${Math.max(PADDING, Math.min(maxTop, computedTop))}px`;
    cardStyle.left = `${Math.max(PADDING, Math.min(maxLeft, computedLeft))}px`;
  } else {
    cardStyle.top = `${Math.max(PADDING, (winH - cardH) / 2)}px`;
    cardStyle.left = `${Math.max(PADDING, (winW - CARD_WIDTH) / 2)}px`;
  }

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-[99990] pointer-events-none"
      data-testid="guided-tour-overlay"
    >
      {/* 4-quadrant interactive cutout: clicks outside close the tour, while spotlighted area remains interactive */}
      {targetRect ? (
        <>
          {/* Top backdrop */}
          <div
            className="fixed left-0 right-0 top-0 bg-[#080C18]/65 backdrop-blur-[1px] pointer-events-auto cursor-default z-[99991]"
            style={{ height: `${Math.max(0, targetRect.top - 6)}px` }}
            onClick={onClose}
          />
          {/* Bottom backdrop */}
          <div
            className="fixed left-0 right-0 bottom-0 bg-[#080C18]/65 backdrop-blur-[1px] pointer-events-auto cursor-default z-[99991]"
            style={{ top: `${Math.min(winH, targetRect.bottom + 6)}px` }}
            onClick={onClose}
          />
          {/* Left backdrop */}
          <div
            className="fixed left-0 bg-[#080C18]/65 backdrop-blur-[1px] pointer-events-auto cursor-default z-[99991]"
            style={{
              top: `${Math.max(0, targetRect.top - 6)}px`,
              height: `${Math.max(0, targetRect.height + 12)}px`,
              width: `${Math.max(0, targetRect.left - 6)}px`,
            }}
            onClick={onClose}
          />
          {/* Right backdrop */}
          <div
            className="fixed right-0 bg-[#080C18]/65 backdrop-blur-[1px] pointer-events-auto cursor-default z-[99991]"
            style={{
              top: `${Math.max(0, targetRect.top - 6)}px`,
              height: `${Math.max(0, targetRect.height + 12)}px`,
              left: `${Math.min(winW, targetRect.right + 6)}px`,
            }}
            onClick={onClose}
          />

          {/* Glowing target ring */}
          <div
            className="fixed pointer-events-none rounded-2xl transition-all duration-300 ring-2 ring-emerald-400/90 shadow-[0_0_35px_rgba(52,211,153,0.35)] z-[99992]"
            style={{
              top: `${Math.max(4, targetRect.top - 6)}px`,
              left: `${Math.max(4, targetRect.left - 6)}px`,
              width: `${Math.min(window.innerWidth - 8, Math.max(30, targetRect.width + 12))}px`,
              height: `${Math.max(20, targetRect.height + 12)}px`,
            }}
          />
        </>
      ) : (
        <div
          className="fixed inset-0 bg-[#080C18]/65 backdrop-blur-[2px] pointer-events-auto cursor-default z-[99991]"
          onClick={onClose}
        />
      )}

      {/* Floating Tour Card */}
      <div
        ref={cardRef}
        data-testid="tour-card"
        style={cardStyle}
        className="bg-[#0B101D]/95 border border-white/20 rounded-2xl p-5 shadow-2xl backdrop-blur-xl pointer-events-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-2 mb-2">
          <span className="text-[11px] font-mono tracking-wider uppercase px-2.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold">
            {step.badge || `Step ${safeIndex + 1}`}
          </span>
          <span className="text-xs text-slate-400 font-mono">
            {step.chapter} · {safeIndex + 1} / {TOUR_STEPS.length}
          </span>
        </div>

        {/* Mini-step progress dots */}
        <div className="flex items-center gap-1.5 mb-3" aria-label="Tour step navigation">
          {TOUR_STEPS.map((s, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => setCurrentStepIndex(idx)}
              className={`h-1.5 rounded-full transition-all duration-200 cursor-pointer ${
                idx === safeIndex
                  ? 'w-6 bg-emerald-400'
                  : 'w-1.5 bg-white/20 hover:bg-white/40'
              }`}
              title={`${s.badge}: ${s.title}`}
            />
          ))}
        </div>

        <h3 className="text-base font-semibold text-white tracking-tight mb-2 leading-snug">
          {step.title}
        </h3>

        <p className="text-sm text-slate-300 leading-relaxed mb-5 font-sans">
          {step.description}
        </p>

        <div className="flex items-center justify-between pt-3 border-t border-white/10">
          <button
            onClick={onClose}
            className="text-xs font-mono text-slate-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-white/5"
            data-testid="tour-close-btn"
          >
            Skip tour (Esc)
          </button>

          <div className="flex items-center gap-2">
            {safeIndex > 0 && (
              <button
                onClick={handlePrev}
                className="text-xs font-medium px-3 py-1.5 rounded-lg border border-white/15 bg-white/5 text-slate-200 hover:bg-white/10 transition-colors"
                data-testid="tour-prev-btn"
              >
                Back
              </button>
            )}
            <button
              onClick={handleNext}
              className="text-xs font-medium px-3.5 py-1.5 rounded-lg bg-emerald-500 text-slate-950 font-semibold hover:bg-emerald-400 transition-colors shadow-lg shadow-emerald-500/20"
              data-testid="tour-next-btn"
            >
              {safeIndex === TOUR_STEPS.length - 1 ? 'Finish' : 'Next →'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
