import { useState, useEffect, useCallback, useRef } from 'react';
import { ROUTES, normalizeRoute, getRouteDef } from '../routes';

interface UseNavigationOptions {
  onToggleTour?: () => void;
}

export function useNavigation({ onToggleTour }: UseNavigationOptions = {}) {
  const [currentPath, setCurrentPath] = useState<string>(() =>
    normalizeRoute(window.location.pathname)
  );
  const activeRoute = getRouteDef(currentPath);

  const [navOpen, setNavOpen] = useState(false);
  const [indicatorStyle, setIndicatorStyle] = useState<{ left: number; width: number }>({
    left: 0,
    width: 0,
  });

  const navCloseTimerRef = useRef<any>(null);
  const buttonsRef = useRef<Record<string, HTMLButtonElement | null>>({});
  const lastScrollYRef = useRef(0);
  const upAccumulatorRef = useRef(0);

  const updateIndicator = useCallback((routeId: string) => {
    const btn = buttonsRef.current[routeId];
    if (btn) {
      setIndicatorStyle({ left: btn.offsetLeft, width: btn.offsetWidth });
    }
  }, []);

  const openNav = useCallback(() => {
    if (navCloseTimerRef.current) clearTimeout(navCloseTimerRef.current);
    setNavOpen(true);
    requestAnimationFrame(() => updateIndicator(activeRoute.id));
  }, [activeRoute.id, updateIndicator]);

  const closeNav = useCallback((delayMs = 0) => {
    if (navCloseTimerRef.current) clearTimeout(navCloseTimerRef.current);
    if (delayMs <= 0) {
      setNavOpen(false);
    } else {
      navCloseTimerRef.current = setTimeout(() => setNavOpen(false), delayMs);
    }
  }, []);

  const navigate = useCallback(
    (path: string) => {
      const target = normalizeRoute(path);
      if (target !== normalizeRoute(window.location.pathname)) {
        window.history.pushState({}, '', target);
      }
      setCurrentPath(target);
      window.scrollTo({ top: 0, behavior: 'auto' });
      const route = getRouteDef(target);
      requestAnimationFrame(() => updateIndicator(route.id));
      closeNav(220);
    },
    [closeNav, updateIndicator]
  );

  useEffect(() => {
    const onPopState = () => {
      const norm = normalizeRoute(window.location.pathname);
      setCurrentPath(norm);
      const route = getRouteDef(norm);
      requestAnimationFrame(() => updateIndicator(route.id));
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [updateIndicator]);

  useEffect(() => {
    requestAnimationFrame(() => updateIndicator(activeRoute.id));
  }, [activeRoute.id, navOpen, updateIndicator]);

  // Cursor glow & card spotlight tracking
  useEffect(() => {
    const cur = document.getElementById('cur');
    const onMove = (e: PointerEvent) => {
      if (cur) cur.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
      const target = e.target as HTMLElement | null;
      const card = target?.closest?.('.card') as HTMLElement | null;
      if (card) {
        const r = card.getBoundingClientRect();
        card.style.setProperty('--mx', `${e.clientX - r.left}px`);
        card.style.setProperty('--my', `${e.clientY - r.top}px`);
      }
    };
    window.addEventListener('pointermove', onMove, { passive: true });
    return () => window.removeEventListener('pointermove', onMove);
  }, []);

  // Scroll progress line + upward-scroll nav auto-reveal
  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY;
      const docHeight = Math.max(1, document.body.scrollHeight - window.innerHeight);
      const scrollFraction = Math.min(1, Math.max(0, y / docHeight));
      const pg = document.getElementById('pg');
      if (pg) pg.style.transform = `scaleX(${scrollFraction})`;

      if (y < lastScrollYRef.current) {
        upAccumulatorRef.current += lastScrollYRef.current - y;
      } else {
        upAccumulatorRef.current = 0;
      }
      if (upAccumulatorRef.current > 200 && y > 200) {
        openNav();
        closeNav(2200);
        upAccumulatorRef.current = 0;
      }
      lastScrollYRef.current = y;
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, [openNav, closeNav]);

  // Keyboard navigation hotkeys (N, T, 1-6, Escape)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (/INPUT|TEXTAREA|SELECT/.test((e.target as HTMLElement)?.tagName || '')) return;
      if (e.key === 'n' || e.key === 'N') {
        if (navOpen) closeNav(0);
        else openNav();
      }
      if (e.key === 't' || e.key === 'T') {
        if (onToggleTour) onToggleTour();
      }
      if (e.key >= '1' && e.key <= '6') {
        const idx = parseInt(e.key, 10) - 1;
        if (ROUTES[idx]) navigate(ROUTES[idx].path);
      }
      if (e.key === 'Escape') {
        closeNav(0);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [navOpen, openNav, closeNav, navigate, onToggleTour]);

  return {
    currentPath,
    activeRoute,
    navOpen,
    indicatorStyle,
    buttonsRef,
    openNav,
    closeNav,
    navigate,
    updateIndicator,
  };
}
