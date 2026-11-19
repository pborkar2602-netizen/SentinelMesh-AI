import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

export type DetailLevel = 'simple' | 'story' | 'expert';

interface DetailContextType {
  detailLevel: DetailLevel;
  setDetailLevel: (level: DetailLevel) => void;
  cycleDetailLevel: () => void;
}

const DetailContext = createContext<DetailContextType | undefined>(undefined);

export const DetailProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [detailLevel, setDetailLevelState] = useState<DetailLevel>(() => {
    try {
      const saved = localStorage.getItem('sentinel_detail_level');
      if (saved === 'simple' || saved === 'story' || saved === 'expert') {
        return saved as DetailLevel;
      }
    } catch {}
    return 'story'; // Default is Story
  });

  const setDetailLevel = useCallback((level: DetailLevel) => {
    setDetailLevelState(level);
    try {
      localStorage.setItem('sentinel_detail_level', level);
    } catch {}
  }, []);

  const cycleDetailLevel = useCallback(() => {
    setDetailLevelState((prev) => {
      let next: DetailLevel = 'story';
      if (prev === 'simple') next = 'story';
      else if (prev === 'story') next = 'expert';
      else if (prev === 'expert') next = 'simple';
      try {
        localStorage.setItem('sentinel_detail_level', next);
      } catch {}
      return next;
    });
  }, []);

  // Listen to Key D to cycle detail level
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }
      if (e.key === 'd' || e.key === 'D') {
        e.preventDefault();
        cycleDetailLevel();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [cycleDetailLevel]);

  return (
    <DetailContext.Provider value={{ detailLevel, setDetailLevel, cycleDetailLevel }}>
      {children}
    </DetailContext.Provider>
  );
};

export const useDetailLevel = (): DetailContextType => {
  const context = useContext(DetailContext);
  if (!context) {
    throw new Error('useDetailLevel must be used within a DetailProvider');
  }
  return context;
};
