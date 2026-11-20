import React, { useState, useEffect } from 'react';
import { ROUTES } from './routes';
import { TourOverlay } from './tour/TourOverlay';
import { OverviewPage } from './pages/OverviewPage';
import { ConsolePage } from './pages/ConsolePage';
import { PlaygroundPage } from './pages/PlaygroundPage';
import { AuditPrivacyPage } from './pages/AuditPrivacyPage';
import { BenchmarksPage } from './pages/BenchmarksPage';
import { ArchitecturePage } from './pages/ArchitecturePage';
import { useGatewayEvents } from './hooks/useGatewayEvents';
import { usePolicyRuntime } from './hooks/usePolicyRuntime';
import { useNavigation } from './hooks/useNavigation';

export function App() {
  const [tourOpen, setTourOpen] = useState<boolean>(() => {
    return new URLSearchParams(window.location.search).get('tour') === '1';
  });
  const [showToolReturn, setShowToolReturn] = useState(false);

  const policyRuntime = usePolicyRuntime();
  const { processAuditEventForChain, fetchStats } = policyRuntime;

  const gatewayEvents = useGatewayEvents({
    onAuditEvent: processAuditEventForChain,
    onIncidentAlert: fetchStats,
    onDemoReset: fetchStats,
  });

  const {
    currentPath,
    activeRoute,
    navOpen,
    indicatorStyle,
    buttonsRef,
    openNav,
    closeNav,
    navigate,
  } = useNavigation({
    onToggleTour: () => setTourOpen((prev) => !prev),
  });

  // Initial load
  useEffect(() => {
    fetchStats();
    gatewayEvents.fetchEvents();
  }, [fetchStats, gatewayEvents.fetchEvents]);

  return (
    <>
      <div className="cursor" id="cur" aria-hidden="true" />
      <div id="pg" aria-hidden="true" />
      <div id="hz" onMouseEnter={openNav} aria-hidden="true" />

      {/* Collapsible Floating Navigation (EXACT morph & animation preserved) */}
      <div id="nv" className={navOpen ? 'open' : ''}>
        <button
          id="hd"
          aria-label="Open navigation"
          onMouseEnter={openNav}
          onClick={openNav}
          data-testid="nav-pill"
        >
          <span
            className={`w-1.5 h-1.5 rounded-full mr-1.5 transition-all ${
              gatewayEvents.wsConnected
                ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]'
                : 'bg-amber-400'
            }`}
            title={gatewayEvents.wsConnected ? 'WebSocket live connected' : 'Connecting to gateway events...'}
          />
          <span id="hl">{activeRoute.label}</span>
          <s>hover · N</s>
        </button>

        <nav
          id="bar"
          aria-label="Primary pages"
          onMouseLeave={() => closeNav(650)}
        >
          <span
            className="ind"
            id="ind"
            style={{
              left: `${indicatorStyle.left}px`,
              width: `${indicatorStyle.width}px`,
            }}
          />
          {ROUTES.map((route, i) => (
            <button
              key={route.id}
              ref={(el) => {
                buttonsRef.current[route.id] = el;
              }}
              data-id={route.id}
              data-testid={`nav-link-${route.id}`}
              className={activeRoute.id === route.id ? 'on' : ''}
              style={{ '--i': i } as React.CSSProperties}
              onClick={() => navigate(route.path)}
            >
              {route.label}
              <kbd>{i + 1}</kbd>
            </button>
          ))}

          <div className="flex items-center pl-2 ml-1 border-l border-white/10">
            <button
              type="button"
              style={{ '--i': ROUTES.length } as React.CSSProperties}
              onClick={() => {
                closeNav(0);
                setTourOpen(true);
              }}
              data-testid="nav-tour-btn"
            >
              Tour
              <kbd>T</kbd>
            </button>
          </div>
        </nav>
      </div>

      {/* Active Route View */}
      <main key={currentPath} className="page-enter">
        {activeRoute.id === 'overview' && (
          <OverviewPage
            events={gatewayEvents.events}
            attackPulseTrigger={gatewayEvents.attackPulseTrigger}
            tickerLines={gatewayEvents.tickerLines}
            onNavigate={navigate}
            onStartTour={() => setTourOpen(true)}
          />
        )}
        {activeRoute.id === 'console' && (
          <ConsolePage
            stats={policyRuntime.stats}
            policyMode={policyRuntime.policyMode}
            events={gatewayEvents.events}
            attackPulseTrigger={gatewayEvents.attackPulseTrigger}
            feedLines={gatewayEvents.feedLines}
            showToolReturn={showToolReturn}
            onToggleToolReturn={setShowToolReturn}
            liveAttackRunning={policyRuntime.liveAttackRunning}
            chainSteps={policyRuntime.chainSteps}
            stepActive={policyRuntime.stepActive}
            stepClasses={policyRuntime.stepClasses}
            riskGauge={policyRuntime.riskGauge}
            barWidths={policyRuntime.barWidths}
            verdict={policyRuntime.verdict}
            onSwitchMode={policyRuntime.switchMode}
            onRunSimulation={policyRuntime.triggerRealLiveAttack}
            onTriggerRealAttack={policyRuntime.triggerRealLiveAttack}
            onRefreshStats={policyRuntime.fetchStats}
          />
        )}
        {activeRoute.id === 'playground' && <PlaygroundPage />}
        {activeRoute.id === 'audit' && (
          <AuditPrivacyPage
            stats={policyRuntime.stats}
            policyMode={policyRuntime.policyMode}
            events={gatewayEvents.events}
            onSwitchMode={policyRuntime.switchMode}
          />
        )}
        {activeRoute.id === 'benchmarks' && <BenchmarksPage />}
        {activeRoute.id === 'architecture' && <ArchitecturePage stats={policyRuntime.stats} />}
      </main>

      {/* Footer */}
      <div className="w">
        <footer>
          <span>
            <b>SentinelMesh AI</b> · Runtime Security Gateway for AI Agents
          </span>
          <span>Synthetic demo telemetry · Zero real personal data</span>
        </footer>
      </div>

      {/* Cross-Page Interactive Guided Tour */}
      <TourOverlay
        isOpen={tourOpen}
        currentRoute={currentPath}
        onNavigate={navigate}
        onClose={() => setTourOpen(false)}
      />
    </>
  );
}

export default App;
