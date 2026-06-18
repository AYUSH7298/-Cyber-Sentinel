import React, { useState, useEffect, useRef } from 'react';

// Types for the incoming WebSocket data
interface ThreatData {
  time: str;
  source: str;
  threat: str;
  level: str;
}

function App() {
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [liveThreats, setLiveThreats] = useState<ThreatData[]>([
    { time: '10:45 AM', source: '192.168.1.10', threat: 'Malware Injection', level: 'HIGH' },
    { time: '10:43 AM', source: 'sbi-kyc-alert.com', threat: 'Phishing Campaign', level: 'MEDIUM' },
    { time: '10:40 AM', source: '10.0.0.56', threat: 'Unauthorized Port Scan', level: 'LOW' }
  ]);
  const ws = useRef<WebSocket | null>(null);

  // WebSocket Connection for Live Auto-Refresh
  useEffect(() => {
    ws.current = new WebSocket('ws://localhost:8080/ws/live-feed');
    
    ws.current.onmessage = (event) => {
      const newThreat = JSON.parse(event.data);
      // Auto-refresh: add new threat to the top of the feed
      setLiveThreats((prev) => [newThreat, ...prev].slice(0, 10)); 
    };

    return () => {
      ws.current?.close();
    };
  }, []);

  // Apply dark mode class to html element for Tailwind's dark: utility if needed,
  // but we will use dynamic classes directly here for absolute control.
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDarkMode]);

  // Dynamic Theme Colors
  const theme = {
    bg: isDarkMode ? 'bg-[#020617]' : 'bg-[#f0f4f8]',
    textMain: isDarkMode ? 'text-white' : 'text-slate-900',
    textMuted: isDarkMode ? 'text-gray-400' : 'text-slate-500',
    glassCard: isDarkMode ? 'glass-card-dark' : 'glass-card-light',
    mapBg: isDarkMode ? 'bg-[#0b0f10] border-white/5' : 'bg-slate-200 border-black/5',
    mapGrid: isDarkMode ? 'radial-gradient(circle at center, #22d3ee 1px, transparent 1px)' : 'radial-gradient(circle at center, #64748b 1px, transparent 1px)',
    itemHover: isDarkMode ? 'hover:bg-white/10' : 'hover:bg-black/5',
    itemBorder: isDarkMode ? 'border-white/5' : 'border-black/5',
    itemBg: isDarkMode ? 'bg-white/5' : 'bg-white',
  };

  return (
    <div className={`min-h-screen ${theme.bg} ${theme.textMain} p-4 md:p-8 font-sans transition-colors duration-300`}>
      {/* Navbar / Header */}
      <header className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cyber Sentinel</h1>
          <p className={`${theme.textMuted} text-sm font-medium`}>RAKSHAK Command Portal</p>
        </div>
        
        <div className="flex items-center space-x-6">
          {/* Core Engine Status */}
          <div className={`flex items-center space-x-2 px-4 py-2 rounded-full border ${isDarkMode ? 'bg-[#22d3ee]/20 border-[#22d3ee]/30 text-[#22d3ee]' : 'bg-[#0ea5e9]/10 border-[#0ea5e9]/30 text-[#0ea5e9]'}`}>
            <div className={`w-3 h-3 rounded-full animate-pulse ${isDarkMode ? 'bg-[#22d3ee]' : 'bg-[#0ea5e9]'}`}></div>
            <span className="text-sm font-bold tracking-wide uppercase">Core Engine Online</span>
          </div>

          {/* Theme Toggle */}
          <button 
            onClick={() => setIsDarkMode(!isDarkMode)}
            className={`p-2 rounded-full border transition-colors ${isDarkMode ? 'bg-white/10 border-white/20 hover:bg-white/20' : 'bg-white border-slate-300 hover:bg-slate-100 shadow-sm'}`}
            title="Toggle Light/Dark Mode"
          >
            {isDarkMode ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>
      </header>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className={`${theme.glassCard} p-6 border-l-4 ${isDarkMode ? 'border-l-[#22d3ee]' : 'border-l-[#0ea5e9]'} hover:scale-[1.02] transition-transform duration-300`}>
          <h3 className={`${theme.textMuted} text-sm mb-2 font-mono uppercase tracking-wider`}>Data Scanned</h3>
          <p className={`text-4xl font-bold ${isDarkMode ? 'text-[#22d3ee]' : 'text-[#0ea5e9]'}`}>1,240 <span className="text-xl">GB</span></p>
          <p className={`text-xs ${theme.textMuted} mt-2`}>+12% in last 24h</p>
        </div>
        
        <div className={`${theme.glassCard} p-6 border-l-4 border-l-amber-500 hover:scale-[1.02] transition-transform duration-300`}>
          <h3 className={`${theme.textMuted} text-sm mb-2 font-mono uppercase tracking-wider`}>Active Campaigns</h3>
          <p className="text-4xl font-bold text-amber-500">24</p>
          <p className={`text-xs ${theme.textMuted} mt-2`}>Ongoing coordinated attacks</p>
        </div>

        <div className={`${theme.glassCard} p-6 border-l-4 border-l-rose-500 hover:scale-[1.02] transition-transform duration-300 ${isDarkMode ? 'shadow-[0_0_20px_rgba(244,63,94,0.15)]' : 'shadow-[0_4px_20px_rgba(244,63,94,0.15)]'}`}>
          <h3 className={`${theme.textMuted} text-sm mb-2 font-mono uppercase tracking-wider`}>High-Risk Alerts</h3>
          <p className="text-4xl font-bold text-rose-500">18</p>
          <p className={`text-xs text-rose-500/80 mt-2 font-medium`}>Critical Threats Pending Action</p>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Geo Radar (Left 2/3) */}
        <div className={`lg:col-span-2 ${theme.glassCard} p-6`}>
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-bold">Geographic Heatmap</h2>
            <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold ${isDarkMode ? 'bg-[#22d3ee]/20 text-[#22d3ee]' : 'bg-[#0ea5e9] text-white shadow-sm'}`}>LIVE DATA</span>
          </div>
          {/* Placeholder for Map */}
          <div className={`w-full h-[400px] rounded-lg border relative overflow-hidden flex items-center justify-center transition-colors duration-300 ${theme.mapBg}`}>
            <div className="absolute inset-0 opacity-20" style={{ backgroundImage: theme.mapGrid, backgroundSize: '20px 20px' }}></div>
            
            {/* Fake Map Elements for Aesthetic */}
            <div className="z-10 relative w-3/4 h-3/4 border-2 border-dashed border-gray-500/30 rounded-3xl flex items-center justify-center">
               <div className="absolute top-1/4 left-1/3 w-8 h-8 bg-rose-500 rounded-full blur-xl opacity-70 animate-pulse"></div>
               <div className="absolute top-1/2 left-1/2 w-12 h-12 bg-amber-500 rounded-full blur-xl opacity-60 animate-pulse"></div>
               <div className="absolute bottom-1/3 right-1/4 w-16 h-16 bg-rose-500 rounded-full blur-2xl opacity-80 animate-pulse" style={{ animationDelay: '1s'}}></div>
               <p className={`${theme.textMuted} font-mono font-medium tracking-widest uppercase`}>[ Mapping Engine Active ]</p>
            </div>
          </div>
        </div>

        {/* Live Threat Feed (Right 1/3) */}
        <div className={`${theme.glassCard} p-6 flex flex-col h-[500px]`}>
          <h2 className="text-xl font-bold mb-6">Live Threat Feed</h2>
          
          {/* Column Headers */}
          <div className={`flex justify-between items-center px-4 pb-2 mb-2 border-b ${theme.itemBorder} text-xs font-bold uppercase tracking-wider ${theme.textMuted}`}>
             <span>Time & Source</span>
             <span>Level</span>
          </div>

          <div className="flex-1 overflow-y-auto pr-2 space-y-3">
            {liveThreats.map((threat, idx) => {
              // Dynamic coloring based on threat level
              let levelClass = '';
              if (threat.level === 'HIGH') {
                levelClass = isDarkMode ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-rose-100 text-rose-700 border border-rose-200';
              } else if (threat.level === 'MEDIUM') {
                levelClass = isDarkMode ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-amber-100 text-amber-700 border border-amber-200';
              } else {
                levelClass = isDarkMode ? 'bg-[#22d3ee]/20 text-[#22d3ee] border border-[#22d3ee]/30' : 'bg-sky-100 text-sky-700 border border-sky-200';
              }

              return (
                <div key={idx} className={`${theme.itemBg} p-4 rounded-lg border ${theme.itemBorder} ${theme.itemHover} transition-colors cursor-pointer shadow-sm animate-pulse-once`}>
                  <div className="flex justify-between items-start mb-2">
                    <span className={`text-xs font-mono font-medium ${theme.textMuted}`}>{threat.time}</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${levelClass}`}>{threat.level}</span>
                  </div>
                  <h4 className="font-bold">{threat.threat}</h4>
                  <p className={`text-sm mt-1 truncate ${theme.textMuted}`}>Src: {threat.source}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
