import React from 'react';
import { Shield, Zap, Sparkles, Clock, Moon, Sun, PanelLeftClose, PanelLeftOpen, FileCode2, FolderOpen } from 'lucide-react';

const navItems = [
  { id: 'products', label: 'Products', icon: FolderOpen },
  { id: 'static', label: 'Static Analysis', icon: Zap },
  { id: 'code', label: 'Code Security', icon: FileCode2 },
  { id: 'iac', label: 'IaC Analysis', icon: Shield },
  { id: 'ai', label: 'AI Analysis', icon: Sparkles },
  { id: 'history', label: 'History', icon: Clock },
];

export default function Sidebar({ activeTab, onTabChange, darkMode, onToggleDarkMode, collapsed, onCollapsedChange }) {
  return (
    <aside
      onKeyDown={event => { if (event.key === 'Escape' && !collapsed) onCollapsedChange(true); }}
      className={`
        fixed left-0 top-0 z-50 flex h-screen flex-col items-center
        transition-all duration-300 ease-in-out
        ${collapsed ? 'w-[68px]' : 'w-[220px]'}
        border-r border-brand-200 bg-white shadow-sm
        dark:border-brand-700 dark:bg-brand-900
      `}
    >
      <div
        className={`
          flex h-20 w-full shrink-0 items-center gap-2 px-3
          ${collapsed ? 'justify-center' : 'justify-between'}
        `}
      >
        {!collapsed && (
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-brand-primary shadow-sm">
              <Shield className="h-4 w-4 text-white" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="whitespace-nowrap text-sm font-semibold text-brand-950 dark:text-white">Aegis Threat</p>
              <p className="mt-0.5 whitespace-nowrap text-[10px] text-brand-500 dark:text-brand-400">Threat Modeling</p>
            </div>
          </div>
        )}
        <button
          type="button"
          onClick={() => onCollapsedChange(!collapsed)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
          aria-controls="main-navigation"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="group relative flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-brand-500 transition-colors hover:bg-brand-100 hover:text-brand-900 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-primary dark:text-brand-300 dark:hover:bg-brand-800 dark:hover:text-white"
        >
          {collapsed ? <PanelLeftOpen size={20} aria-hidden="true" /> : <PanelLeftClose size={20} aria-hidden="true" />}
          <span aria-hidden="true" className="pointer-events-none invisible absolute left-full z-50 ml-3 whitespace-nowrap rounded-md bg-brand-900 px-3 py-1.5 text-xs font-medium text-white opacity-0 shadow-lg group-hover:visible group-hover:opacity-100 group-focus-visible:visible group-focus-visible:opacity-100 dark:bg-brand-100 dark:text-brand-900">
            {collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          </span>
        </button>
      </div>

      <div className={`mb-3 h-px bg-brand-200 dark:bg-brand-700 ${collapsed ? 'w-8' : 'w-[calc(100%-2rem)]'}`} />

      <nav id="main-navigation" aria-label="Main navigation" className="flex w-full flex-1 flex-col gap-1 px-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              aria-label={item.label}
              aria-current={isActive ? 'page' : undefined}
              onClick={() => onTabChange(item.id)}
              title={collapsed ? item.label : undefined}
              className={`
                group relative flex w-full items-center gap-3 rounded-lg transition-colors duration-150
                ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
                ${isActive
                  ? 'bg-brand-100 text-brand-primary dark:bg-brand-800 dark:text-brand-100'
                  : 'text-brand-500 hover:bg-brand-50 hover:text-brand-800 dark:text-brand-400 dark:hover:bg-brand-800/60 dark:hover:text-brand-100'
                }
              `}
            >
              {isActive && (
                <div
                  className="absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r-full bg-brand-primary"
                />
              )}

              <div
                className={`
                  relative flex-shrink-0 transition-colors duration-200
                  ${isActive ? 'text-brand-primary dark:text-brand-100' : ''}
                `}
              >
                <Icon className="h-5 w-5" />
              </div>

              {!collapsed && (
                <span
                  className={`
                    whitespace-nowrap text-sm font-medium transition-colors duration-200
                    ${isActive ? 'text-brand-950 dark:text-white' : 'text-brand-600 group-hover:text-brand-900 dark:text-brand-400 dark:group-hover:text-white'}
                  `}
                >
                  {item.label}
                </span>
              )}

              {collapsed && (
                <div className="pointer-events-none absolute left-full ml-3 whitespace-nowrap rounded-lg bg-brand-900 px-3 py-1.5 text-xs font-medium text-white opacity-0 invisible shadow-xl transition-all duration-200 group-hover:visible group-hover:opacity-100 dark:bg-brand-100 dark:text-brand-900">
                  {item.label}
                  <div className="absolute right-full top-1/2 -translate-y-1/2 border-4 border-transparent border-r-brand-900 dark:border-r-brand-100" />
                </div>
              )}
            </button>
          );
        })}
      </nav>

      <div className="w-full space-y-1 px-2 pb-4">
        <div className={`mx-auto mb-2 h-px bg-brand-200 dark:bg-brand-700 ${collapsed ? 'w-8' : 'w-[calc(100%-1rem)]'}`} />

        <button
          onClick={onToggleDarkMode}
          aria-label={darkMode ? 'Light mode' : 'Dark mode'}
          title={collapsed ? (darkMode ? 'Light mode' : 'Dark mode') : undefined}
          className={`
            group relative flex w-full items-center gap-3 rounded-lg transition-colors duration-150
            ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
            hover:bg-brand-50 dark:hover:bg-brand-800/60
          `}
        >
          {darkMode
            ? <Sun className="h-5 w-5 text-amber-400 transition-transform duration-300 group-hover:rotate-45" />
            : <Moon className="h-5 w-5 text-brand-500 transition-transform duration-300 group-hover:-rotate-12 dark:text-brand-400" />}
          {!collapsed && (
            <span className="whitespace-nowrap text-sm font-medium text-brand-600 dark:text-brand-400">
              {darkMode ? 'Light Mode' : 'Dark Mode'}
            </span>
          )}
        </button>

      </div>
    </aside>
  );
}
