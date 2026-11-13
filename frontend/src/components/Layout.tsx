import { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Shield, LayoutDashboard, Search, Globe, FileText, Image, Brain,
  Clock, BookOpen, AlertTriangle, GraduationCap, FileBarChart,
  Settings, Menu, X, ChevronRight
} from 'lucide-react';
import clsx from 'clsx';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/scan', label: 'Scan Centre', icon: Search },
  { to: '/website-inspector', label: 'Website Inspector', icon: Globe },
  { to: '/file-scanner', label: 'File Scanner', icon: FileText },
  { to: '/image-scanner', label: 'Image Scanner', icon: Image },
  { to: '/threat-intelligence', label: 'Threat Intelligence', icon: Brain },
  { to: '/history', label: 'Scan History', icon: Clock },
  { to: '/awareness', label: 'Cyber Awareness', icon: BookOpen },
  { to: '/digital-arrest', label: 'Digital Arrest', icon: AlertTriangle },
  { to: '/quiz', label: 'Security Quiz', icon: GraduationCap },
  { to: '/reports', label: 'Reports', icon: FileBarChart },
  { to: '/settings', label: 'Settings', icon: Settings },
];

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/scan': 'Scan Centre',
  '/website-inspector': 'Website Inspector',
  '/file-scanner': 'File Scanner',
  '/image-scanner': 'Image Scanner',
  '/threat-intelligence': 'Threat Intelligence',
  '/history': 'Scan History',
  '/awareness': 'Cyber Awareness',
  '/digital-arrest': 'Digital Arrest Awareness',
  '/quiz': 'Security Quiz',
  '/reports': 'Reports',
  '/settings': 'Settings',
};

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  const pageTitle = Object.entries(pageTitles)
    .sort((a, b) => b[0].length - a[0].length)
    .find(([path]) => location.pathname === path || location.pathname.startsWith(path + '/'))?.[1] || 'THREATNEX';

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-20 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={clsx(
        'fixed inset-y-0 left-0 z-30 w-64 bg-white border-r border-gray-200 flex flex-col transition-transform duration-300',
        'lg:translate-x-0 lg:static lg:z-auto',
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      )}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <img
            src="/threatnex-logo.jpg"
            alt="THREATNEX Logo"
            className="w-9 h-9 object-contain rounded-lg"
          />
          <div>
            <div className="text-sm font-bold text-gray-900 leading-tight tracking-wide">THREATNEX</div>
            <div className="text-xs text-gray-500">Cyber Threat Intelligence</div>
          </div>
          <button
            className="ml-auto lg:hidden text-gray-500 hover:text-gray-700"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close navigation sidebar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-0.5">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.exact}
              className={({ isActive }) =>
                clsx('sidebar-link', isActive && 'active')
              }
              onClick={() => setSidebarOpen(false)}
            >
              <item.icon className="w-4 h-4 flex-shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="border-t border-gray-200 px-5 py-3 flex-shrink-0">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-xs text-gray-500">System Online</span>
          </div>
          <div className="text-xs text-gray-400 mt-1">v1.0.0 · THREATNEX</div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <header className="bg-white border-b border-gray-200 px-5 py-3 flex items-center gap-4 flex-shrink-0">
          <button
            className="lg:hidden p-1.5 rounded-lg hover:bg-gray-100 text-gray-600"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open navigation sidebar"
            aria-expanded={sidebarOpen}
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex items-center gap-2 text-sm text-gray-600">
            <span className="font-medium text-gray-900">{pageTitle}</span>
            {location.pathname !== '/' && (
              <>
                <ChevronRight className="w-4 h-4 text-gray-400" />
                <span className="text-gray-500">{location.pathname.split('/').filter(Boolean).join(' / ')}</span>
              </>
            )}
          </div>

          <div className="ml-auto flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-1.5 bg-blue-50 text-blue-700 px-3 py-1.5 rounded-full text-xs font-medium border border-blue-200">
              <Shield className="w-3.5 h-3.5" />
              Protected
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <div className="p-5 max-w-7xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
