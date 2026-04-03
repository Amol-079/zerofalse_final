import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../hooks/useTheme';

export const DarkModeToggle = () => {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      style={{
        width: '36px',
        height: '36px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: 'var(--radius-md)',
        backgroundColor: 'transparent',
        border: 'none',
        cursor: 'pointer',
        transition: 'all 0.15s ease'
      }}
      onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--color-surface-2)'}
      onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
      data-testid="dark-mode-toggle"
      aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {theme === 'dark' ? (
        <Sun style={{ width: '20px', height: '20px', color: 'var(--color-text-muted)' }} />
      ) : (
        <Moon style={{ width: '20px', height: '20px', color: 'var(--color-text-muted)' }} />
      )}
    </button>
  );
};

export default DarkModeToggle;
