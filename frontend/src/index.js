import React from 'react';
import ReactDOM from 'react-dom/client';
import { ClerkProvider } from '@clerk/clerk-react';
import { HelmetProvider } from 'react-helmet-async';
import './index.css';
import App from './App';
import { AuthProvider } from './context/AuthContext';

const CLERK_KEY = process.env.REACT_APP_CLERK_PUBLISHABLE_KEY;
if (!CLERK_KEY) {
  throw new Error('Missing REACT_APP_CLERK_PUBLISHABLE_KEY. Check your .env file.');
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <HelmetProvider>
      <ClerkProvider publishableKey={CLERK_KEY}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ClerkProvider>
    </HelmetProvider>
  </React.StrictMode>
);
