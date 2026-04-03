import { useState, useEffect } from 'react';
import client from '../api/client';

export const useDashboard = () => {
  const [stats, setStats] = useState(null);
  const [recentEvents, setRecentEvents] = useState([]);
  const [threatBreakdown, setThreatBreakdown] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStats = async () => {
    try {
      const r = await client.get('/api/v1/dashboard/stats');
      setStats(r.data);
    } catch (e) { setError(e); }
  };

  const fetchRecentEvents = async () => {
    try {
      const r = await client.get('/api/v1/scan/history', { params: { limit: 20 } });
      setRecentEvents(r.data.scans || []);
    } catch (e) { setError(e); }
  };

  const fetchThreatBreakdown = async () => {
    try {
      const r = await client.get('/api/v1/dashboard/threat-breakdown');
      setThreatBreakdown(r.data);
    } catch (e) { setError(e); }
  };

  const refreshAll = async () => {
    setLoading(true);
    await Promise.all([fetchStats(), fetchRecentEvents(), fetchThreatBreakdown()]);
    setLoading(false);
  };

  useEffect(() => { refreshAll(); }, []); // eslint-disable-line

  return { stats, recentEvents, threatBreakdown, loading, error, refreshAll };
};
