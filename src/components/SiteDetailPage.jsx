// src/components/SiteDetailPage.jsx
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import api from "../utils/api.js";

export default function SiteDetailPage() {
  const { id } = useParams(); // id as a string
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchReport = async () => {
      setLoading(true);
      try {
        const response = await api.get(`/reports/${id}`);
        setReport(response.data); // assume data shape: { domain, score, ai_summary: { workingWell, improvement, invite }, details: {...} }
      } catch (err) {
        console.error("Error fetching report:", err);
        setError("Could not load report. Maybe it doesn’t exist?");
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [id]);

  if (loading) {
    return <div className="loading-indicator">Loading report…</div>;
  }

  if (error) {
    return <div className="error">{error}</div>;
  }

  if (!report) {
    return null; // or a “No Data” placeholder
  }

  return (
    <div className="site-detail-container">
      <h2>{report.domain}</h2>
      <div className="score-section">
        <span className="score-large">{report.score.toFixed(1)} / 100</span>
      </div>

      {/* AI Summary Sections */}
      <section className="ai-summary glass-ui">
        <h3>What’s Working Well</h3>
        <p>{report.ai_summary.workingWell}</p>
      </section>
      <section className="ai-summary glass-ui">
        <h3>Improvement Areas</h3>
        <p>{report.ai_summary.improvement}</p>
      </section>
      <section className="ai-summary glass-ui">
        <h3>How to Get Started</h3>
        <p>{report.ai_summary.invite}</p>
      </section>

      {/* (Optional) Detailed Audit Data */}
      <section className="audit-details">
        <h3>Detailed Audit Data</h3>
        {/* You can loop over keys in report.details if it’s an object */}
        {Object.entries(report.details || {}).map(([key, value]) => (
          <div key={key} className="detail-row">
            <strong>{key}</strong>: {JSON.stringify(value)}
          </div>
        ))}
      </section>
    </div>
  );
}
