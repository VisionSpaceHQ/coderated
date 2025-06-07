// src/components/WebsiteCard.jsx
import React from "react";
import { Link } from "react-router-dom";

export default function WebsiteCard({ site }) {
  // site = { id, domain, score, summary, ... }

  return (
    <div className="website-card glass-ui">
      <div className="card-header">
        <h3>{site.domain}</h3>
        <span className="score-badge">{site.score.toFixed(1)}</span>
      </div>

      <div className="card-body">
        <p className="summary-text">
          {site.summary.length > 100
            ? site.summary.slice(0, 100) + "…"
            : site.summary}
        </p>
      </div>

      <div className="card-footer">
        <Link to={`/sites/${site.id}`} className="detail-link">
          View Full Report →
        </Link>
      </div>
    </div>
  );
}
