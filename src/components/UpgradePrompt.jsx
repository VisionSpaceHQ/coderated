// src/components/UpgradePrompt.jsx
import React, { useState } from "react";
import api from "../utils/api.js";

export default function UpgradePrompt() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleUpgrade = async () => {
    setLoading(true);
    setError("");

    try {
      // Example: let backend create Stripe session and return URL
      const response = await api.post("/billing/create-checkout-session", {
        tier: "reviewer", // or "business"
      });
      const { checkoutUrl } = response.data;
      // Redirect user to Stripe checkout
      window.location.href = checkoutUrl;
    } catch (err) {
      console.error(err);
      setError("Could not initiate upgrade. Try again later.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="upgrade-prompt-container glass-ui">
      <h2>Upgrade Your Account</h2>
      <p>As an Observer, you have read-only access. Here’s what you’re missing:</p>

      <ul>
        <li>Full access to detailed site audits</li>
        <li>Unlimited exports of VisionScores</li>
        <li>Email outreach tools for high-scoring leads</li>
      </ul>

      <h3>Pricing</h3>
      <table className="pricing-table">
        <thead>
          <tr>
            <th>Tier</th>
            <th>Price</th>
            <th>Features</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Reviewer</td>
            <td>$29 / month</td>
            <td>All audit data, prioritized support</td>
          </tr>
          <tr>
            <td>Business Claim</td>
            <td>$99 / year</td>
            <td>Manage your company profile, custom branding</td>
          </tr>
        </tbody>
      </table>

      {error && <div className="error-message">{error}</div>}

      <button onClick={handleUpgrade} disabled={loading}>
        {loading ? "Redirecting…" : "Upgrade Now"}
      </button>
    </div>
  );
}
