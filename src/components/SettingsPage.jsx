// src/components/SettingsPage.jsx
import React, { useState } from "react";
import api from "../utils/api.js";

export default function SettingsPage() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setMessage("");

    if (newPassword !== confirmPassword) {
      setMessage("New passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      await api.post("/users/change-password", {
        currentPassword,
        newPassword,
      });
      setMessage("Password updated successfully.");
    } catch (err) {
      console.error(err);
      setMessage(err.response?.data?.message || "Error changing password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="settings-container glass-ui">
      <h2>Settings</h2>
      {message && <div className="message">{message}</div>}
      <form onSubmit={handleChangePassword}>
        <label>
          Current Password
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
          />
        </label>

        <label>
          New Password
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
        </label>

        <label>
          Confirm New Password
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
        </label>

        <button type="submit" disabled={loading}>
          {loading ? "Updating…" : "Change Password"}
        </button>
      </form>
    </div>
  );
}
