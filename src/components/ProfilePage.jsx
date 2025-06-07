// src/components/ProfilePage.jsx
import React, { useEffect, useState } from "react";
import api from "../utils/api.js";

export default function ProfilePage() {
  const [user, setUser] = useState(null);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const fetchProfile = async () => {
      setLoading(true);
      try {
        const response = await api.get("/users/me");
        setUser(response.data);
        setEmail(response.data.email);
        setDisplayName(response.data.displayName || "");
      } catch (err) {
        console.error("Error fetching user profile:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, []);

  const handleUpdate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const response = await api.put("/users/me", { displayName });
      setUser(response.data);
      setMessage("Profile updated successfully.");
    } catch (err) {
      console.error(err);
      setMessage("Update failed.");
    } finally {
      setLoading(false);
    }
  };

  if (loading && !user) {
    return <div>Loading profile…</div>;
  }

  return (
    <div className="profile-container glass-ui">
      <h2>My Profile</h2>
      {message && <div className="message">{message}</div>}
      <form onSubmit={handleUpdate}>
        <label>
          Email (read-only)
          <input type="email" value={email} disabled />
        </label>

        <label>
          Display Name
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </label>

        <button type="submit">Update Profile</button>
      </form>
    </div>
  );
}
