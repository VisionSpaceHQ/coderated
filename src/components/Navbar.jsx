// src/components/Navbar.jsx
import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { isAuthenticated, getUserRole, logout } from "../utils/auth.js";

export default function Navbar() {
  const navigate = useNavigate();
  const authenticated = isAuthenticated();
  const role = getUserRole();

  const handleLogout = () => {
    logout();
    navigate("/", { replace: true });
  };

  return (
    <nav className="navbar glass-ui">
      <div className="navbar-left">
        <Link to="/" className="navbar-logo">
          <img src="/logo.svg" alt="CodeRated" height="32" />
        </Link>
      </div>

      <div className="navbar-right">
        {!authenticated && (
          <>
            <Link to="/login" className="nav-link">
              Login
            </Link>
            <Link to="/signup" className="nav-link">
              Sign Up
            </Link>
          </>
        )}

        {authenticated && (
          <>
            <Link to="/" className="nav-link">
              Dashboard
            </Link>
            {/* Show “Upgrade” if role === "observer" */}
            {role === "observer" && (
              <Link to="/upgrade" className="nav-link upgrade-link">
                Upgrade
              </Link>
            )}
            <Link to="/profile" className="nav-link">
              Profile
            </Link>
            <button onClick={handleLogout} className="nav-link logout-button">
              Logout
            </button>
          </>
        )}
      </div>
    </nav>
  );
}
