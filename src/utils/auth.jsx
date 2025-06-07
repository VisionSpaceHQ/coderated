// utils/auth.jsx - Authentication Context & API
import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiClient } from './api';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('codeRatedToken'));

  useEffect(() => {
    if (token) {
      apiClient.setAuthToken(token);
      verifyToken();
    } else {
      setLoading(false);
    }
  }, [token]);

  const verifyToken = async () => {
    try {
      const userData = await apiClient.get('/auth/me');
      setUser(userData);
    } catch (error) {
      // Token invalid, clear it
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      const response = await apiClient.post('/auth/login', { email, password });
      const { access_token, user: userData } = response;
      
      setToken(access_token);
      setUser(userData);
      localStorage.setItem('codeRatedToken', access_token);
      apiClient.setAuthToken(access_token);
      
      return userData;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Login failed');
    }
  };

  const register = async (name, email, password) => {
    try {
      const response = await apiClient.post('/auth/register', {
        name,
        email,
        password,
        tier: 'observer'
      });
      const { access_token, user_id } = response;
      
      setToken(access_token);
      const userData = { id: user_id, name, email, tier: 'observer' };
      setUser(userData);
      localStorage.setItem('codeRatedToken', access_token);
      apiClient.setAuthToken(access_token);
      
      return userData;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Registration failed');
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('codeRatedToken');
    apiClient.setAuthToken(null);
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
