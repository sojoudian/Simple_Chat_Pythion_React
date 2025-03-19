import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';

function Login({ setIsAuthenticated }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5001";
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      console.log("🔍 Sending login request to:", `${API_URL}/api/login`);
      console.log("🔍 Request data:", { username, password });

      // First, check if the server is available with a simple OPTIONS request
      await axios({
        method: 'OPTIONS',
        url: `${API_URL}/api/login`,
        headers: {
          'Content-Type': 'application/json',
        }
      });

      // Then perform the actual login request
      const response = await axios.post(
        `${API_URL}/api/login`,
        { username, password },
        {
          headers: {
            "Content-Type": "application/json",
          },
          // Changed to false because our Python implementation is handling 
          // authentication with JWT tokens rather than cookies
          withCredentials: false
        }
      );
      
      console.log("✅ Login response:", response.data);
      
      // Store token and username in localStorage
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('username', response.data.username);
      
      // Configure axios defaults for future requests
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      
      setIsAuthenticated(true);
      navigate("/chat"); // Redirect user to chat page after login
    } catch (err) {
      console.error("❌ Login error:", err);
      
      let errorMessage = 'Login failed. Please try again.';
      
      if (err.response) {
        console.error("Response error data:", err.response.data);
        errorMessage = err.response.data.message || errorMessage;
      } else if (err.request) {
        console.error("Request error:", err.request);
        errorMessage = "No response from server. Please check your connection.";
      } else {
        console.error("Error:", err.message);
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="auth-container">
      <h2>Login</h2>
      {error && <div className="error-message">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit" className="btn-primary" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>
      <p className="auth-link">
        Don't have an account? <Link to="/register">Register</Link>
      </p>
    </div>
  );
}

export default Login;