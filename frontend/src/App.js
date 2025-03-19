import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Chat from './components/Chat';
import './App.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  
  useEffect(() => {
    // Check if user is authenticated on component mount
    const token = localStorage.getItem('token');
    if (token) {
      setIsAuthenticated(true);
    }
  }, []);
  
  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
  };
  
  return (
    <Router>
      <div className="app">
        <header className="app-header">
          <h1>Simple Chat App</h1>
          {isAuthenticated && (
            <button className="logout-btn" onClick={logout}>
              Logout
            </button>
          )}
        </header>
        <main className="app-content">
          <Routes>
            <Route 
              path="/login" 
              element={isAuthenticated ? <Navigate to="/chat" /> : <Login setIsAuthenticated={setIsAuthenticated} />} 
            />
            <Route 
              path="/register" 
              element={isAuthenticated ? <Navigate to="/chat" /> : <Register setIsAuthenticated={setIsAuthenticated} />} 
            />
            <Route 
              path="/chat" 
              element={isAuthenticated ? <Chat /> : <Navigate to="/login" />} 
            />
            <Route 
              path="*" 
              element={<Navigate to={isAuthenticated ? "/chat" : "/login"} />} 
            />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
