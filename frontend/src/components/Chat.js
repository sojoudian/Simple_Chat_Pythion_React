import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import io from 'socket.io-client';

function Chat() {
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState('');
  const [loading, setLoading] = useState(true);
  const [socketConnected, setSocketConnected] = useState(false);
  const socket = useRef(null);
  const messagesEndRef = useRef(null);
  const currentUser = localStorage.getItem('username');
  const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5001";
  
  useEffect(() => {
    // Connect to socket.io server
    console.log("Attempting to connect to Socket.IO server...");
    
    // Create socket connection with proper configuration
    socket.current = io(API_URL, { 
      transports: ["websocket", "polling"], // Try both transports
      path: "/socket.io",
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 20000
    });
    
    // Log connection events
    socket.current.on("connect", () => {
      console.log("✅ Socket connected successfully");
      setSocketConnected(true);
      
      // Authenticate socket connection after successful connection
      const token = localStorage.getItem("token");
      if (token) {
        console.log("Authenticating socket connection...");
        socket.current.emit("authenticate", token);
      } else {
        console.error("No authentication token found");
      }
    });
    
    socket.current.on("connect_error", (err) => {
      console.error("❌ Socket connection error:", err);
    });
    
    // Listen for authentication response
    socket.current.on("authenticated", (data) => {
      console.log("✅ WebSocket Authenticated:", data);
    });

    socket.current.on("authentication_failed", () => {
      console.error("❌ WebSocket Authentication Failed");
    });
    
    // Fetch all users
    fetchUsers();
    
    // Clean up socket connection when component unmounts
    return () => {
      if (socket.current) {
        console.log("Disconnecting socket...");
        socket.current.disconnect();
      }
    };
  }, []); // Only run this effect once on mount
  
  // Separate effect for message events that depends on selectedUser
  useEffect(() => {
    if (!socket.current || !socketConnected) return;
    
    // Message event handler
    const handleReceiveMessage = (message) => {
      console.log("Received message:", message);
      if (message.sender === selectedUser) {
        setMessages((prevMessages) => [...prevMessages, message]);
      } else {
        // Could implement notifications for messages from other users
        console.log(`New message from ${message.sender}`);
      }
    };
    
    // Register event handler
    socket.current.on("receive_message", handleReceiveMessage);
    
    // Clean up event handler
    return () => {
      socket.current.off("receive_message", handleReceiveMessage);
    };
  }, [selectedUser, socketConnected]);
  
  // Fetch users from the API
  const fetchUsers = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem("token");
      
      const response = await axios.get(`${API_URL}/api/users`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      
      const filteredUsers = response.data.filter(user => user.username !== currentUser);
      setUsers(filteredUsers);
    } catch (err) {
      console.error("Error fetching users:", err);
    } finally {
      setLoading(false);
    }
  };
  
  // Fetch messages when a user is selected
  useEffect(() => {
    if (selectedUser) {
      fetchMessages();
    } else {
      setMessages([]);
    }
  }, [selectedUser]);
  
  // Scroll to bottom of messages when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);
  
  // Fetch messages between current user and selected user
  const fetchMessages = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem("token");
      
      const response = await axios.get(`${API_URL}/api/messages/${selectedUser}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      
      setMessages(response.data);
    } catch (err) {
      console.error("Error fetching messages:", err);
    } finally {
      setLoading(false);
    }
  };
  
  // Send a message to the selected user
  const sendMessage = (e) => {
    e.preventDefault();
    
    if (!messageInput.trim() || !selectedUser || !socketConnected) {
      console.log("Cannot send message:", {
        messageInput: !!messageInput.trim(),
        selectedUser: !!selectedUser,
        socketConnected
      });
      return;
    }
    
    console.log(`Sending message to ${selectedUser}: ${messageInput}`);
    
    // Send message through socket
    socket.current.emit("send_message", {
      recipient: selectedUser,
      content: messageInput
    });
    
    // Optimistically add message to UI
    setMessages((prevMessages) => [
      ...prevMessages, 
      {
        sender: currentUser,
        recipient: selectedUser,
        content: messageInput,
        timestamp: new Date().toISOString(),
      }
    ]);
    
    setMessageInput('');
  };
  
  return (
    <div className="chat-container">
      <div className="users-list">
        <h3>Users</h3>
        {!socketConnected && (
          <div className="connection-status error">
            Socket disconnected. Reconnecting...
          </div>
        )}
        {loading && users.length === 0 ? (
          <p>Loading users...</p>
        ) : (
          <ul>
            {users.map((user) => (
              <li 
                key={user.username} 
                className={user.username === selectedUser ? "selected" : ""}
                onClick={() => setSelectedUser(user.username)}
              >
                {user.username}
              </li>
            ))}
          </ul>
        )}
      </div>
      
      <div className="messages-container">
        {!selectedUser ? (
          <div className="no-chat-selected">
            <p>Select a user to start chatting</p>
          </div>
        ) : (
          <>
            <div className="chat-header">
              <h3>Chat with {selectedUser}</h3>
            </div>
            
            <div className="messages-list">
              {loading ? (
                <p>Loading messages...</p>
              ) : messages.length === 0 ? (
                <p className="no-messages">No messages yet. Start the conversation!</p>
              ) : (
                messages.map((message, index) => (
                  <div 
                    key={index} 
                    className={`message ${message.sender === currentUser ? "sent" : "received"}`}
                  >
                    <div className="message-content">{message.content}</div>
                    <div className="message-timestamp">
                      {new Date(message.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>
            
            <form className="message-input-form" onSubmit={sendMessage}>
              <input
                type="text"
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Type your message..."
                required
              />
              <button type="submit" disabled={!socketConnected}>
                {socketConnected ? "Send" : "Connecting..."}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

export default Chat;