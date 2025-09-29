// components/MessageList.js
import React, { useEffect, useRef } from 'react';

export default function MessageList({ messages, loading }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  return (
    <div className="message-list">
      {messages.map((msg, idx) => (
        <div
          key={idx}
          className={`message ${msg.from === 'user' ? 'user-message' : 'bot-message'}`}
        >
          {msg.text.split('\n').map((line, i) => (
            <span key={i}>{line}<br /></span>
          ))}
        </div>
      ))}
      {loading && <div className="message bot-message">Typing...</div>}
      <div ref={endRef} />
    </div>
  );
}
