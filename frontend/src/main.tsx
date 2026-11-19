import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { DetailProvider } from './context/DetailContext'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <DetailProvider>
      <App />
    </DetailProvider>
  </React.StrictMode>,
)
