import React from 'react'
import ReactDOM from 'react-dom/client'
<<<<<<< HEAD
import { BrowserRouter } from "react-router-dom";
import App from './App'
=======
import App from './app.tsx'
>>>>>>> 9aad3b4 (Bring in Daniel's latest branch contents after force-push)
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
<<<<<<< HEAD
    <BrowserRouter>
        <App />
        </BrowserRouter>
=======
    <App />
>>>>>>> 9aad3b4 (Bring in Daniel's latest branch contents after force-push)
  </React.StrictMode>,
)