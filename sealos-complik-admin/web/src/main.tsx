import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { LoginGate } from "./components/LoginGate";
import { AppDataProvider } from "./contexts/AppDataContext";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <LoginGate>
        <AppDataProvider>
          <App />
        </AppDataProvider>
      </LoginGate>
    </BrowserRouter>
  </React.StrictMode>,
);
