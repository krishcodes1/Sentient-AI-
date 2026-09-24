/**
 * Entry point of the setup window: mounts <App> and loads the stylesheet.
 *
 * Why it exists: index.html's only script points here; everything else is imported from it, so
 * the production build is one module script and one stylesheet, both served from 'self'.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
