/**
 * Browser entry point: mounts <App> under the error boundary, theme and router
 * providers, and loads the self-hosted fonts and global CSS.
 *
 * Why it exists: Something has to create the React root and assemble the provider tree exactly
 * once; index.html's module script points here.
 */

import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
// Imported through the alias, exactly as every consumer does: a relative
// specifier here resolves to a second module instance, which means a
// second React context — the provider fills one and useTheme reads the
// other, so every consumer throws "must be used inside <ThemeProvider>".
import { ThemeProvider } from "@/theme";
// Self-hosted fonts (imported here, not in globals.css, because Tailwind v4
// mangles CSS @import ordering). Weights match actual usage: Inter 400-700,
// JetBrains Mono 400-600 (.mono-num, .mono-tag, .eyebrow/.metric).
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "./styles/globals.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <ThemeProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ThemeProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
