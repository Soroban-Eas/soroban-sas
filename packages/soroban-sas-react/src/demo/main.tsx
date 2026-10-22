import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { SASDemoApp } from "./SASDemoApp.js";

const rootElement = document.getElementById("root");
if (rootElement) {
  createRoot(rootElement).render(
    <StrictMode>
      <SASDemoApp />
    </StrictMode>,
  );
}
