import { mountExplorer } from "./app.js";

let storage: Storage | null = null;
try {
  storage = window.localStorage;
} catch {
  storage = null;
}

mountExplorer(document, {
  storage,
  replaceUrl: (query) => window.history.replaceState(null, "", query),
});
