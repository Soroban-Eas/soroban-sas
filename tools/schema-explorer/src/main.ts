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
  getLocationSearch: () => window.location.search,
  onPopState: (handler) => {
    const listener = () => handler(window.location.search);
    window.addEventListener("popstate", listener);
    return () => window.removeEventListener("popstate", listener);
  },
});
