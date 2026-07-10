import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout.jsx";
import SessionsPage from "./pages/SessionsPage.jsx";
import SessionDetailPage from "./pages/SessionDetailPage.jsx";
import ToolsPage from "./pages/ToolsPage.jsx";
import WordlistsPage from "./pages/WordlistsPage.jsx";
import RemotePage from "./pages/RemotePage.jsx";
import SuitesPage from "./pages/SuitesPage.jsx";
import OsintPage from "./pages/OsintPage.jsx";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/sessions" replace />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/sessions/:sessionId" element={<SessionDetailPage />} />
        <Route path="/tools" element={<ToolsPage />} />
        <Route path="/suites" element={<SuitesPage />} />
        <Route path="/wordlists" element={<WordlistsPage />} />
        <Route path="/remote" element={<RemotePage />} />
        <Route path="/osint" element={<OsintPage />} />
      </Routes>
    </Layout>
  );
}
