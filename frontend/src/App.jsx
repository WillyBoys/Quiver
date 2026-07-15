import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout.jsx";
import SessionsPage from "./pages/SessionsPage.jsx";
import SessionDetailPage from "./pages/SessionDetailPage.jsx";
import ToolsPage from "./pages/ToolsPage.jsx";
import WordlistsPage from "./pages/WordlistsPage.jsx";
import RemotePage from "./pages/RemotePage.jsx";
import ActivityPage from "./pages/ActivityPage.jsx";
import CampaignsPage from "./pages/CampaignsPage.jsx";
import ApprovalQueuePage from "./pages/ApprovalQueuePage.jsx";
import ShannonScansPage from "./pages/ShannonScansPage.jsx";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/campaigns" replace />} />
        <Route path="/campaigns" element={<CampaignsPage />} />
        <Route path="/approvals" element={<ApprovalQueuePage />} />
        <Route path="/web-scans" element={<ShannonScansPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/sessions/:sessionId" element={<SessionDetailPage />} />
        <Route path="/tools" element={<ToolsPage />} />
        <Route path="/wordlists" element={<WordlistsPage />} />
        <Route path="/remote" element={<RemotePage />} />
        <Route path="/activity" element={<ActivityPage />} />
      </Routes>
    </Layout>
  );
}
