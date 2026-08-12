import { Route, Routes } from "react-router-dom";
import AnalyzePage from "../pages/AnalyzePage";
import SettingsPage from "../pages/SettingsPage";

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<AnalyzePage />} />
      <Route path="/settings" element={<SettingsPage />} />
    </Routes>
  );
}
