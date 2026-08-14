import { Link as RouterLink, Route, Routes } from "react-router-dom";
import { AppBar, Box, Link, Toolbar, Typography } from "@mui/material";
import AnalyzePage from "../pages/AnalyzePage";
import SettingsPage from "../pages/SettingsPage";
import HistoryPage from "../pages/HistoryPage";
import AnalysisDetailPage from "../pages/AnalysisDetailPage";
import ApiHealthIndicator from "../shared/components/ApiHealthIndicator";

export function AppRouter() {
  return (
    <>
      <AppBar position="static">
        <Toolbar sx={{ gap: 2 }}>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            vt_tool
          </Typography>
          <Link component={RouterLink} to="/" color="inherit">
            Analyze
          </Link>
          <Link component={RouterLink} to="/history" color="inherit">
            History
          </Link>
          <Link component={RouterLink} to="/settings" color="inherit">
            Settings
          </Link>
          <ApiHealthIndicator />
        </Toolbar>
      </AppBar>
      <Box sx={{ p: 3 }}>
        <Routes>
          <Route path="/" element={<AnalyzePage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/history/:id" element={<AnalysisDetailPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </Box>
    </>
  );
}
