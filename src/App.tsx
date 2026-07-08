import { Suspense } from "react";
import { useRoutes, Routes, Route } from "react-router-dom";
import Home from "./components/home";
// @ts-ignore
import routes from "tempo-routes";

function App() {
  const tempoRoutes = useRoutes(routes);

  return (
    <Suspense fallback={<p>Loading...</p>}>
      <>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
        {import.meta.env.VITE_TEMPO === "true" && tempoRoutes}
      </>
    </Suspense>
  );
}

export default App;
