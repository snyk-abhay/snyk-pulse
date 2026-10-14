import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: (id: string) => {
          if (
            id.includes("/node_modules/echarts/") ||
            id.includes("/node_modules/zrender/")
          )
            return "charts";
        },
      },
    },
  },
});
