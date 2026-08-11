import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 后端 FastAPI 基址 http://127.0.0.1:8100;API 路由均为顶层前缀,
// 同源代理这三个前缀即可覆盖全部端点,不影响 vite 自身的静态资源。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/healthz": "http://127.0.0.1:8100",
      "/cases": "http://127.0.0.1:8100",
      "/sources": "http://127.0.0.1:8100",
    },
  },
});
