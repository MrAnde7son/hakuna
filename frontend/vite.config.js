import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.VITE_API_PROXY_TARGET || 'http://localhost:8000'
  const vmTarget = env.VITE_VM_PROXY_TARGET || apiTarget || 'http://localhost:8002'
  const isHttps = apiTarget.startsWith('https://')

  return {
    plugins: [react()],
    build: {
      chunkSizeWarningLimit: 1000,
      rollupOptions: {
        output: {
          manualChunks: {
            'vendor-react': ['react', 'react-dom', 'react-router-dom'],
            'vendor-charts': ['recharts'],
            'vendor-flow': ['@xyflow/react', '@dagrejs/dagre'],
            'vendor-export': ['html2canvas', 'jspdf', 'pptxgenjs'],
          },
        },
      },
    },
    optimizeDeps: {
      include: ['react-markdown'],
    },
    server: {
      port: 3000,
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
          secure: isHttps,
        },
        '/vm': {
          target: vmTarget,
          changeOrigin: true,
          secure: vmTarget.startsWith('https://'),
        },
      },
    },
  }
})
