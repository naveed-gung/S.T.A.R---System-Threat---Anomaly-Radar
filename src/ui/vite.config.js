import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
    plugins: [react()],
    root: 'react', // Source root
    base: './',    // Relative paths for Electron
    build: {
        outDir: '../dist',
        emptyOutDir: true
    },
    server: {
        port: 5173
    }
});
