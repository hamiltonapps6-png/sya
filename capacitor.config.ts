import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'tn.siyantek.app',
  appName: 'Siyantek',
  webDir: 'dist',
  bundledWebRuntime: false,
  server: { androidScheme: 'https' },
};

export default config;
