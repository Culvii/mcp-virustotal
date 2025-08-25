import { Registry, Counter, collectDefaultMetrics } from 'prom-client';

// Create a registry
const register = new Registry();

// Create the http_requests_total counter
export const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'endpoint', 'status_code'],
  registers: [register],
});

// Async function to setup metrics
export async function setupMetrics(): Promise<void> {
  try {
    // Collect default metrics (CPU, memory, etc.)
    collectDefaultMetrics({ register });
    
    console.log('[METRICS] Prometheus metrics setup completed');
  } catch (error) {
    console.error('[METRICS] Error setting up metrics:', error);
    throw error;
  }
}

// Function to get metrics as text
export async function getMetrics(): Promise<string> {
  return await register.metrics();
}

// Function to record HTTP request
export function recordHttpRequest(method: string, endpoint: string, statusCode: number): void {
  httpRequestsTotal.labels(method, endpoint, statusCode.toString()).inc();
}

// Export the registry for potential external use
export { register };
