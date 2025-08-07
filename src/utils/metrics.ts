import { Registry, Counter, collectDefaultMetrics } from 'prom-client';

// Create a registry
export const register = new Registry();

// Add default metrics (CPU, memory, etc.)
collectDefaultMetrics({ register });

// Define the http_requests_total counter
export const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'endpoint', 'status_code'],
  registers: [register],
});

// Function to increment the counter
export function incrementHttpRequests(method: string, endpoint: string, statusCode: number) {
  httpRequestsTotal.inc({ method, endpoint, statusCode });
}

// Function to get metrics as text
export async function getMetrics(): Promise<string> {
  return await register.metrics();
} 