#!/usr/bin/env node

import express, { Request, Response } from 'express';
import axios from 'axios';
import dotenv from "dotenv";
import { zodToJsonSchema } from "zod-to-json-schema";
import { logToFile } from './utils/logging.js';
import { setupMetrics, recordHttpRequest, getMetrics } from './utils/metrics.js';
import {
  GetUrlReportArgsSchema,
  GetUrlRelationshipArgsSchema,
  GetFileReportArgsSchema,
  GetFileRelationshipArgsSchema,
  GetIpReportArgsSchema,
  GetIpRelationshipArgsSchema,
  GetDomainReportArgsSchema,
} from './schemas/index.js';
import {
  handleGetUrlReport,
  handleGetUrlRelationship,
  handleGetFileReport,
  handleGetFileRelationship,
  handleGetIpReport,
  handleGetIpRelationship,
  handleGetDomainReport,
} from './handlers/index.js';
import { JSONRPCRequest, JSONRPCResponse } from '@modelcontextprotocol/sdk/types.js';

dotenv.config();

const API_KEY = process.env.VIRUSTOTAL_API_KEY;
if (!API_KEY) throw new Error("VIRUSTOTAL_API_KEY environment variable is required");

const axiosInstance = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: { 'x-apikey': API_KEY },
});

// --- HTTP Request Handler ---
async function handleMCPRequest(request: JSONRPCRequest): Promise<JSONRPCResponse | null> {
  try {
    logToFile(`[HTTP] Processing MCP request: ${request.method}`);
    
    // Handle notifications (requests without IDs)
    if (request.id === undefined || request.id === null) {
      switch (request.method) {
        case 'notifications/initialized':
          logToFile("[HTTP] Received initialized notification");
          return null; // No response needed for notifications
        case 'notifications/exit':
          logToFile("[HTTP] Received exit notification");
          return null; // No response needed for notifications
        default:
          logToFile(`[HTTP] Unknown notification method: ${request.method}`);
          return null; // No response needed for notifications
      }
    }
    
    // Handle regular requests (with IDs)
    switch (request.method) {
      case 'initialize':
        return {
          jsonrpc: '2.0',
          id: request.id,
          result: {
            protocolVersion: "2024-11-05",
            capabilities: {
              tools: {
                listChanged: true,
              },
            },
            serverInfo: {
              name: "virustotal-mcp",
              version: "1.0.0",
            },
            instructions: `VirusTotal Analysis Server\n\nThis server provides comprehensive security analysis tools using the VirusTotal API. Each analysis tool automatically fetches relevant relationship data (e.g., contacted domains, downloaded files) along with the basic report.\n\nFor more detailed relationship analysis, dedicated relationship tools are available to query specific types of relationships with pagination support.\n\nAvailable Analysis Types:\n- URLs: Security reports and relationships like contacted domains\n- Files: Analysis results and relationships like dropped files\n- IPs: Security reports and relationships like historical data\n- Domains: DNS information and relationships like subdomains\n\nAll tools return formatted results with clear categorization and relationship data.`
          }
        };
        
      case 'tools/list':
        return {
          jsonrpc: '2.0',
          id: request.id,
          result: {
            tools: [
              {
                name: "get_url_report",
                description: "Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors). Returns both the basic security analysis and automatically fetched relationship data.",
                inputSchema: zodToJsonSchema(GetUrlReportArgsSchema),
              },
              {
                name: "get_url_relationship",
                description: "Query a specific relationship type for a URL with pagination support. Choose from 17 relationship types including analyses, communicating files, contacted domains/IPs, downloaded files, graphs, referrers, redirects, and threat actors. Useful for detailed investigation of specific relationship types.",
                inputSchema: zodToJsonSchema(GetUrlRelationshipArgsSchema),
              },
              {
                name: "get_file_report",
                description: "Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256). Includes detection results, file properties, and key relationships (behaviors, dropped files, network connections, embedded content, threat actors). Returns both the basic analysis and automatically fetched relationship data.",
                inputSchema: zodToJsonSchema(GetFileReportArgsSchema),
              },
              {
                name: "get_file_relationship",
                description: "Query a specific relationship type for a file with pagination support. Choose from 41 relationship types including behaviors, network connections, dropped files, embedded content, execution chains, and threat actors. Useful for detailed investigation of specific relationship types.",
                inputSchema: zodToJsonSchema(GetFileRelationshipArgsSchema),
              },
              {
                name: "get_ip_report",
                description: "Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships (communicating files, historical certificates/WHOIS, resolutions). Returns both the basic analysis and automatically fetched relationship data.",
                inputSchema: zodToJsonSchema(GetIpReportArgsSchema),
              },
              {
                name: "get_ip_relationship",
                description: "Query a specific relationship type for an IP address with pagination support. Choose from 12 relationship types including communicating files, historical SSL certificates, WHOIS records, resolutions, and threat actors. Useful for detailed investigation of specific relationship types.",
                inputSchema: zodToJsonSchema(GetIpRelationshipArgsSchema),
              },
              {
                name: "get_domain_report",
                description: "Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships (SSL certificates, subdomains, historical data). Optionally specify which relationships to include in the report. Returns both the basic analysis and relationship data.",
                inputSchema: zodToJsonSchema(GetDomainReportArgsSchema),
              }
            ]
          }
        };
        
      case 'tools/call':
        const { name, arguments: args } = request.params as { name: string; arguments: any };
        let result;
        
        switch (name) {
          case "get_url_report":
            result = await handleGetUrlReport(axiosInstance, args);
            break;
          case "get_url_relationship":
            result = await handleGetUrlRelationship(axiosInstance, args);
            break;
          case "get_file_report":
            result = await handleGetFileReport(axiosInstance, args);
            break;
          case "get_file_relationship":
            result = await handleGetFileRelationship(axiosInstance, args);
            break;
          case "get_ip_report":
            result = await handleGetIpReport(axiosInstance, args);
            break;
          case "get_ip_relationship":
            result = await handleGetIpRelationship(axiosInstance, args);
            break;
          case "get_domain_report":
            result = await handleGetDomainReport(axiosInstance, args);
            break;
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
        
        return {
          jsonrpc: '2.0',
          id: request.id,
          result
        };
        
      default:
        return {
          jsonrpc: '2.0',
          id: request.id,
          result: {
            error: {
              code: -32601,
              message: 'Method not found',
              data: `Method '${request.method}' not found`
            }
          }
        };
    }
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logToFile(`[HTTP] Error handling MCP request: ${errorMessage}`);
    
    // Only return error response if this is a request (has ID), not a notification
    if (request.id !== undefined && request.id !== null) {
      return {
        jsonrpc: '2.0',
        id: request.id,
        result: {
          error: {
            code: -32603,
            message: 'Internal error',
            data: errorMessage
          }
        }
      };
    }
    
    // For notifications, just log the error and return null
    logToFile(`[HTTP] Error in notification ${request.method}: ${errorMessage}`);
    return null;
  }
}

const app = express();
app.use(express.json());

// Middleware to record HTTP requests
app.use((req: Request, res: Response, next) => {
  const originalSend = res.send;
  res.send = function(data) {
    recordHttpRequest(req.method, req.path, res.statusCode);
    return originalSend.call(this, data);
  };
  next();
});

// POST / (MCP endpoint)
app.post('/', async (req: Request, res: Response) => {
  logToFile(`[HTTP] POST / received: ${JSON.stringify(req.body)}`);
  console.log(`[HTTP] POST / received: ${JSON.stringify(req.body)}`);
  
  // Validate request body
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({
      jsonrpc: '2.0',
      error: {
        code: -32600,
        message: 'Invalid Request',
        data: 'Request body must be a valid JSON object'
      },
      id: null
    });
  }
  
  try {
    const request = req.body as JSONRPCRequest;
    
    // Validate JSON-RPC request structure
    if (!request.jsonrpc || request.jsonrpc !== '2.0') {
      return res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32600,
          message: 'Invalid Request',
          data: 'Invalid JSON-RPC version'
        },
        id: request.id || null
      });
    }
    
    // Handle the MCP request directly
    const response = await handleMCPRequest(request);
    
    // If response is null, this was a notification - no response needed
    if (response === null) {
      logToFile("[HTTP] Notification received, no response needed");
      console.log("[HTTP] Notification received, no response needed");
      res.status(204).end(); // No content response for notifications
      return;
    }
    
    logToFile(`[HTTP] Sending response: ${JSON.stringify(response)}`);
    console.log(`[HTTP] Sending response: ${JSON.stringify(response)}`);
    res.json(response);
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    logToFile(`[HTTP] Error handling request: ${errorMessage}`);
    console.log(`[HTTP] Error handling request: ${errorMessage}`);
    if (errorStack) {
      logToFile(`[HTTP] Error stack: ${errorStack}`);
    }
    res.status(500).json({
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: 'Internal error',
        data: errorMessage
      },
      id: req.body?.id || null
    });
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString()
  });
});

// Metrics endpoint for Prometheus
app.get('/metrics', async (req: Request, res: Response) => {
  try {
    const metrics = await getMetrics();
    res.set('Content-Type', 'text/plain');
    res.send(metrics);
  } catch (error: any) {
    res.status(500).send(`Error collecting metrics: ${error.message}`);
  }
});

async function runHttpServer() {
  const port = process.env.PORT || 3001;
  logToFile("[HTTP] Starting VirusTotal MCP Streamable HTTP Server...");
  console.log("[HTTP] Starting VirusTotal MCP Streamable HTTP Server...");
  try {
    // Setup Prometheus metrics
    await setupMetrics();
    logToFile("[HTTP] Prometheus metrics initialized");
    console.log("[HTTP] Prometheus metrics initialized");
    
    logToFile("[HTTP] MCP server ready for HTTP requests");
    console.log("[HTTP] MCP server ready for HTTP requests");
    app.listen(port, () => {
      logToFile(`[HTTP] VirusTotal MCP HTTP Server is running on port ${port}`);
      console.log(`[HTTP] VirusTotal MCP HTTP Server is running on port ${port}`);
      console.log(`[HTTP] Health check: http://localhost:${port}/health`);
      console.log(`[HTTP] Metrics endpoint: http://localhost:${port}/metrics`);
      console.log(`[HTTP] MCP endpoint: POST http://localhost:${port}/`);
    });
  } catch (error: any) {
    logToFile(`[HTTP] Error starting HTTP server: ${error.message}`);
    console.log(`[HTTP] Error starting HTTP server: ${error.message}`);
    process.exit(1);
  }
}

process.on('uncaughtException', (error) => {
  logToFile(`[HTTP] Uncaught exception: ${error.message}`);
  console.log(`[HTTP] Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logToFile(`[HTTP] Unhandled rejection: ${reason}`);
  console.log(`[HTTP] Unhandled rejection: ${reason}`);
  process.exit(1);
});

process.on('SIGINT', () => {
  logToFile('[HTTP] Received SIGINT, shutting down gracefully...');
  console.log('[HTTP] Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logToFile('[HTTP] Received SIGTERM, shutting down gracefully...');
  console.log('[HTTP] Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

runHttpServer().catch((error: any) => {
  logToFile(`[HTTP] Fatal error: ${error.message}`);
  console.log(`[HTTP] Fatal error: ${error.message}`);
  process.exit(1);
}); 