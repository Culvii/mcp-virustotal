#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from 'axios';
import dotenv from "dotenv";
import { zodToJsonSchema } from "zod-to-json-schema";
import { logToFile } from './utils/logging.js';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { incrementHttpRequests, getMetrics } from './utils/metrics.js';
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

dotenv.config();

const API_KEY = process.env.VIRUSTOTAL_API_KEY;

if (!API_KEY) {
  throw new Error("VIRUSTOTAL_API_KEY environment variable is required");
}

// In-memory map to track active transports by sessionId
const transportMap = new Map<string, SSEServerTransport>()

// Track session creation time for cleanup
const sessionTimestamps = new Map<string, number>()

// Cleanup old sessions (older than 5 minutes)
const SESSION_TIMEOUT_MS = 5 * 60 * 1000

function cleanupOldSessions() {
  const now = Date.now()
  for (const [sessionId, timestamp] of sessionTimestamps.entries()) {
    if (now - timestamp > SESSION_TIMEOUT_MS) {
      console.error(`[SSE] Cleaning up old session: ${sessionId}`)
      transportMap.delete(sessionId)
      sessionTimestamps.delete(sessionId)
    }
  }
}

// Run cleanup every minute
setInterval(cleanupOldSessions, 60 * 1000)

// Server Setup
const server = new Server(
  {
    name: "virustotal-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {
        listChanged: true,
      },
    },
  }
);

// Handle Initialization
server.setRequestHandler(InitializeRequestSchema, async (request) => {
  logToFile("Received initialize request.");
  return {
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
    instructions: `VirusTotal Analysis Server

This server provides comprehensive security analysis tools using the VirusTotal API. Each analysis tool automatically fetches relevant relationship data (e.g., contacted domains, downloaded files) along with the basic report.

For more detailed relationship analysis, dedicated relationship tools are available to query specific types of relationships with pagination support.

Available Analysis Types:
- URLs: Security reports and relationships like contacted domains
- Files: Analysis results and relationships like dropped files
- IPs: Security reports and relationships like historical data
- Domains: DNS information and relationships like subdomains

All tools return formatted results with clear categorization and relationship data.`,
  };
});

// Register Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [
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
  ];

  logToFile("Registered tools.");
  return { tools };
});

// Create axios instance
const axiosInstance = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: {
    'x-apikey': API_KEY,
  },
});

// Handle Tool Calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  logToFile(`Tool called: ${request.params.name}`);

  try {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "get_url_report":
        return await handleGetUrlReport(axiosInstance, args);

      case "get_url_relationship":
        return await handleGetUrlRelationship(axiosInstance, args);

      case "get_file_report":
        return await handleGetFileReport(axiosInstance, args);

      case "get_file_relationship":
        return await handleGetFileRelationship(axiosInstance, args);

      case "get_ip_report":
        return await handleGetIpReport(axiosInstance, args);

      case "get_ip_relationship":
        return await handleGetIpRelationship(axiosInstance, args);

      case "get_domain_report":
        return await handleGetDomainReport(axiosInstance, args);

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logToFile(`Error handling tool call: ${errorMessage}`);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

async function main() {
  const port = process.env.PORT ? parseInt(process.env.PORT) : 3000
  const host = process.env.HOST || 'localhost'

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    console.error(`[HTTP] ${req.method} ${req.url} - ${new Date().toISOString()}`)

    // Health check endpoint
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      incrementHttpRequests('GET', '/health', 200)
      res.end(JSON.stringify({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'virustotal-mcp',
        activeSessions: Array.from(transportMap.keys()),
        totalSessions: transportMap.size,
        sessionTimestamps: Object.fromEntries(sessionTimestamps),
      }))
    }

    // Metrics endpoint
    else if (req.method === 'GET' && req.url === '/metrics') {
      try {
        const metrics = await getMetrics()
        res.writeHead(200, { 'Content-Type': 'text/plain' })
        incrementHttpRequests('GET', '/metrics', 200)
        res.end(metrics)
      } catch (error) {
        console.error('[METRICS] Error getting metrics:', error)
        res.writeHead(500, { 'Content-Type': 'text/plain' })
        incrementHttpRequests('GET', '/metrics', 500)
        res.end('Error getting metrics')
      }
    }

    // Debug endpoint for session management
    else if (req.method === 'GET' && req.url === '/debug/sessions') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      incrementHttpRequests('GET', '/debug/sessions', 200)
      res.end(JSON.stringify({
        activeSessions: Array.from(transportMap.keys()),
        totalSessions: transportMap.size,
        sessionTimestamps: Object.fromEntries(sessionTimestamps),
        timestamp: new Date().toISOString(),
      }))
    }

    // Handle SSE GET connection
    else if (req.method === 'GET' && req.url?.startsWith('/sse')) {
      const urlObj = new URL(req.url, `http://${req.headers.host}`)
      let sessionId = urlObj.searchParams.get('sessionId')

      // Generate a session ID if not provided
      if (!sessionId) {
        sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        console.error('[SSE] No sessionId provided, generated:', sessionId)
      } else {
        console.error('[SSE] Using provided sessionId:', sessionId)
      }

      console.error('[SSE] New SSE connection established for session:', sessionId)
      incrementHttpRequests('GET', '/sse', 200)

      try {
        const transport = new SSEServerTransport('/sse', res)
        transportMap.set(sessionId, transport)
        sessionTimestamps.set(sessionId, Date.now())
        console.error(`[SSE] Transport stored in map. Total sessions: ${transportMap.size}`)

        console.error('[SSE] Transport created, connecting to server...')
        await server.connect(transport)
        console.error('[SSE] Server connected, starting transport...')
        console.error('[SSE] Transport started successfully')
        
        // Set up cleanup when the connection closes
        res.on('close', () => {
          console.error(`[SSE] Connection closed for session: ${sessionId}`)
          transportMap.delete(sessionId)
          sessionTimestamps.delete(sessionId)
          console.error(`[SSE] Transport removed from map. Remaining sessions: ${transportMap.size}`)
        })
        
        res.on('error', (error) => {
          console.error(`[SSE] Connection error for session ${sessionId}:`, error)
          transportMap.delete(sessionId)
          sessionTimestamps.delete(sessionId)
          console.error(`[SSE] Transport removed from map due to error. Remaining sessions: ${transportMap.size}`)
        })
      } catch (error) {
        console.error('[SSE] Error in SSE connection:', error)
        transportMap.delete(sessionId)
        sessionTimestamps.delete(sessionId)
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'SSE connection failed' }))
        }
      }
    }

    // Handle SSE POST messages
    else if (req.method === 'POST' && req.url?.startsWith('/sse')) {
      let sessionId: string | undefined
      let originalSessionId: string | undefined

      try {
        const urlObj = new URL(req.url, `http://${req.headers.host}`)
        sessionId = urlObj.searchParams.get('sessionId') || undefined
        originalSessionId = sessionId
      } catch {}

      // If no sessionId in POST, try to find the first available transport
      if (!sessionId) {
        console.error(`[SSE] POST /sse received without sessionId, looking for available transport`)
        const availableSessions = Array.from(transportMap.keys())
        if (availableSessions.length > 0) {
          sessionId = availableSessions[0]
          console.error(`[SSE] Using first available session: ${sessionId}`)
        }
      }

      if (!sessionId) {
        console.error(`[SSE] No sessionId provided and no available transports`)
        res.writeHead(400, { 'Content-Type': 'application/json' })
        incrementHttpRequests('POST', '/sse', 400)
        res.end(JSON.stringify({ error: 'No SSE connection established' }))
        return
      }

      let transport = transportMap.get(sessionId)
      let usedSessionId = sessionId

      // If the specific session is not found, try to use any available transport
      if (!transport) {
        console.error(`[SSE] No transport found for session: ${sessionId}`)
        console.error(`[SSE] Available sessions: ${Array.from(transportMap.keys()).join(', ')}`)
        console.error(`[SSE] Total active sessions: ${transportMap.size}`)
        
        // Try to use the first available transport as a fallback
        const availableSessions = Array.from(transportMap.keys())
        if (availableSessions.length > 0) {
          const fallbackSessionId = availableSessions[0]
          transport = transportMap.get(fallbackSessionId)
          usedSessionId = fallbackSessionId
          console.error(`[SSE] Using fallback session: ${fallbackSessionId}`)
          
          // Update the session timestamp to keep it alive
          sessionTimestamps.set(fallbackSessionId, Date.now())
        }
      } else {
        // Update the session timestamp to keep it alive
        sessionTimestamps.set(sessionId, Date.now())
      }

      if (!transport) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        incrementHttpRequests('POST', '/sse', 400)
        res.end(JSON.stringify({ 
          error: 'SSE connection not established',
          availableSessions: Array.from(transportMap.keys()),
          totalSessions: transportMap.size,
          requestedSession: originalSessionId,
          usedSession: usedSessionId
        }))
        return
      }

      try {
        await transport.handlePostMessage(req, res)
        console.error(`[SSE] POST message handled successfully for session: ${usedSessionId}`)
        incrementHttpRequests('POST', '/sse', 200)
      } catch (error) {
        console.error(`[SSE] Error handling POST message for session ${usedSessionId}:`, error)
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' })
          incrementHttpRequests('POST', '/sse', 500)
          res.end(JSON.stringify({ error: 'POST message handling failed' }))
        }
      }
    }

    // 404 fallback
    else {
      console.error(`[HTTP] 404 - Not Found: ${req.method} ${req.url}`)
      res.writeHead(404)
      incrementHttpRequests(req.method || 'UNKNOWN', req.url || '/unknown', 404)
      res.end('Not Found')
    }
  })

  httpServer.listen(port, host, () => {
    console.error(`[SERVER] VirusTotal MCP server starting...`)
    console.error(`[SERVER] Server running on SSE at http://${host}:${port}/sse`)
    console.error(`[SERVER] Health check available at http://${host}:${port}/health`)
    console.error(`[SERVER] Metrics available at http://${host}:${port}/metrics`)
    console.error(`[SERVER] Debug sessions available at http://${host}:${port}/debug/sessions`)
    console.error(`[SERVER] Server started at ${new Date().toISOString()}`)
  })

  process.on('SIGINT', () => {
    console.error('[SERVER] Received SIGINT, shutting down gracefully...')
    httpServer.close(() => {
      console.error('[SERVER] Server closed')
      process.exit(0)
    })
  })

  process.on('SIGTERM', () => {
    console.error('[SERVER] Received SIGTERM, shutting down gracefully...')
    httpServer.close(() => {
      console.error('[SERVER] Server closed')
      process.exit(0)
    })
  })
}

// Handle process events
process.on('uncaughtException', (error) => {
  logToFile(`Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logToFile(`Unhandled rejection: ${reason}`);
  process.exit(1);
});

main().catch((error: any) => {
  logToFile(`Fatal error: ${error.message}`);
  process.exit(1);
});
