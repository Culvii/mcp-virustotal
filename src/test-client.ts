import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { config } from 'dotenv'

// Load environment variables silently
config({ debug: false })

async function testMCPServer() {
  // Check environment variables
  const requiredEnvVars = [
    'VIRUSTOTAL_API_KEY',
  ]

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      console.error(`❌ Missing required environment variable: ${envVar}`)
      console.error(
        'Please set all required environment variables before running the test.',
      )
      process.exit(1)
    }
  }

  console.log('✅ All required environment variables are set.')

  const baseUrl = process.env.MCP_SERVER_URL || 'http://localhost:3000'
  const transport = new SSEClientTransport(new URL(`${baseUrl}/sse`))

  const client = new Client(
    {
      name: 'test-client',
      version: '1.0.0',
    },
    {
      capabilities: {},
    },
  )

  try {
    console.log('Connecting to MCP server...')
    await client.connect(transport)
    console.log('✅ Connected to MCP server')

    // List available tools
    console.log('\nListing available tools...')
    const toolsResponse = await client.listTools()
    console.log(
      'Available tools:',
      JSON.stringify(toolsResponse.tools, null, 2),
    )

    // Test the get_url_report tool
    const testUrl = process.argv[2] || 'https://www.google.com'
    console.log(`\nTesting get_url_report tool with URL: ${testUrl}`)

    const result = await client.callTool({
      name: 'get_url_report',
      arguments: {
        url: testUrl,
      },
    })

    console.log('\n✅ Tool executed successfully!')
    console.log('Result:', JSON.stringify(result, null, 2))
  } catch (error) {
    console.error('❌ Error:', error)
  } finally {
    console.log('\nClosing connection...')
    await client.close()
    process.exit(0)
  }
}

// Run the test
testMCPServer().catch(console.error) 