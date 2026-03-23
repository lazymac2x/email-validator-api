const express = require("express");
const cors = require("cors");
const { validateEmail, validateBatch, checkDomain, suggestFix } = require("./validator");

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// ---------- REST endpoints ----------

app.get("/health", (_req, res) => {
  res.json({ status: "ok", version: "1.0.0", timestamp: new Date().toISOString() });
});

app.post("/validate", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email field is required" });
    const result = await validateEmail(email);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/validate/batch", async (req, res) => {
  try {
    const { emails } = req.body;
    if (!Array.isArray(emails)) return res.status(400).json({ error: "emails must be an array" });
    if (emails.length > 100) return res.status(400).json({ error: "Maximum 100 emails per batch" });
    const result = await validateBatch(emails);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/domain", async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: "domain field is required" });
    const result = await checkDomain(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/suggest", (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email field is required" });
    const result = suggestFix(email);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- MCP JSON-RPC endpoint ----------

const MCP_TOOLS = [
  {
    name: "validate_email",
    description:
      "Validate a single email address with comprehensive checks: syntax (RFC 5322), MX records, disposable domain detection, role-based detection, SPF/DKIM, typo suggestions, and risk scoring (0-100).",
    inputSchema: {
      type: "object",
      properties: {
        email: { type: "string", description: "Email address to validate" },
      },
      required: ["email"],
    },
  },
  {
    name: "validate_batch",
    description:
      "Batch validate up to 100 email addresses at once. Returns individual results plus summary stats.",
    inputSchema: {
      type: "object",
      properties: {
        emails: {
          type: "array",
          items: { type: "string" },
          description: "Array of email addresses (max 100)",
        },
      },
      required: ["emails"],
    },
  },
  {
    name: "check_domain",
    description:
      "Check domain reputation: MX records, SPF, DKIM, disposable detection, A record existence, and overall reputation score.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domain to check (e.g. gmail.com)" },
      },
      required: ["domain"],
    },
  },
  {
    name: "suggest_fix",
    description:
      "Detect common email typos and suggest corrections (e.g. user@gmial.com → user@gmail.com). Covers Gmail, Yahoo, Hotmail, Outlook, iCloud, Protonmail, and more.",
    inputSchema: {
      type: "object",
      properties: {
        email: { type: "string", description: "Email address to check for typos" },
      },
      required: ["email"],
    },
  },
];

async function handleMcpToolCall(name, args) {
  switch (name) {
    case "validate_email":
      return await validateEmail(args.email);
    case "validate_batch":
      return await validateBatch(args.emails);
    case "check_domain":
      return await checkDomain(args.domain);
    case "suggest_fix":
      return suggestFix(args.email);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

app.post("/mcp", async (req, res) => {
  const { jsonrpc, id, method, params } = req.body;

  if (jsonrpc !== "2.0") {
    return res.json({ jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid JSON-RPC version" } });
  }

  try {
    let result;

    switch (method) {
      case "initialize":
        result = {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: {
            name: "email-validator-api",
            version: "1.0.0",
            description:
              "Comprehensive email validation: syntax, MX, disposable detection, role-based detection, SPF/DKIM, typo suggestions, risk scoring",
          },
        };
        break;

      case "tools/list":
        result = { tools: MCP_TOOLS };
        break;

      case "tools/call": {
        const { name, arguments: toolArgs } = params || {};
        if (!name) {
          return res.json({ jsonrpc: "2.0", id, error: { code: -32602, message: "Missing tool name" } });
        }
        const toolResult = await handleMcpToolCall(name, toolArgs || {});
        result = {
          content: [{ type: "text", text: JSON.stringify(toolResult, null, 2) }],
        };
        break;
      }

      default:
        return res.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Method not found: ${method}` },
        });
    }

    res.json({ jsonrpc: "2.0", id, result });
  } catch (err) {
    res.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32000, message: err.message },
    });
  }
});

// ---------- Start ----------

const PORT = process.env.PORT || 3100;
const server = app.listen(PORT, () => {
  console.log(`email-validator-api running on http://localhost:${PORT}`);
  console.log(`  REST: POST /validate, /validate/batch, /domain, /suggest`);
  console.log(`  MCP:  POST /mcp (JSON-RPC 2.0)`);
});

module.exports = { app, server };
