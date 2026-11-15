import crypto from "node:crypto";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  saveOAuthState,
  buildTwitchAuthorizationUrl,
  getChannelOverview,
  getLiveStatus,
  getRecentVideos,
  getRecentClips,
  disconnectTwitch
} from "../lib/twitch.js";

function textResult(value) {
  return {
    content: [{
      type: "text",
      text: typeof value === "string" ? value : JSON.stringify(value, null, 2)
    }]
  };
}

function createServer() {
  const server = new McpServer(
    { name: "beuraverse-twitch", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "start_twitch_authorization",
    {
      title: "Connect Twitch account",
      description: "Create a one-time Twitch authorization link. Open the returned URL, review the consent screen, and approve it to connect the account. This initial connection requests no additional Twitch scopes; it is limited to the authorized profile and public channel activity.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }
    },
    async () => {
      if (!process.env.TWITCH_CLIENT_SECRET) {
        throw new Error("Twitch setup is incomplete: add TWITCH_CLIENT_SECRET to the Vercel project's Production, Preview, and Development environments, then redeploy.");
      }
      const state = crypto.randomBytes(32).toString("hex");
      await saveOAuthState(state);
      const url = buildTwitchAuthorizationUrl(state);
      return textResult({
        authorization_url: url,
        expires_in_minutes: 10,
        instructions: "Open the authorization URL, review the requested access, and approve BeuraVerse. Return to ChatGPT after the success page appears."
      });
    }
  );

  server.registerTool(
    "get_channel_overview",
    {
      title: "Get Twitch channel overview",
      description: "Read the connected Twitch profile, channel title and category, and current live status. Does not change channel settings.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true }
    },
    async () => textResult(await getChannelOverview())
  );

  server.registerTool(
    "get_live_status",
    {
      title: "Check live status",
      description: "Check whether the connected Twitch channel is live and, if so, return the stream title, category, viewer count, and start time.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true }
    },
    async () => textResult(await getLiveStatus())
  );

  server.registerTool(
    "get_recent_videos",
    {
      title: "Get recent Twitch videos",
      description: "List up to five recent videos from the connected Twitch channel, including title, URL, date, duration, and view count.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true }
    },
    async () => textResult(await getRecentVideos())
  );

  server.registerTool(
    "get_recent_clips",
    {
      title: "Get recent Twitch clips",
      description: "List up to five clips created during the last seven days for the connected Twitch channel.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true }
    },
    async () => textResult(await getRecentClips())
  );

  server.registerTool(
    "disconnect_twitch",
    {
      title: "Disconnect Twitch account",
      description: "Revoke the current Twitch access token and delete the encrypted BeuraVerse session. This does not delete Twitch content.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true }
    },
    async () => {
      const disconnected = await disconnectTwitch();
      return textResult(disconnected ? "Twitch was disconnected and the stored session was deleted." : "No Twitch account was connected.");
    }
  );

  return server;
}

const mcpHandler = createMcpHandler(createServer);

function constantTimeEqual(left, right) {
  if (!left || !right) return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export default async function handler(request) {
  const expected = process.env.BEURAVERSE_MCP_API_KEY;
  const authorization = request.headers.get("authorization") || "";
  const presented = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";

  if (!expected || !constantTimeEqual(presented, expected)) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "WWW-Authenticate": 'Bearer realm="BeuraVerse Twitch MCP"',
        "Cache-Control": "no-store"
      }
    });
  }

  const response = await mcpHandler.fetch(request);
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
