#!/usr/bin/env node
// Per-model streaming control for pi-ai's openai-completions.js.
// pi-ai hardcodes stream:true; the params.streaming workaround doesn't reach here (openclaw#12218).
//
// This patch adds per-model streaming control. Each model's "streaming" setting in
// openclaw.json determines behavior: false (default) uses non-streaming API calls with
// synthesized stream events; true uses native streaming.

const fs = require("fs");

const file = process.argv[2] ||
  "/home/agent/.npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/providers/openai-completions.js";

let code = fs.readFileSync(file, "utf8");

// Anchor: the streaming create call followed by event setup
const anchor = `const openaiStream = await client.chat.completions.create(params, { signal: options?.signal });
            stream.push({ type: "start", partial: output });
            let currentBlock = null;
            const blocks = output.content;
            const blockIndex = () => blocks.length - 1;`;

if (!code.includes(anchor)) {
  if (code.includes("nonStreamParams")) {
    console.log("patch-streaming.js: already patched, skipping");
    process.exit(0);
  }
  console.error("patch-streaming.js: anchor text not found — pi-ai version may have changed");
  process.exit(1);
}

const replacement = `// PATCHED: per-model streaming config
            let _skipStreamLoop = false;
            let _shouldStream = false;
            try {
                const _fs = require('fs');
                const _cfg = JSON.parse(_fs.readFileSync('/home/agent/.openclaw/openclaw.json', 'utf8'));
                const _models = _cfg.agents?.defaults?.models || {};
                const _modelCfg = _models[params.model] || _models['nearai/' + params.model] || {};
                if (_modelCfg.streaming === true) _shouldStream = true;
            } catch(_e) { /* config read failed, stay non-streaming */ }
            var openaiStream;
            var currentBlock = null;
            var blocks;
            var blockIndex;
            if (_shouldStream) {
                // STREAMING PATH: original pi-ai behavior
                openaiStream = await client.chat.completions.create(params, { signal: options?.signal });
                stream.push({ type: "start", partial: output });
                blocks = output.content;
                blockIndex = () => blocks.length - 1;
            } else {
                // NON-STREAMING PATH: synthesize stream events from complete response
                const nonStreamParams = { ...params, stream: false };
                delete nonStreamParams.stream_options;
                const completion = await client.chat.completions.create(nonStreamParams, { signal: options?.signal });
                stream.push({ type: "start", partial: output });
                blocks = output.content;
                blockIndex = () => blocks.length - 1;
                if (completion.usage) {
                    const cachedTokens = completion.usage.prompt_tokens_details?.cached_tokens || 0;
                    const reasoningTokens = completion.usage.completion_tokens_details?.reasoning_tokens || 0;
                    const inp = (completion.usage.prompt_tokens || 0) - cachedTokens;
                    const out = (completion.usage.completion_tokens || 0) + reasoningTokens;
                    output.usage = { input: inp, output: out, cacheRead: cachedTokens, cacheWrite: 0, totalTokens: inp + out + cachedTokens, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
                }
                const _choice = completion.choices?.[0];
                const _msg = _choice?.message;
                if (_msg?.reasoning_content) {
                    const blk = { type: "thinking", thinking: _msg.reasoning_content, thinkingSignature: "reasoning_content" };
                    blocks.push(blk);
                    stream.push({ type: "thinking_start", contentIndex: blockIndex(), partial: output });
                    stream.push({ type: "thinking_delta", contentIndex: blockIndex(), delta: _msg.reasoning_content, partial: output });
                    stream.push({ type: "thinking_end", contentIndex: blockIndex(), content: _msg.reasoning_content, partial: output });
                }
                if (_msg?.content) {
                    const blk = { type: "text", text: _msg.content };
                    blocks.push(blk);
                    stream.push({ type: "text_start", contentIndex: blockIndex(), partial: output });
                    stream.push({ type: "text_delta", contentIndex: blockIndex(), delta: _msg.content, partial: output });
                    stream.push({ type: "text_end", contentIndex: blockIndex(), content: _msg.content, partial: output });
                }
                if (_msg?.tool_calls) {
                    for (const _tc of _msg.tool_calls) {
                        let _args = {};
                        try { _args = JSON.parse(_tc.function.arguments || "{}"); } catch(e) { console.error("patch-streaming: failed to parse tool args for", _tc.function.name, e.message); _args = {}; }
                        const blk = { type: "toolCall", id: _tc.id, name: _tc.function.name, arguments: _args };
                        blocks.push(blk);
                        stream.push({ type: "toolcall_start", contentIndex: blockIndex(), partial: output });
                        stream.push({ type: "toolcall_delta", contentIndex: blockIndex(), delta: _tc.function.arguments || "{}", partial: output });
                        stream.push({ type: "toolcall_end", contentIndex: blockIndex(), toolCall: blk, partial: output });
                    }
                }
                if (_choice?.finish_reason === "tool_calls") output.stopReason = "toolUse";
                else if (_choice?.finish_reason === "length") output.stopReason = "maxTokens";
                else output.stopReason = "stop";
                stream.push({ type: "done", reason: output.stopReason, message: output });
                stream.end();
                _skipStreamLoop = true;
            }`;

code = code.replace(anchor, replacement);

// Make the for-await loop skip when we already handled everything
code = code.replace(
  "for await (const chunk of openaiStream) {",
  "for await (const chunk of (_skipStreamLoop ? [] : openaiStream)) {"
);

fs.writeFileSync(file, code);
console.log("patch-streaming.js: patched successfully");
