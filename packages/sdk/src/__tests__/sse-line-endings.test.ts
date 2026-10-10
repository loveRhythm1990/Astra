import { afterEach, expect, test, vi } from 'vitest';
import { parseSseDataEvents, SSEClient } from '../sse-client';
import type { StreamEvent } from '../types';

afterEach(() => vi.unstubAllGlobals());
const events = [
  { type: 'text_delta', content: '中文🙂' },
  { type: 'run_finished', run_id: 'synthetic-run' },
] as StreamEvent[];

for (const [name, separator] of [['LF', '\n'], ['CRLF', '\r\n'], ['CR', '\r']]) {
  const raw = events.map((event) => `data: ${JSON.stringify(event)}${separator}${separator}`).join('');
  test(`buffered SSE preserves ${name} events`, () => {
    expect(parseSseDataEvents(raw)).toEqual(events);
  });
  for (const chunkSize of [1, 7, 999]) {
    test(`live SSE preserves ${name} events with ${chunkSize}-byte chunks`, async () => {
      const bytes = new TextEncoder().encode(raw);
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          for (let i = 0; i < bytes.length; i += chunkSize) {
            controller.enqueue(bytes.slice(i, i + chunkSize));
          }
          controller.close();
        },
      });
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body)));
      const received: StreamEvent[] = [];
      const client = new SSEClient({
        url: 'https://example.test/stream', maxRetries: 0, requireTerminalEvent: true,
        onEvent: (event) => received.push(event),
      });
      await client.connect();
      client.close();
      expect(received).toEqual(events);
    });
  }
}

test('buffered and live parsing share mixed lines, BOM, comments, multiline data, and EOF tolerance', async () => {
  const raw = '\uFEFF: keepalive\r\nevent: ignored\r' +
    'data: {"type":\n' + 'data: "text_delta", "content":"中文🙂"}\r\n\r' +
    'data:{"type":"run_finished","run_id":"synthetic-run"}';
  expect(parseSseDataEvents(raw)).toEqual(events);
  const bytes = new TextEncoder().encode(raw);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
    start(controller) {
      for (const byte of bytes) controller.enqueue(Uint8Array.of(byte));
      controller.close();
    },
  }))));
  const received: StreamEvent[] = [];
  const lines: string[] = [];
  const client = new SSEClient({
    url: 'https://example.test/stream', maxRetries: 0, requireTerminalEvent: true,
    onEvent: (event) => received.push(event), onRawLine: (line) => lines.push(line),
  });
  await client.connect();
  client.close();
  expect(received).toEqual(events);
  expect(lines).toContain(': keepalive');
  expect(lines.every((line) => !/[\r\n]/.test(line))).toBe(true);
});

test('CR terminal is delivered before EOF or the next byte arrives', async () => {
  let source!: ReadableStreamDefaultController<Uint8Array>;
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
    start(controller) { source = controller; },
  }))));
  const received: StreamEvent[] = [];
  let delivered!: () => void;
  const terminal = new Promise<void>((resolve) => { delivered = resolve; });
  const client = new SSEClient({
    url: 'https://example.test/stream', maxRetries: 0, requireTerminalEvent: true,
    onEvent: (event) => { received.push(event); delivered(); },
  });
  const pending = client.connect();
  source.enqueue(new TextEncoder().encode('data: {"type":"run_finished"}\r\r'));
  try {
    await terminal;
    expect(received).toEqual([{ type: 'run_finished' }]);
  } finally {
    source.close();
    await pending;
    client.close();
  }
});
