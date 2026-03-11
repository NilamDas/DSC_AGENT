// TypeScript declarations for dsc-agent-client.js

export interface HealthInfo {
  ok?: boolean;
  dll?: string;
  slotPresent?: boolean;
  promptAvailable?: boolean;
  [key: string]: any;
}

export interface SignOptions {
  reason?: string;
  includeESS?: boolean;
  embedIntermediates?: boolean;
  signingTime?: string;
  pin?: string;
  requirePin?: boolean;
  rememberSessionPin?: boolean;
  stampAllPages?: boolean;
  // Placement options
  rect?: [number, number, number, number]; // when rectMode='pdf': [x1,y1,x2,y2] in PDF points (origin bottom-left)
  rectMode?: 'pdf' | 'top-left';           // 'top-left': rect interpreted as [left, top, width, height]
  rectNorm?: [number, number, number, number]; // normalized [nx,ny,nw,nh] in 0..1
  page?: number | 'last';                  // 1-based page index or 'last'
  duplicateWidgets?: boolean;              // duplicate clickable widgets across pages when stamping
  anchor?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right';
}

export interface BatchOptions extends SignOptions {
  pinPrompt?: () => Promise<string> | string;
}

export interface SignResult {
  ok: true;
  signedPdfBase64: string;
}

export interface ErrorResult {
  ok: false;
  message: string;
}

export interface BatchResult {
  ok: true;
  results: Array<SignResult | ErrorResult>;
}

export interface Client {
  base: string;
  health(): Promise<HealthInfo>;
  signPdf(data: ArrayBuffer | ArrayBufferView | string, opts?: SignOptions): Promise<SignResult>;
  signPdfBatch(items: Array<ArrayBuffer | ArrayBufferView | string | Blob>, opts?: BatchOptions): Promise<BatchResult>;
}

export declare const utils: {
  toBase64(input: ArrayBuffer | ArrayBufferView | string): string;
  fileToArrayBuffer(file: Blob): Promise<ArrayBuffer>;
};

export function discover(timeoutMs?: number, ports?: number[]): Promise<Client>;
export function createClient(base: string): Client;
declare const _default: { discover: typeof discover; createClient: typeof createClient; utils: typeof utils };
export default _default;

