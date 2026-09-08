declare module "node:crypto" {
  export function createHmac(algorithm: string, key: string | Uint8Array): {
    update(data: string | Uint8Array): any;
    digest(): Buffer;
  };
  export function createHash(algorithm: string): {
    update(data: string | Uint8Array): any;
    digest(encoding: "hex"): string;
  };
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
}

declare module "node:assert/strict" {
  const assert: {
    equal(actual: unknown, expected: unknown, message?: string): void;
  };
  export default assert;
}

declare module "node:test" {
  export default function test(name: string, fn: () => void | Promise<void>): void;
}

declare module "node:http" {
  export interface IncomingMessage {
    method?: string;
    url?: string;
    headers: { authorization?: string };
  }
  export interface ServerResponse {
    statusCode: number;
    setHeader(name: string, value: string | number): void;
    end(data?: string | Uint8Array): void;
  }
  export interface Server {
    listen(port: number, host: string, callback?: () => void): void;
  }
  export function createServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Server;
}

declare class Buffer extends Uint8Array {
  static from(input: string | Uint8Array, encoding?: string): Buffer;
  static byteLength(input: string): number;
  toString(encoding?: string): string;
}

declare const process: {
  argv: string[];
};

declare class URL {
  constructor(input: string, base?: string);
  pathname: string;
}
