import type { Context } from "hono";

export type CveHeaders = {
  "CVE-API-ORG": string;
  "CVE-API-USER": string;
  "CVE-API-KEY": string;
};

export type Submitter = { kind: "submitter"; name: string; submitterId: number; tokenId: number };

export type Agent = Omit<Submitter, "kind"> & { kind: "agent" };

export type Actor = { kind: "cna_user"; name: string; headers: CveHeaders } | Submitter | Agent;

/** A request cvedexd sends itself, as an actor already signed in: a proposal or an MCP tool call. */
export type Replay = { actor: Actor; proposalId?: string };

export type Env = {
  DB: D1Database;
  CVE_API_URL: string;
  CVE_API_ORG: string;
  CVE_API_USER: string;
  CVE_API_KEY: string;
  VERSION: string;
  MAX_OPEN_IDS: string;
  WEBHOOK_URL?: string;
  AUTH_LIMITER: RateLimit;
  REPLAY?: Replay;
};

export type AppEnv = {
  Bindings: Env;
  Variables: { actor?: Actor; proposalId?: string };
};

export type AppContext = Context<AppEnv>;
