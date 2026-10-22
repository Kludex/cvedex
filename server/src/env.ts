import type { Context } from "hono";

export type CveHeaders = {
  "CVE-API-ORG": string;
  "CVE-API-USER": string;
  "CVE-API-KEY": string;
};

export type Submitter = { kind: "submitter"; name: string; submitterId: number; tokenId: number };

export type Agent = Omit<Submitter, "kind"> & { kind: "agent" };

export type Actor = { kind: "cna_user"; name: string; headers: CveHeaders } | Submitter | Agent;

export type Replay = { actor: Submitter; proposalId: string };

export type Env = {
  DB: D1Database;
  CVE_API_URL: string;
  CVE_API_ORG: string;
  CVE_API_USER: string;
  CVE_API_KEY: string;
  VERSION: string;
  REPLAY?: Replay;
};

export type AppEnv = {
  Bindings: Env;
  Variables: { actor?: Actor; proposalId?: string };
};

export type AppContext = Context<AppEnv>;
