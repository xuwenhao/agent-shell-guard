export type ShellDialect = 'bash' | 'posix' | 'zsh';
export type CommandSource =
  | 'top-level'
  | 'shell-c'
  | 'eval'
  | 'command-substitution'
  | 'backtick-substitution'
  | 'process-substitution';

export interface AnalysisUnknown {
  reason: string;
  detail: string;
}

export interface AnalyzedCommand {
  argv: Array<string | null>;
  rawArgv: Array<string | null>;
  displayArgv: string[];
  dialect: ShellDialect;
  source: CommandSource;
  span: { start: number; end: number };
  wrappers: string[];
  hasRedirection: boolean;
  pipelineGroup: number | null;
}

export interface AnalyzedRedirection {
  /** shfmt v3.13.1 RedirOperator value */
  op: number;
  fd: string | null;
  target: string | null;
}

export interface ShellGraph {
  status: 'safe' | 'unknown';
  dialect: ShellDialect;
  commands: AnalyzedCommand[];
  unknowns: AnalysisUnknown[];
  hasPipeline: boolean;
  hasRedirection: boolean;
  hasSubstitution: boolean;
  hasCompound: boolean;
  nativePromptArgv: string[] | null;
  redirections: AnalyzedRedirection[];
}

export type ShellInput =
  | { kind: 'script'; text: string }
  | { kind: 'argv'; argv: string[] };

export interface AnalyzeOptions {
  dialect: ShellDialect;
  shfmtPath?: string;
  zshPath?: string;
  timeoutMs?: number;
  maxInputBytes?: number;
  maxRecursion?: number;
  maxCommands?: number;
}

export interface ProjectInfo {
  /** Nearest enclosing repository (where project settings are read). */
  gitRoot: string | null;
  /** Outermost enclosing repository below home (thin project root). */
  projectRoot: string | null;
  sandboxConfigured: boolean;
  nestedRepos: boolean;
}

export interface GuardOptions extends Omit<AnalyzeOptions, 'dialect'> {
  profile?: string;
  envShell?: string;
  protectedRoots?: string[];
  protectedPaths?: string[];
  /** Read-only project lookup; defaults to the filesystem inspector. */
  inspectDirectory?: (directory: string) => ProjectInfo;
}

export interface GuardAllow {
  kind: 'allow';
  command: string;
  description: string;
  analysis: ShellGraph;
}

export interface GuardIntervention {
  kind: 'deny' | 'confirm' | 'review';
  evaluation: 'matched' | 'unknown';
  ruleId: string;
  command: string;
  description: string;
  detail: string;
  why: string;
  analysis: ShellGraph;
}

export type GuardDecision = GuardAllow | GuardIntervention;

export interface ReviewerConfig {
  command: string;
  args: string[];
  model?: string;
  timeoutMs: number;
}

export interface GuardConfig {
  mode: 'strict' | 'reviewed';
  profile: 'full' | 'dangerous-only' | 'legacy-dangerous' | 'off';
  shfmtPath: string;
  zshPath?: string;
  protectedRoots: string[];
  protectedPaths: string[];
  nativePrompt: { codex: boolean; grok: boolean; kimi: boolean };
  reviewer: ReviewerConfig | null;
}

export interface HookOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'ask' | 'deny';
    permissionDecisionReason: string;
  };
}

export interface GrokHookOutput {
  decision: 'deny';
  reason: string;
}

export function analyzeShellInput(input: ShellInput, options: AnalyzeOptions): ShellGraph;
export function selectShellDialect(input: {
  toolName: string;
  explicitShell?: string;
  envShell?: string;
}): ShellDialect;
export function evaluateHookEvent(
  event: Record<string, unknown>,
  options?: GuardOptions,
): GuardDecision | null;
export function explainGuardDecision(result: GuardIntervention): string;
export function inspectDirectory(
  directory: string,
  options?: { ephemeralRoots?: string[] },
): ProjectInfo;
export function isReadOnlyGraph(graph: ShellGraph): boolean;
export function permissionTier(mode: unknown): 'relaxed' | 'bypass';
export function loadConfig(options?: {
  configPath?: string;
  env?: Record<string, string | undefined>;
}): GuardConfig;
export function resolveShfmtPath(
  explicit?: string,
  env?: Record<string, string | undefined>,
): string;
export function resolveDecision(
  decision: GuardDecision,
  options: {
    supportsHookPrompt: boolean;
    nativePromptCovered: boolean;
    mode: 'strict' | 'reviewed';
    reviewer: ReviewerConfig | null;
  },
): {
  action: 'allow' | 'deny' | 'prompt' | 'delegate';
  reason?: string;
  reasonCode?: 'hard-deny' | 'native-prompt-unavailable' | 'reviewer-not-configured' | 'reviewer-denied';
  reviewer?: { decision: 'allow' | 'deny' | 'uncertain'; reason: string };
};
export function adaptClaude(event: Record<string, unknown>, config: GuardConfig): HookOutput | null;
export function adaptCodex(event: Record<string, unknown>, config: GuardConfig): HookOutput | null;
export function adaptGrok(event: Record<string, unknown>, config: GuardConfig): GrokHookOutput | null;
export function grokDenyOutput(reason: string): GrokHookOutput;
export function adaptKimi(event: Record<string, unknown>, config: GuardConfig): HookOutput | null;
export const GROK_NATIVE_PROMPT_PREFIXES: Map<string, string[][]>;
export const GROK_PERMISSION_PATTERNS: string[];
export function isGrokNativePromptCovered(
  ruleId: string,
  analysis: Pick<ShellGraph, 'nativePromptArgv'>,
  command: string,
): boolean;
export const KIMI_NATIVE_PROMPT_PREFIXES: Map<string, string[][]>;
export const KIMI_PERMISSION_PATTERNS: string[];
export function isKimiNativePromptCovered(
  ruleId: string,
  analysis: Pick<ShellGraph, 'nativePromptArgv'>,
  command: string,
): boolean;
