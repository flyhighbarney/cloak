import * as vscode from "vscode";
import { scan, label, Finding } from "./patterns";

let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let debounceTimer: NodeJS.Timeout | undefined;
let sessionCounts = { scanned: 0, findings: 0 };

export function activate(context: vscode.ExtensionContext) {
  diagnostics = vscode.languages.createDiagnosticCollection("policyd");
  context.subscriptions.push(diagnostics);

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = "policyd.showFindings";
  context.subscriptions.push(statusBar);
  refreshStatusBar();
  statusBar.show();

  context.subscriptions.push(
    vscode.commands.registerCommand("policyd.scanCurrentFile", scanCurrentFile),
    vscode.commands.registerCommand("policyd.scanSelection", scanSelection),
    vscode.commands.registerCommand("policyd.showFindings", showFindings),
    vscode.commands.registerCommand("policyd.configure", configureGateway),
  );

  // Scan on open and on switch.
  vscode.workspace.textDocuments.forEach(scanDocument);
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(scanDocument),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) scanDocument(editor.document);
    }),
  );

  // Scan on save (config-gated).
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (vscode.workspace.getConfiguration("policyd").get<boolean>("scanOnSave", true)) {
        scanDocument(doc);
      }
    }),
  );

  // Scan while typing (debounced).
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((ev) => {
      if (!vscode.workspace.getConfiguration("policyd").get<boolean>("scanOnType", true)) {
        return;
      }
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => scanDocument(ev.document), 500);
    }),
  );
}

export function deactivate() {
  diagnostics?.dispose();
}

// -------- Scanning --------

function scanDocument(doc: vscode.TextDocument): Finding[] {
  // Skip untitled/large files and non-file schemes.
  if (doc.uri.scheme !== "file" && doc.uri.scheme !== "untitled") return [];
  if (doc.getText().length > 1024 * 1024) return []; // 1 MiB cap

  const findings = scan(doc.getText());
  sessionCounts.scanned++;
  sessionCounts.findings += findings.length;

  const severity = severityFromConfig();
  const diags: vscode.Diagnostic[] = findings.map((f) => {
    const start = doc.positionAt(f.start);
    const end = doc.positionAt(f.end);
    const range = new vscode.Range(start, end);
    const d = new vscode.Diagnostic(
      range,
      `Do not send this to a public AI: ${label(f.kind)} detected. policyd will redact or block it.`,
      severity,
    );
    d.source = "policyd";
    d.code = f.kind;
    return d;
  });
  diagnostics.set(doc.uri, diags);
  refreshStatusBar();
  return findings;
}

function severityFromConfig(): vscode.DiagnosticSeverity {
  const s = vscode.workspace.getConfiguration("policyd").get<string>("severity", "warning");
  switch (s) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "information":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

// -------- Commands --------

function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showInformationMessage("policyd: no active editor");
    return;
  }
  const findings = scanDocument(editor.document);
  if (findings.length === 0) {
    vscode.window.showInformationMessage("policyd: no findings ✓");
  } else {
    vscode.window.showWarningMessage(`policyd: ${findings.length} finding(s) in this file`);
  }
}

function scanSelection() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const selection = editor.document.getText(editor.selection);
  const findings = scan(selection);
  if (findings.length === 0) {
    vscode.window.showInformationMessage("policyd: selection is clean ✓");
  } else {
    const kinds = [...new Set(findings.map((f) => label(f.kind)))].join(", ");
    vscode.window.showWarningMessage(`policyd: selection contains ${kinds}`);
  }
}

function showFindings() {
  const total = sessionCounts.findings;
  const scanned = sessionCounts.scanned;
  const gateway = vscode.workspace.getConfiguration("policyd").get<string>("gatewayUrl", "");
  const gwLine = gateway ? `Gateway: ${gateway}/admin` : "No gateway configured — run policyd: Configure Gateway";
  vscode.window.showInformationMessage(
    `policyd session: ${scanned} scans, ${total} findings. ${gwLine}`,
  );
}

async function configureGateway() {
  const current = vscode.workspace.getConfiguration("policyd").get<string>("gatewayUrl", "");
  const url = await vscode.window.showInputBox({
    prompt: "policyd gateway URL",
    value: current,
    placeHolder: "https://gateway.example.com",
    validateInput: (v) => (v && !/^https?:\/\//i.test(v) ? "must start with http:// or https://" : null),
  });
  if (url !== undefined) {
    await vscode.workspace.getConfiguration("policyd").update("gatewayUrl", url, true);
    vscode.window.showInformationMessage(`policyd: gateway set to ${url}`);
  }
}

function refreshStatusBar() {
  statusBar.text = `$(shield) policyd: ${sessionCounts.findings} finding${sessionCounts.findings === 1 ? "" : "s"}`;
  statusBar.tooltip = `${sessionCounts.scanned} files scanned this session\nClick for details`;
}
