import { readFile, stat } from "node:fs/promises";

const TEMPLATE_FILES = {
  welcome: new URL("./templates/welcome.html", import.meta.url),
  connection: new URL("./templates/connection.html", import.meta.url),
  install: new URL("./templates/install.html", import.meta.url),
  network: new URL("./templates/network.html", import.meta.url),
  registration: new URL("./templates/registration.html", import.meta.url),
  success: new URL("./templates/success.html", import.meta.url),
  styles: new URL("./templates/styles.css", import.meta.url),
  client: new URL("./templates/client.js", import.meta.url),
  connectionClient: new URL("./templates/connection-client.js", import.meta.url),
  installClient: new URL("./templates/install-client.js", import.meta.url),
  networkClient: new URL("./templates/network-client.js", import.meta.url),
  registrationClient: new URL("./templates/registration-client.js", import.meta.url),
  successClient: new URL("./templates/success-client.js", import.meta.url),
  agreement: new URL("./templates/operator-agreement.html", import.meta.url),
};

export interface WelcomeHtmlInput {
  progress: Record<string, unknown>;
  agreementVersion: string;
  logoUrl: string;
  faviconUrl: string;
  progressUrl: string;
  agreementUrl: string;
  nextUrl: string;
  reloadUrl: string;
  serverStartId: string;
  devReload: boolean;
}

export async function renderWelcomeHtml(input: WelcomeHtmlInput): Promise<string> {
  const [template, styles, clientScript, agreementContent] = await Promise.all([
    readText(TEMPLATE_FILES.welcome),
    readText(TEMPLATE_FILES.styles),
    readText(TEMPLATE_FILES.client),
    readText(TEMPLATE_FILES.agreement),
  ]);
  const config = safeScriptJson({
    progress: input.progress,
    agreementVersion: input.agreementVersion,
    progressUrl: input.progressUrl,
    agreementUrl: input.agreementUrl,
    nextUrl: input.nextUrl,
    reloadUrl: input.reloadUrl,
    serverStartId: input.serverStartId,
    devReload: input.devReload,
  });

  return injectTemplate(template, {
    AGREEMENT_CONTENT: agreementContent,
    AGREEMENT_VERSION: escapeHtml(input.agreementVersion),
    CLIENT_SCRIPT: clientScript,
    CONFIG_JSON: config,
    FAVICON_URL: escapeHtml(input.faviconUrl),
    LOGO_URL: escapeHtml(input.logoUrl),
    STYLES: styles,
  });
}

export interface ConnectionHtmlInput {
  progress: Record<string, unknown>;
  logoUrl: string;
  faviconUrl: string;
  bunLogoUrl: string;
  pm2LogoUrl: string;
  installDir: string;
  defaultInstallDir: string;
  backUrl: string;
  connectionUrl: string;
  installUrl: string;
  installDirSelectUrl: string;
  environmentUrl: string;
  bunInstallUrl: string;
  pm2InstallUrl: string;
  reloadUrl: string;
  serverStartId: string;
  devReload: boolean;
}

export async function renderConnectionHtml(input: ConnectionHtmlInput): Promise<string> {
  const [template, styles, clientScript] = await Promise.all([
    readText(TEMPLATE_FILES.connection),
    readText(TEMPLATE_FILES.styles),
    readText(TEMPLATE_FILES.connectionClient),
  ]);
  const config = safeScriptJson({
    progress: input.progress,
    backUrl: input.backUrl,
    connectionUrl: input.connectionUrl,
    installUrl: input.installUrl,
    installDirSelectUrl: input.installDirSelectUrl,
    environmentUrl: input.environmentUrl,
    bunInstallUrl: input.bunInstallUrl,
    pm2InstallUrl: input.pm2InstallUrl,
    reloadUrl: input.reloadUrl,
    serverStartId: input.serverStartId,
    devReload: input.devReload,
  });

  return injectTemplate(template, {
    CLIENT_SCRIPT: clientScript,
    CONFIG_JSON: config,
    BUN_LOGO_URL: escapeHtml(input.bunLogoUrl),
    DEFAULT_INSTALL_DIR: escapeHtml(input.defaultInstallDir),
    FAVICON_URL: escapeHtml(input.faviconUrl),
    INSTALL_DIR: escapeHtml(input.installDir),
    LOGO_URL: escapeHtml(input.logoUrl),
    PM2_LOGO_URL: escapeHtml(input.pm2LogoUrl),
    STYLES: styles,
  });
}

export interface InstallHtmlInput {
  progress: Record<string, unknown>;
  logoUrl: string;
  faviconUrl: string;
  installDir: string;
  backUrl: string;
  manifestUrl: string;
  installUrl: string;
  nextUrl: string;
  reloadUrl: string;
  serverStartId: string;
  devReload: boolean;
}

export async function renderInstallHtml(input: InstallHtmlInput): Promise<string> {
  const [template, styles, clientScript] = await Promise.all([
    readText(TEMPLATE_FILES.install),
    readText(TEMPLATE_FILES.styles),
    readText(TEMPLATE_FILES.installClient),
  ]);
  const config = safeScriptJson({
    progress: input.progress,
    backUrl: input.backUrl,
    manifestUrl: input.manifestUrl,
    installUrl: input.installUrl,
    nextUrl: input.nextUrl,
    reloadUrl: input.reloadUrl,
    serverStartId: input.serverStartId,
    devReload: input.devReload,
  });

  return injectTemplate(template, {
    CLIENT_SCRIPT: clientScript,
    CONFIG_JSON: config,
    FAVICON_URL: escapeHtml(input.faviconUrl),
    INSTALL_DIR: escapeHtml(input.installDir),
    LOGO_URL: escapeHtml(input.logoUrl),
    STYLES: styles,
  });
}

export interface NetworkHtmlInput {
  progress: Record<string, unknown>;
  logoUrl: string;
  faviconUrl: string;
  backUrl: string;
  statusUrl: string;
  runUrl: string;
  nextUrl: string;
  reloadUrl: string;
  serverStartId: string;
  devReload: boolean;
}

export async function renderNetworkHtml(input: NetworkHtmlInput): Promise<string> {
  const [template, styles, clientScript] = await Promise.all([
    readText(TEMPLATE_FILES.network),
    readText(TEMPLATE_FILES.styles),
    readText(TEMPLATE_FILES.networkClient),
  ]);
  const config = safeScriptJson({
    progress: input.progress,
    backUrl: input.backUrl,
    statusUrl: input.statusUrl,
    runUrl: input.runUrl,
    nextUrl: input.nextUrl,
    reloadUrl: input.reloadUrl,
    serverStartId: input.serverStartId,
    devReload: input.devReload,
  });

  return injectTemplate(template, {
    CLIENT_SCRIPT: clientScript,
    CONFIG_JSON: config,
    FAVICON_URL: escapeHtml(input.faviconUrl),
    LOGO_URL: escapeHtml(input.logoUrl),
    STYLES: styles,
  });
}

export interface RegistrationHtmlInput {
  progress: Record<string, unknown>;
  logoUrl: string;
  faviconUrl: string;
  backUrl: string;
  statusUrl: string;
  emailStartUrl: string;
  emailVerifyUrl: string;
  walletSessionUrl: string;
  walletStatusUrl: string;
  registerUrl: string;
  successUrl: string;
  reloadUrl: string;
  serverStartId: string;
  devReload: boolean;
}

export async function renderRegistrationHtml(input: RegistrationHtmlInput): Promise<string> {
  const [template, styles, clientScript] = await Promise.all([
    readText(TEMPLATE_FILES.registration),
    readText(TEMPLATE_FILES.styles),
    readText(TEMPLATE_FILES.registrationClient),
  ]);
  const config = safeScriptJson({
    progress: input.progress,
    backUrl: input.backUrl,
    statusUrl: input.statusUrl,
    emailStartUrl: input.emailStartUrl,
    emailVerifyUrl: input.emailVerifyUrl,
    walletSessionUrl: input.walletSessionUrl,
    walletStatusUrl: input.walletStatusUrl,
    registerUrl: input.registerUrl,
    successUrl: input.successUrl,
    reloadUrl: input.reloadUrl,
    serverStartId: input.serverStartId,
    devReload: input.devReload,
  });

  return injectTemplate(template, {
    CLIENT_SCRIPT: clientScript,
    CONFIG_JSON: config,
    FAVICON_URL: escapeHtml(input.faviconUrl),
    LOGO_URL: escapeHtml(input.logoUrl),
    STYLES: styles,
  });
}

export interface SuccessHtmlInput {
  progress: Record<string, unknown>;
  logoUrl: string;
  faviconUrl: string;
  statusUrl: string;
  pm2Url: string;
  reloadUrl: string;
  serverStartId: string;
  devReload: boolean;
}

export async function renderSuccessHtml(input: SuccessHtmlInput): Promise<string> {
  const [template, styles, clientScript] = await Promise.all([
    readText(TEMPLATE_FILES.success),
    readText(TEMPLATE_FILES.styles),
    readText(TEMPLATE_FILES.successClient),
  ]);
  const config = safeScriptJson({
    progress: input.progress,
    statusUrl: input.statusUrl,
    pm2Url: input.pm2Url,
    reloadUrl: input.reloadUrl,
    serverStartId: input.serverStartId,
    devReload: input.devReload,
  });

  return injectTemplate(template, {
    CLIENT_SCRIPT: clientScript,
    CONFIG_JSON: config,
    FAVICON_URL: escapeHtml(input.faviconUrl),
    LOGO_URL: escapeHtml(input.logoUrl),
    STYLES: styles,
  });
}

export async function setupWizardTemplateVersion(serverStartId: string): Promise<string> {
  const versions = await Promise.all(
    Object.values(TEMPLATE_FILES).map(async (file) => {
      const fileStat = await stat(file);
      return `${file.pathname}:${fileStat.size}:${fileStat.mtimeMs}`;
    }),
  );
  return `${serverStartId}:${versions.join("|")}`;
}

async function readText(url: URL): Promise<string> {
  return readFile(url, "utf8");
}

function injectTemplate(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{([A-Z0-9_]+)\}\}/g, (match, key: string) => values[key] ?? match);
}

function safeScriptJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
