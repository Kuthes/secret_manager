"use client";

if (typeof window !== "undefined" && !(window as Record<string, unknown>).Buffer) {
  (window as Record<string, unknown>).Buffer = {
    from: (str: string) => ({
      toString: (encoding?: string) => (encoding === "base64" ? btoa(encodeURIComponent(str)) : str),
    }),
  };
}

import { useMemo, useState, type Dispatch, type SetStateAction } from "react";
import { motion, AnimatePresence } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Boxes,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  Copy,
  Database,
  Download,
  Eye,
  EyeOff,
  FileKey2,
  Fingerprint,
  GitBranch,
  History,
  KeyRound,
  LayoutDashboard,
  Lock,
  MoreHorizontal,
  Network,
  Play,
  Plus,
  RefreshCw,
  RotateCw,
  Search,
  SearchX,
  Settings,
  ShieldCheck,
  Terminal,
  Users,
  Vault,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { toast, Toaster } from "sonner";

// --- TYPES ---

interface SecretVersion {
  version: number;
  value: string;
  actor: string;
  timestamp: string;
}

interface Secret {
  id: string;
  key: string;
  value: string;
  environment: string;
  path: string;
  updated: string;
  actor: string;
  version: number;
  rotation?: string;
  versions: SecretVersion[];
}

interface DynamicLease {
  id: string;
  provider: string;
  username: string;
  secret: string;
  expiresIn: string;
  status: "Active" | "Revoked";
}

interface Certificate {
  id: string;
  commonName: string;
  issuer: string;
  san: string[];
  daysLeft: number;
  autoRenew: boolean;
  status: "Active" | "Revoked" | "Expiring";
}

interface KMSKey {
  id: string;
  name: string;
  algorithm: string;
  purpose: string;
  created: string;
  status: "Enabled" | "Disabled";
}

interface AccessRequest {
  id: string;
  requester: string;
  resource: string;
  reason: string;
  duration: string;
  status: "Pending" | "Approved" | "Rejected" | "Revoked";
  requestedAt: string;
}

interface AuditLog {
  id: string;
  action: string;
  actor: string;
  resource: string;
  timestamp: string;
  status: "Success" | "Failed" | "Warning";
  ip: string;
  details?: string;
}

interface ScanResult {
  rule: string;
  file: string;
  line: number;
  preview: string;
  fingerprint: string;
  severity: "Critical" | "High" | "Medium";
}

type LogEventFn = (action: string, resource: string, status?: "Success" | "Failed" | "Warning", details?: string) => void;

let globalSeqCounter = 1000;

function generateId(prefix: string): string {
  globalSeqCounter += 1;
  return `${prefix}-${globalSeqCounter}`;
}

function generateToken(prefix: string): string {
  globalSeqCounter += 1;
  return `${prefix}_token_${globalSeqCounter.toString(36)}`;
}

interface SecretsPageProps {
  environment: string;
  setEnvironment: (e: string) => void;
  query: string;
  setQuery: (q: string) => void;
  filteredSecrets: Secret[];
  revealed: string[];
  toggleReveal: (key: string) => void;
  copyToClipboard: (val: string, label: string) => void;
  handleRotateSecret: (id: string) => void;
  handleDeleteSecret: (id: string, key: string) => void;
  openAddSecret: boolean;
  setOpenAddSecret: (o: boolean) => void;
  newKey: string;
  setNewKey: (k: string) => void;
  newValue: string;
  setNewValue: (v: string) => void;
  newPath: string;
  setNewPath: (p: string) => void;
  newRotation: string;
  setNewRotation: (r: string) => void;
  handleAddSecret: () => void;
  setSelectedSecretForVersions: (s: Secret | null) => void;
}

interface CertificatesPageProps {
  certificates: Certificate[];
  setCertificates: Dispatch<SetStateAction<Certificate[]>>;
  logEvent: LogEventFn;
}

interface KMSPageProps {
  kmsKeys: KMSKey[];
  logEvent: LogEventFn;
}

interface AccessPageProps {
  requests: AccessRequest[];
  setRequests: Dispatch<SetStateAction<AccessRequest[]>>;
  logEvent: LogEventFn;
}

// --- INITIAL SEED DATA ---

const initialSecrets: Secret[] = [
  {
    id: "sec-1",
    key: "DATABASE_URL",
    value: "postgresql://aegis:demo_pass_924@postgres:5432/app_prod",
    environment: "production",
    path: "/backend",
    updated: "8 min ago",
    actor: "Maya Chen",
    version: 7,
    rotation: "30 days",
    versions: [
      { version: 7, value: "postgresql://aegis:demo_pass_924@postgres:5432/app_prod", actor: "Maya Chen", timestamp: "8 min ago" },
      { version: 6, value: "postgresql://aegis:old_pass_881@postgres:5432/app_prod", actor: "Rotation bot", timestamp: "30 days ago" },
      { version: 5, value: "postgresql://aegis:init_pass_102@postgres:5432/app_prod", actor: "Noah Williams", timestamp: "60 days ago" },
    ],
  },
  {
    id: "sec-2",
    key: "STRIPE_SECRET_KEY",
    value: "sk_test_mock_stripe_key_902Lz81P",
    environment: "production",
    path: "/payments",
    updated: "42 min ago",
    actor: "Rotation bot",
    version: 12,
    rotation: "14 days",
    versions: [
      { version: 12, value: "sk_test_mock_stripe_key_902Lz81P", actor: "Rotation bot", timestamp: "42 min ago" },
      { version: 11, value: "sk_test_mock_stripe_key_01290Kzz", actor: "Rotation bot", timestamp: "14 days ago" },
    ],
  },
  {
    id: "sec-3",
    key: "REDIS_URL",
    value: "redis://:cache_auth_8912@cache.acme.internal:6379/0",
    environment: "production",
    path: "/backend",
    updated: "Yesterday",
    actor: "Noah Williams",
    version: 3,
    versions: [
      { version: 3, value: "redis://:cache_auth_8912@cache.acme.internal:6379/0", actor: "Noah Williams", timestamp: "Yesterday" },
    ],
  },
  {
    id: "sec-4",
    key: "JWT_SIGNING_KEY",
    value: "aegis_5tQ8w912mZ091Xkaj0912Kz",
    environment: "production",
    path: "/auth",
    updated: "2 days ago",
    actor: "Maya Chen",
    version: 4,
    rotation: "60 days",
    versions: [
      { version: 4, value: "aegis_5tQ8w912mZ091Xkaj0912Kz", actor: "Maya Chen", timestamp: "2 days ago" },
    ],
  },
  {
    id: "sec-5",
    key: "OPENAI_API_KEY",
    value: "sk-proj-xJ2991kaMzz9102Lkaa109",
    environment: "production",
    path: "/ai",
    updated: "3 days ago",
    actor: "Noah Williams",
    version: 2,
    versions: [
      { version: 2, value: "sk-proj-xJ2991kaMzz9102Lkaa109", actor: "Noah Williams", timestamp: "3 days ago" },
    ],
  },
];

const initialCertificates: Certificate[] = [
  { id: "cert-1", commonName: "api.prod.acme.dev", issuer: "AegisVault Root CA", san: ["api.prod.acme.dev", "api-fallback.acme.dev"], daysLeft: 71, autoRenew: true, status: "Active" },
  { id: "cert-2", commonName: "internal-ca.acme", issuer: "Self-Signed Intermediate", san: ["*.acme.internal"], daysLeft: 340, autoRenew: false, status: "Active" },
  { id: "cert-3", commonName: "checkout.prod.svc", issuer: "AegisVault Intermediate CA", san: ["checkout.prod.svc.cluster.local"], daysLeft: 5, autoRenew: true, status: "Expiring" },
];

const initialKMSKeys: KMSKey[] = [
  { id: "kms-1", name: "payments-master", algorithm: "AES-256-GCM", purpose: "Envelope Encryption Core", created: "30 days ago", status: "Enabled" },
  { id: "kms-2", name: "session-signing", algorithm: "Ed25519", purpose: "JWT & Token Signatures", created: "60 days ago", status: "Enabled" },
  { id: "kms-3", name: "backup-wrapping", algorithm: "RSA-4096", purpose: "DB Snapshot Key Wrapping", created: "90 days ago", status: "Enabled" },
];

const initialAccessRequests: AccessRequest[] = [
  { id: "acc-1", requester: "Noah Williams", resource: "Production DB Read/Write", reason: "Investigating slow payment webhooks in prod", duration: "1 hour", status: "Pending", requestedAt: "10 min ago" },
  { id: "acc-2", requester: "Isha Patel", resource: "Kubernetes Cluster Admin", reason: "Applying security patch to ingress controller", duration: "2 hours", status: "Pending", requestedAt: "25 min ago" },
  { id: "acc-3", requester: "Maya Chen", resource: "Stripe Console Credentials", reason: "Auditing billing refund discrepancy", duration: "4 hours", status: "Approved", requestedAt: "3 hours ago" },
];

const initialAuditLogs: AuditLog[] = [
  { id: "aud-1", action: "secret.read", actor: "Saurabh Kuthe", resource: "DATABASE_URL", timestamp: "Just now", status: "Success", ip: "192.168.1.104" },
  { id: "aud-2", action: "kms.encrypt", actor: "payments-api", resource: "payments-master", timestamp: "2 min ago", status: "Success", ip: "10.244.0.12" },
  { id: "aud-3", action: "pki.issue", actor: "pki-agent", resource: "api.prod.acme.dev", timestamp: "1 hour ago", status: "Success", ip: "10.244.1.88" },
  { id: "aud-4", action: "access.approve", actor: "Saurabh Kuthe", resource: "Stripe Console Credentials", timestamp: "3 hours ago", status: "Success", ip: "192.168.1.104" },
  { id: "aud-5", action: "secret.rotate", actor: "Rotation bot", resource: "STRIPE_SECRET_KEY", timestamp: "42 min ago", status: "Success", ip: "127.0.0.1" },
];

const navigationItems: readonly (readonly [string, LucideIcon])[] = [
  ["Overview", LayoutDashboard],
  ["Secrets", Vault],
  ["Dynamic secrets", Clock3],
  ["Secret rotations", RotateCw],
  ["Secret scanning", GitBranch],
  ["Integrations", Boxes],
  ["Certificates", FileKey2],
  ["KMS", KeyRound],
  ["Access", Fingerprint],
  ["Audit logs", Activity],
] as const;

interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  avatar: string;
}

const initialProfiles: UserProfile[] = [
  { id: "usr-1", name: "Saurabh Kuthe", email: "saurabh@aegisvault.local", role: "Owner", avatar: "SK" },
  { id: "usr-2", name: "Maya Chen", email: "maya@aegisvault.local", role: "Security Lead", avatar: "MC" },
  { id: "usr-3", name: "Noah Williams", email: "noah@aegisvault.local", role: "DevOps Lead", avatar: "NW" },
];

export default function Home() {
  const [section, setSection] = useState("Overview");
  const [environment, setEnvironment] = useState("production");
  const [query, setQuery] = useState("");
  const [revealed, setRevealed] = useState<string[]>([]);
  const [secrets, setSecrets] = useState<Secret[]>(initialSecrets);
  const [certificates, setCertificates] = useState<Certificate[]>(initialCertificates);
  const [kmsKeys] = useState<KMSKey[]>(initialKMSKeys);
  const [accessRequests, setAccessRequests] = useState<AccessRequest[]>(initialAccessRequests);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>(initialAuditLogs);

  // User Profile state
  const [profiles, setProfiles] = useState<UserProfile[]>(initialProfiles);
  const [currentUser, setCurrentUser] = useState<UserProfile>(initialProfiles[0]);

  // Modals state
  const [openAddSecret, setOpenAddSecret] = useState(false);
  const [openProfileModal, setOpenProfileModal] = useState(false);
  const [selectedSecretForVersions, setSelectedSecretForVersions] = useState<Secret | null>(null);

  // Profile Form state
  const [newProfileName, setNewProfileName] = useState("");
  const [newProfileEmail, setNewProfileEmail] = useState("");
  const [newProfileRole, setNewProfileRole] = useState("Security Engineer");
  
  // Form states
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const [newPath, setNewPath] = useState("/backend");
  const [newRotation, setNewRotation] = useState("None");

  // Filtered secrets by environment and query
  const filteredSecrets = useMemo(() => {
    return secrets.filter((s) => {
      const matchEnv = s.environment === environment;
      const matchQuery = `${s.key} ${s.path}`.toLowerCase().includes(query.toLowerCase());
      return matchEnv && matchQuery;
    });
  }, [environment, query, secrets]);

  // Helper to add audit log event
  const logEvent: LogEventFn = (action, resource, status = "Success", details) => {
    const id = generateId("aud");
    const newLog: AuditLog = {
      id,
      action,
      actor: currentUser.name,
      resource,
      timestamp: "Just now",
      status,
      ip: "192.168.1.104",
      details,
    };
    setAuditLogs((prev) => [newLog, ...prev]);
  };

  const handleCreateProfile = () => {
    if (!newProfileName.trim()) return toast.error("Name is required");
    const nameStr = newProfileName.trim();
    const initials = nameStr.split(" ").map((n) => n[0]).join("").toUpperCase().substring(0, 2) || "US";
    const created: UserProfile = {
      id: generateId("usr"),
      name: nameStr,
      email: newProfileEmail.trim() || `${nameStr.toLowerCase().replace(/\s+/g, ".")}@aegisvault.local`,
      role: newProfileRole,
      avatar: initials,
    };
    setProfiles((prev) => [...prev, created]);
    setCurrentUser(created);
    setNewProfileName("");
    setNewProfileEmail("");
    setOpenProfileModal(false);
    toast.success(`Profile created for ${created.name}`);
    logEvent("user.profile.create", created.name);
  };

  // Actions
  const copyToClipboard = async (val: string, label: string) => {
    await navigator.clipboard?.writeText(val);
    toast.success(`${label} copied to clipboard`);
    logEvent("secret.copy", label);
  };

  const toggleReveal = (key: string) => {
    const isNowRevealed = !revealed.includes(key);
    setRevealed((prev) =>
      prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]
    );
    if (isNowRevealed) {
      logEvent("secret.reveal", key);
    }
  };

  const handleAddSecret = () => {
    if (!newKey.trim() || !newValue.trim()) {
      return toast.error("Key and value are required");
    }
    const secId = generateId("sec");
    const created: Secret = {
      id: secId,
      key: newKey.trim().toUpperCase(),
      value: newValue,
      environment,
      path: newPath.startsWith("/") ? newPath : `/${newPath}`,
      updated: "Just now",
      actor: currentUser.name,
      version: 1,
      rotation: newRotation === "None" ? undefined : newRotation,
      versions: [
        { version: 1, value: newValue, actor: currentUser.name, timestamp: "Just now" }
      ]
    };

    setSecrets((prev) => [created, ...prev]);
    setNewKey("");
    setNewValue("");
    setOpenAddSecret(false);
    toast.success(`Secret ${created.key} encrypted and saved`);
    logEvent("secret.create", created.key);
  };

  const handleRotateSecret = (secretId: string) => {
    setSecrets((prev) =>
      prev.map((s) => {
        if (s.id === secretId) {
          const nextVer = s.version + 1;
          const newVal = generateToken(`${s.value.split("_")[0]}_rotated`);
          const updatedVer: SecretVersion = {
            version: nextVer,
            value: newVal,
            actor: "Rotation Bot",
            timestamp: "Just now",
          };
          toast.success(`Secret ${s.key} rotated to v${nextVer}`);
          logEvent("secret.rotate", s.key);
          return {
            ...s,
            version: nextVer,
            value: newVal,
            updated: "Just now",
            actor: "Rotation Bot",
            versions: [updatedVer, ...s.versions],
          };
        }
        return s;
      })
    );
  };

  const handleRollbackSecret = (secretId: string, targetVersion: SecretVersion) => {
    setSecrets((prev) =>
      prev.map((s) => {
        if (s.id === secretId) {
          toast.success(`Rolled back ${s.key} to version ${targetVersion.version}`);
          logEvent("secret.rollback", `${s.key} (v${targetVersion.version})`);
          return {
            ...s,
            value: targetVersion.value,
            updated: "Just now (Rollback)",
            actor: "Saurabh Kuthe",
          };
        }
        return s;
      })
    );
    setSelectedSecretForVersions(null);
  };

  const handleDeleteSecret = (secretId: string, keyName: string) => {
    setSecrets((prev) => prev.filter((s) => s.id !== secretId));
    toast.success(`Secret ${keyName} deleted`);
    logEvent("secret.delete", keyName, "Warning");
  };

  return (
    <div className="app-shell">
      <Toaster position="bottom-right" theme="dark" richColors />
      
      {/* Sidebar */}
      <aside className="sidebar" aria-label="Sidebar Navigation">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={16} />
          </div>
          <span>AegisVault</span>
          <span className="version">v1.4.0</span>
        </div>

        <button type="button" className="org-switcher" aria-label="Switch organization: Acme Cloud">
          <div className="org-avatar" aria-hidden="true">AC</div>
          <div>
            <strong>Acme Cloud</strong>
            <span>Organization</span>
          </div>
          <ChevronDown size={14} aria-hidden="true" />
        </button>

        <nav className="nav-list" aria-label="Main menu">
          <p>Workspace</p>
          {navigationItems.slice(0, 6).map(([label, Icon]) => {
            const isActive = section === label;
            return (
              <button
                type="button"
                key={label}
                className={isActive ? "active" : ""}
                onClick={() => setSection(label)}
                aria-current={isActive ? "page" : undefined}
              >
                {isActive && (
                  <motion.div
                    layoutId="sidebar-active-pill"
                    className="absolute inset-0 bg-white rounded-md z-0"
                    transition={{ type: "spring", stiffness: 380, damping: 30 }}
                  />
                )}
                <Icon
                  size={15}
                  className={`z-10 relative ${isActive ? "text-zinc-950" : ""}`}
                  aria-hidden="true"
                />
                <span className={`z-10 relative ${isActive ? "text-zinc-950 font-semibold" : ""}`}>
                  {label}
                </span>
              </button>
            );
          })}

          <p>Security</p>
          {navigationItems.slice(6).map(([label, Icon]) => {
            const isActive = section === label;
            return (
              <button
                type="button"
                key={label}
                className={isActive ? "active" : ""}
                onClick={() => setSection(label)}
                aria-current={isActive ? "page" : undefined}
              >
                {isActive && (
                  <motion.div
                    layoutId="sidebar-active-pill"
                    className="absolute inset-0 bg-white rounded-md z-0"
                    transition={{ type: "spring", stiffness: 380, damping: 30 }}
                  />
                )}
                <Icon
                  size={15}
                  className={`z-10 relative ${isActive ? "text-zinc-950" : ""}`}
                  aria-hidden="true"
                />
                <span className={`z-10 relative ${isActive ? "text-zinc-950 font-semibold" : ""}`}>
                  {label}
                </span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <button type="button" onClick={() => toast.info("Documentation opened")}>
            <CircleHelp size={15} aria-hidden="true" />
            <span>Documentation</span>
          </button>
          <button type="button" onClick={() => toast.info("Settings opened")}>
            <Settings size={15} aria-hidden="true" />
            <span>Settings</span>
          </button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="user w-full text-left bg-transparent border-0 hover:bg-zinc-900/80 p-2 rounded-lg transition-colors cursor-pointer"
                aria-label="User profile options"
              >
                <div className="avatar" aria-hidden="true">{currentUser.avatar}</div>
                <div className="flex-1 min-w-0">
                  <strong className="truncate block text-xs font-semibold text-white">{currentUser.name}</strong>
                  <span className="truncate block text-[11px] text-zinc-400">{currentUser.role}</span>
                </div>
                <MoreHorizontal size={14} className="text-zinc-500 hover:text-zinc-200" aria-hidden="true" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56 bg-zinc-950 border-zinc-800 text-zinc-100">
              <div className="p-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500 border-b border-zinc-800">
                Active Profile
              </div>
              {profiles.map((p) => (
                <DropdownMenuItem
                  key={p.id}
                  onClick={() => {
                    setCurrentUser(p);
                    toast.success(`Switched active profile to ${p.name}`);
                    logEvent("user.profile.switch", p.name);
                  }}
                  className="flex items-center justify-between cursor-pointer hover:bg-zinc-900 py-2"
                >
                  <div className="flex items-center gap-2">
                    <div className="w-6 h-6 rounded bg-zinc-800 text-[10px] grid place-items-center font-bold text-white border border-zinc-700">
                      {p.avatar}
                    </div>
                    <div className="flex flex-col">
                      <span className="text-xs font-medium text-white">{p.name}</span>
                      <span className="text-[10px] text-zinc-400">{p.role}</span>
                    </div>
                  </div>
                  {currentUser.id === p.id && <Check size={14} className="text-emerald-400" />}
                </DropdownMenuItem>
              ))}
              <div className="border-t border-zinc-800 my-1" />
              <DropdownMenuItem
                onClick={() => setOpenProfileModal(true)}
                className="text-xs text-white hover:bg-zinc-900 cursor-pointer font-medium"
              >
                <Plus size={14} className="mr-2 text-zinc-400" />
                Create New Profile...
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main" id="main-content">
        <header className="topbar">
          <div className="crumb">
            <Database size={15} aria-hidden="true" />
            <span>Acme Cloud</span>
            <b aria-hidden="true">/</b>
            <strong>Payments API</strong>
            <Badge variant="outline" className="text-xs font-normal border-zinc-700 bg-zinc-900 text-zinc-300">
              {environment}
            </Badge>
          </div>

          <div className="top-actions">
            <button
              type="button"
              className="command"
              aria-label="Open command palette"
              onClick={() => toast.info("Command palette (⌘K)")}
            >
              <Search size={14} aria-hidden="true" />
              <span>Search anything</span>
              <kbd aria-hidden="true">⌘ K</kbd>
            </button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-9 text-xs font-normal"
              onClick={() => toast.success("CLI authenticated: av login --demo")}
            >
              <Terminal size={13} className="me-1.5" aria-hidden="true" />
              CLI
            </Button>
            <div className="status" role="status" aria-label="System status: Operational">
              <i aria-hidden="true" />
              <span>Operational</span>
            </div>
          </div>
        </header>

        <div className="content">
          <AnimatePresence mode="wait">
            <motion.div
              key={section}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              {section === "Overview" ? (
                <OverviewPage setSection={setSection} secretsCount={secrets.length} certsCount={certificates.length} pendingAccess={accessRequests.filter(a => a.status === "Pending").length} currentUserName={currentUser.name} />
              ) : section === "Secrets" ? (
                <SecretsPage
                  environment={environment}
                  setEnvironment={setEnvironment}
                  query={query}
                  setQuery={setQuery}
                  filteredSecrets={filteredSecrets}
                  revealed={revealed}
                  toggleReveal={toggleReveal}
                  copyToClipboard={copyToClipboard}
                  handleRotateSecret={handleRotateSecret}
                  handleDeleteSecret={handleDeleteSecret}
                  openAddSecret={openAddSecret}
                  setOpenAddSecret={setOpenAddSecret}
                  newKey={newKey}
                  setNewKey={setNewKey}
                  newValue={newValue}
                  setNewValue={setNewValue}
                  newPath={newPath}
                  setNewPath={setNewPath}
                  newRotation={newRotation}
                  setNewRotation={setNewRotation}
                  handleAddSecret={handleAddSecret}
                  setSelectedSecretForVersions={setSelectedSecretForVersions}
                />
              ) : section === "Dynamic secrets" ? (
                <DynamicSecretsPage logEvent={logEvent} />
              ) : section === "Secret rotations" ? (
                <RotationsPage secrets={secrets} handleRotateSecret={handleRotateSecret} />
              ) : section === "Secret scanning" ? (
                <SecretScanningPage logEvent={logEvent} />
              ) : section === "Integrations" ? (
                <IntegrationsPage logEvent={logEvent} />
              ) : section === "Certificates" ? (
                <CertificatesPage certificates={certificates} setCertificates={setCertificates} logEvent={logEvent} />
              ) : section === "KMS" ? (
                <KMSPage kmsKeys={kmsKeys} logEvent={logEvent} />
              ) : section === "Access" ? (
                <AccessPage requests={accessRequests} setRequests={setAccessRequests} logEvent={logEvent} />
              ) : (
                <AuditLogsPage auditLogs={auditLogs} />
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>

      {/* Version History Modal */}
      {selectedSecretForVersions && (
        <Dialog open={!!selectedSecretForVersions} onOpenChange={() => setSelectedSecretForVersions(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Version History: {selectedSecretForVersions.key}</DialogTitle>
              <DialogDescription>
                Immutable cryptographic version history. Roll back to any prior version.
              </DialogDescription>
            </DialogHeader>
            <div className="dialog-form">
              {selectedSecretForVersions.versions.map((ver) => (
                <div key={ver.version} className="flex items-center justify-between p-3 rounded-lg border border-zinc-800 bg-zinc-900/60">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-xs text-white">v{ver.version}</span>
                      {ver.version === selectedSecretForVersions.version && (
                        <Badge variant="outline" className="text-[10px] border-emerald-800 bg-emerald-950/60 text-emerald-300">Active</Badge>
                      )}
                    </div>
                    <p className="text-xs text-zinc-400 font-mono mt-1">{ver.value}</p>
                    <span className="text-[11px] text-zinc-500">{ver.actor} · {ver.timestamp}</span>
                  </div>
                  {ver.version !== selectedSecretForVersions.version && (
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => handleRollbackSecret(selectedSecretForVersions.id, ver)}
                    >
                      Rollback to v{ver.version}
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Create New Profile Modal */}
      <Dialog open={openProfileModal} onOpenChange={setOpenProfileModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New User Profile</DialogTitle>
            <DialogDescription>
              Add a new team member or role profile to switch identity contexts dynamically.
            </DialogDescription>
          </DialogHeader>
          <div className="dialog-form">
            <div>
              <label htmlFor="profile-name">Full Name</label>
              <Input
                id="profile-name"
                value={newProfileName}
                onChange={(e) => setNewProfileName(e.target.value)}
                placeholder="Alex Rivera"
              />
            </div>
            <div>
              <label htmlFor="profile-email">Email Address</label>
              <Input
                id="profile-email"
                type="email"
                value={newProfileEmail}
                onChange={(e) => setNewProfileEmail(e.target.value)}
                placeholder="alex@acme.dev"
              />
            </div>
            <div>
              <label htmlFor="profile-role">Role</label>
              <select
                id="profile-role"
                value={newProfileRole}
                onChange={(e) => setNewProfileRole(e.target.value)}
                className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 px-3 text-xs outline-none"
              >
                <option value="Owner">Owner</option>
                <option value="Security Lead">Security Lead</option>
                <option value="Security Engineer">Security Engineer</option>
                <option value="DevOps Lead">DevOps Lead</option>
                <option value="Auditor">Auditor</option>
              </select>
            </div>
            <Button type="button" onClick={handleCreateProfile} className="mt-2 h-9">
              Create Profile & Switch
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ==========================================
// SUB-PAGES & COMPONENTS
// ==========================================

function OverviewPage({
  setSection,
  secretsCount,
  certsCount,
  pendingAccess,
  currentUserName,
}: {
  setSection: (s: string) => void;
  secretsCount: number;
  certsCount: number;
  pendingAccess: number;
  currentUserName: string;
}) {
  return (
    <>
      <section className="page-heading">
        <div>
          <p className="eyebrow">Project Overview</p>
          <h1>Good morning, {currentUserName.split(" ")[0]}</h1>
          <p>Security control plane status and active workloads.</p>
        </div>
        <div className="heading-actions">
          <Button type="button" variant="outline" size="sm" className="h-9 gap-1.5" onClick={() => setSection("Audit logs")}>
            <History size={14} aria-hidden="true" />
            Audit log
          </Button>
          <Button type="button" size="sm" className="h-9 gap-1.5" onClick={() => setSection("Secrets")}>
            <Plus size={14} aria-hidden="true" />
            Add secret
          </Button>
        </div>
      </section>

      {/* Stats Cards */}
      <section className="stats" aria-label="Summary metrics">
        {[
          { label: "Active secrets", value: secretsCount.toString(), detail: "+2 this week", icon: Vault },
          { label: "Certificates", value: certsCount.toString(), detail: "1 expiring soon", icon: ShieldCheck },
          { label: "Healthy syncs", value: "4/4", detail: "GitHub, Vercel, AWS, K8s", icon: Network },
          { label: "Access requests", value: pendingAccess.toString(), detail: "Awaiting review", icon: Users },
        ].map(({ label, value, detail, icon: Icon }, idx) => (
          <motion.article
            key={label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2, delay: idx * 0.05 }}
            whileHover={{ y: -3, transition: { duration: 0.15 } }}
          >
            <div className="stat-header">
              <span>{label}</span>
              <Icon size={16} className="stat-icon" aria-hidden="true" />
            </div>
            <strong>{value}</strong>
            <small>{detail}</small>
          </motion.article>
        ))}
      </section>

      <div className="overview-grid">
        {/* Activity Feed */}
        <section className="panel activity-panel">
          <div className="panel-head">
            <div>
              <h2>Recent activity</h2>
              <p>Security audit events for this project</p>
            </div>
            <button type="button" onClick={() => setSection("Audit logs")}>View all</button>
          </div>
          <div className="timeline">
            {[
              ["Secret rotated", "STRIPE_SECRET_KEY rotated automatically", "8m ago", RotateCw],
              ["Certificate issued", "api.prod.acme.dev · 90-day validity", "1h ago", FileKey2],
              ["Access granted", "Noah Williams · expires in 55m", "3h ago", Fingerprint],
              ["Sync completed", "AWS Secrets Manager · synchronized", "5h ago", Check],
            ].map(([title, desc, time, Icon]) => (
              <div className="event" key={title}>
                <div className="event-icon">
                  <Icon size={14} aria-hidden="true" />
                </div>
                <div>
                  <strong>{title}</strong>
                  <p>{desc}</p>
                </div>
                <time>{time}</time>
              </div>
            ))}
          </div>
        </section>

        {/* Security Posture */}
        <section className="panel posture">
          <div className="panel-head">
            <div>
              <h2>Security posture</h2>
              <p>Configuration compliance score</p>
            </div>
            <span className="score">94%</span>
          </div>
          <div className="scorebar" role="progressbar" aria-valuenow={94} aria-valuemin={0} aria-valuemax={100}>
            <motion.i initial={{ width: 0 }} animate={{ width: "94%" }} transition={{ duration: 0.6, ease: "easeOut" }} />
          </div>
          <div className="checks">
            <div>
              <Check size={14} aria-hidden="true" />
              <span>Secret rotation enabled</span>
              <span>4/5</span>
            </div>
            <div>
              <Check size={14} aria-hidden="true" />
              <span>MFA required for all roles</span>
              <span>Enforced</span>
            </div>
            <div>
              <Check size={14} aria-hidden="true" />
              <span>Audit retention policy</span>
              <span>365 days</span>
            </div>
            <div>
              <Check size={14} aria-hidden="true" />
              <span>Envelope encryption active</span>
              <span>AES-256-GCM</span>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

function SecretsPage({
  environment,
  setEnvironment,
  query,
  setQuery,
  filteredSecrets,
  revealed,
  toggleReveal,
  copyToClipboard,
  handleRotateSecret,
  handleDeleteSecret,
  openAddSecret,
  setOpenAddSecret,
  newKey,
  setNewKey,
  newValue,
  setNewValue,
  newPath,
  setNewPath,
  newRotation,
  setNewRotation,
  handleAddSecret,
  setSelectedSecretForVersions,
}: SecretsPageProps) {
  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Secret Management</p>
          <h1>Secrets</h1>
          <p>Encrypted environment variables and key-value credentials.</p>
        </div>

        <Dialog open={openAddSecret} onOpenChange={setOpenAddSecret}>
          <DialogTrigger asChild>
            <Button size="sm" className="h-9 gap-1.5">
              <Plus size={15} aria-hidden="true" />
              Add secret
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add encrypted secret</DialogTitle>
              <DialogDescription>
                Create a new AES-256-GCM encrypted secret key for {environment}.
              </DialogDescription>
            </DialogHeader>
            <div className="dialog-form">
              <div>
                <label htmlFor="secret-key">Secret key</label>
                <Input
                  id="secret-key"
                  value={newKey}
                  onChange={(e) => setNewKey(e.target.value)}
                  placeholder="DATABASE_PASSWORD"
                />
              </div>
              <div>
                <label htmlFor="secret-value">Secret value</label>
                <Input
                  id="secret-value"
                  type="password"
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  placeholder="Enter secret payload"
                />
              </div>
              <div>
                <label htmlFor="secret-path">Path</label>
                <Input
                  id="secret-path"
                  value={newPath}
                  onChange={(e) => setNewPath(e.target.value)}
                  placeholder="/backend"
                />
              </div>
              <div>
                <label htmlFor="secret-rotation">Rotation Policy</label>
                <select
                  id="secret-rotation"
                  value={newRotation}
                  onChange={(e) => setNewRotation(e.target.value)}
                  className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 px-3 text-xs"
                >
                  <option value="None">No automatic rotation</option>
                  <option value="14 days">14 days</option>
                  <option value="30 days">30 days</option>
                  <option value="60 days">60 days</option>
                </select>
              </div>
              <Button type="button" onClick={handleAddSecret} className="mt-2 h-9">
                Encrypt and save
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </section>

      <section className="secret-toolbar">
        <Tabs value={environment} onValueChange={setEnvironment}>
          <TabsList className="h-9 bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="development" className="text-xs data-[state=active]:bg-white data-[state=active]:text-black font-medium">Development</TabsTrigger>
            <TabsTrigger value="staging" className="text-xs data-[state=active]:bg-white data-[state=active]:text-black font-medium">Staging</TabsTrigger>
            <TabsTrigger value="production" className="text-xs data-[state=active]:bg-white data-[state=active]:text-black font-medium">Production</TabsTrigger>
          </TabsList>
        </Tabs>

        <div className="searchbox">
          <Search size={14} aria-hidden="true" />
          <input
            id="search-secrets"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search secrets..."
          />
        </div>
      </section>

      <section className="panel secret-table" aria-label="Secrets list">
        <div className="table-head">
          <span>KEY</span>
          <span>VALUE</span>
          <span>PATH</span>
          <span>UPDATED</span>
          <span className="sr-only">Actions</span>
        </div>

        {filteredSecrets.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">
              <SearchX size={18} />
            </div>
            <div className="empty-state-content">
              <h3>No secrets in {environment}</h3>
              <p>Add a secret to this environment to get started.</p>
              <Button size="sm" onClick={() => setOpenAddSecret(true)}>
                <Plus size={14} className="mr-1.5" />
                Add secret
              </Button>
            </div>
          </div>
        ) : (
          filteredSecrets.map((s: Secret, idx: number) => {
            const isRevealed = revealed.includes(s.key);
            return (
              <motion.div
                className="secret-row"
                key={s.id}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.15, delay: idx * 0.03 }}
              >
                <div>
                  <KeyRound size={14} className="text-zinc-400" />
                  <strong className="font-mono text-xs text-zinc-100">{s.key}</strong>
                  {s.rotation && (
                    <span title={`Rotates every ${s.rotation}`} className="text-zinc-500">
                      <RotateCw size={11} />
                    </span>
                  )}
                </div>
                <code>{isRevealed ? s.value : "••••••••••••••••••••"}</code>
                <span className="path">{s.path}</span>
                <span className="updated">
                  <strong>{s.updated}</strong>
                  <small>{s.actor} · v{s.version}</small>
                </span>
                <div className="row-actions">
                  <button type="button" onClick={() => toggleReveal(s.key)} title={isRevealed ? "Hide value" : "Reveal value"}>
                    {isRevealed ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                  <button type="button" onClick={() => copyToClipboard(s.value, s.key)} title="Copy secret">
                    <Copy size={15} />
                  </button>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <button type="button" title="More options">
                        <MoreHorizontal size={15} />
                      </button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="bg-zinc-950 border-zinc-800 text-zinc-100">
                      <DropdownMenuItem onClick={() => setSelectedSecretForVersions(s)} className="hover:bg-zinc-900 cursor-pointer">
                        Version history (v{s.version})
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleRotateSecret(s.id)} className="hover:bg-zinc-900 cursor-pointer">
                        Rotate now
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleDeleteSecret(s.id, s.key)} className="text-red-400 hover:bg-zinc-900 cursor-pointer">
                        Delete secret
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </motion.div>
            );
          })
        )}

        <div className="table-foot">
          {filteredSecrets.length} secrets in {environment}
          <span>AES-256-GCM Envelope Encrypted</span>
        </div>
      </section>
    </>
  );
}

function DynamicSecretsPage({ logEvent }: { logEvent: LogEventFn }) {
  const [leases, setLeases] = useState<DynamicLease[]>([
    { id: "lse-1", provider: "PostgreSQL checkout-db", username: "aegis_dyn_usr_881", secret: "p_tmp_89124kaa", expiresIn: "54m 12s", status: "Active" },
    { id: "lse-2", provider: "AWS IAM deployer-role", username: "AKIA3910KAA912", secret: "a8912Mkaa912Lz81P912", expiresIn: "11m 40s", status: "Active" },
  ]);

  const [openGenerate, setOpenGenerate] = useState(false);
  const [provider, setProvider] = useState("PostgreSQL checkout-db");

  const handleGenerateLease = () => {
    const newLease: DynamicLease = {
      id: generateId("lse"),
      provider,
      username: generateToken("aegis_dyn"),
      secret: generateToken("tmp_pass"),
      expiresIn: "60m 00s",
      status: "Active",
    };
    setLeases([newLease, ...leases]);
    setOpenGenerate(false);
    toast.success(`Generated dynamic credentials for ${provider}`);
    logEvent("dynamic.lease.create", provider);
  };

  const handleRevokeLease = (id: string) => {
    setLeases(prev => prev.map(l => l.id === id ? { ...l, status: "Revoked" } : l));
    toast.success("Dynamic lease revoked early");
    logEvent("dynamic.lease.revoke", id);
  };

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>Dynamic Secrets</h1>
          <p>Issue short-lived, just-in-time database and cloud credentials on demand.</p>
        </div>
        <Button size="sm" onClick={() => setOpenGenerate(true)}>
          <Zap size={15} className="mr-1.5" />
          Generate Credential
        </Button>
      </section>

      <section className="panel p-5 mb-5">
        <h2 className="text-sm font-semibold text-white mb-3">Active Dynamic Leases</h2>
        <div className="space-y-3">
          {leases.map((lease) => (
            <div key={lease.id} className="flex items-center justify-between p-3 rounded-lg border border-zinc-800 bg-zinc-900/60">
              <div>
                <div className="flex items-center gap-2">
                  <strong className="text-xs text-white">{lease.provider}</strong>
                  <Badge variant="outline" className={lease.status === "Active" ? "border-emerald-800 text-emerald-400" : "border-zinc-700 text-zinc-500"}>
                    {lease.status}
                  </Badge>
                </div>
                <div className="flex items-center gap-3 text-xs text-zinc-400 font-mono mt-1">
                  <span>User: {lease.username}</span>
                  <span>Pass: {lease.secret}</span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-zinc-400">TTL: {lease.expiresIn}</span>
                {lease.status === "Active" && (
                  <Button size="xs" variant="destructive" onClick={() => handleRevokeLease(lease.id)}>
                    Revoke Lease
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      <Dialog open={openGenerate} onOpenChange={setOpenGenerate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate Ephemeral Credential</DialogTitle>
            <DialogDescription>
              Select a target database or provider engine to request short-lived credentials.
            </DialogDescription>
          </DialogHeader>
          <div className="dialog-form">
            <div>
              <label>Target Provider</label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 text-zinc-100 px-3 text-xs"
              >
                <option value="PostgreSQL checkout-db">PostgreSQL · checkout-db</option>
                <option value="AWS IAM deployer-role">AWS IAM · deployer-role</option>
                <option value="MongoDB analytics-db">MongoDB · analytics-db</option>
              </select>
            </div>
            <Button onClick={handleGenerateLease}>Issue Ephemeral Key</Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function RotationsPage({ secrets, handleRotateSecret }: { secrets: Secret[]; handleRotateSecret: (id: string) => void }) {
  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>Secret Rotations</h1>
          <p>Automatic background credential re-wrapping and schedule configuration.</p>
        </div>
        <Button size="sm" onClick={() => toast.info("New rotation schedule flow")}>
          <Plus size={15} className="mr-1.5" />
          Add Schedule
        </Button>
      </section>

      <section className="panel p-5">
        <h2 className="text-sm font-semibold text-white mb-3">Managed Secret Schedules</h2>
        <div className="space-y-3">
          {secrets.map((sec) => (
            <div key={sec.id} className="flex items-center justify-between p-3 rounded-lg border border-zinc-800 bg-zinc-900/60">
              <div>
                <strong className="text-xs text-white font-mono">{sec.key}</strong>
                <p className="text-xs text-zinc-400 mt-0.5">Policy: {sec.rotation || "Manual only"} · Environment: {sec.environment}</p>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-zinc-500">v{sec.version} · {sec.updated}</span>
                <Button size="xs" variant="outline" onClick={() => handleRotateSecret(sec.id)}>
                  <RotateCw size={12} className="mr-1" />
                  Rotate Now
                </Button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

function SecretScanningPage({ logEvent }: { logEvent: LogEventFn }) {
  const [code, setCode] = useState(`// Example code with potential leak\nconst STRIPE_KEY = "sk_test_mock_stripe_key_902Lz81P";\nconst AWS_SECRET = "AKIA3910KAA912";`);
  const [results, setResults] = useState<ScanResult[]>([]);

  const handleRunScan = () => {
    const found: ScanResult[] = [];
    if (code.includes("sk_test_")) {
      found.push({
        rule: "Stripe Secret Key Detected",
        file: "src/config/payments.ts",
        line: 12,
        preview: 'const STRIPE_KEY = "sk_test_••••••••7Xk";',
        fingerprint: "sha256:8f92a104...",
        severity: "Critical",
      });
    }
    if (code.includes("AKIA")) {
      found.push({
        rule: "AWS Access Key ID",
        file: "src/config.ts",
        line: 3,
        preview: 'const AWS_SECRET = "AKIA••••••••912";',
        fingerprint: "sha256:1a09z71...",
        severity: "High",
      });
    }
    setResults(found);
    if (found.length > 0) {
      toast.error(`Detected ${found.length} exposed secret leaks!`);
      logEvent("scanner.detect", `${found.length} leaks`, "Warning");
    } else {
      toast.success("No hardcoded secrets detected!");
      logEvent("scanner.clean", "Clean scan");
    }
  };

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>Secret Leak Scanner</h1>
          <p>Real-time detection for hardcoded API keys, RSA private keys, and cloud tokens.</p>
        </div>
      </section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <section className="panel p-4">
          <h2 className="text-sm font-semibold text-white mb-2">Scan Code Payload</h2>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            rows={8}
            className="w-full rounded-md border border-zinc-800 bg-zinc-950 text-zinc-100 p-3 font-mono text-xs outline-none"
            placeholder="Paste code or config snippet here to scan for leaks..."
          />
          <Button size="sm" onClick={handleRunScan} className="mt-3">
            <Play size={13} className="mr-1.5" />
            Run Scanner
          </Button>
        </section>

        <section className="panel p-4">
          <h2 className="text-sm font-semibold text-white mb-2">Scan Results</h2>
          {results.length === 0 ? (
            <p className="text-xs text-zinc-500">Run scanner to detect exposed credentials.</p>
          ) : (
            <div className="space-y-3">
              {results.map((r, i) => (
                <div key={i} className="p-3 rounded-lg border border-red-900/60 bg-red-950/30">
                  <div className="flex items-center justify-between">
                    <strong className="text-xs text-red-300">{r.rule}</strong>
                    <Badge variant="destructive">{r.severity}</Badge>
                  </div>
                  <pre className="text-[11px] text-zinc-400 font-mono mt-1">{r.preview}</pre>
                  <span className="text-[10px] text-zinc-500 block mt-1">Fingerprint: {r.fingerprint}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function IntegrationsPage({ logEvent }: { logEvent: LogEventFn }) {
  const [integrations, setIntegrations] = useState([
    { name: "GitHub Actions", target: "acme/payments-api", status: "Healthy", lastSync: "10m ago" },
    { name: "Vercel Production", target: "payments-dashboard", status: "Healthy", lastSync: "25m ago" },
    { name: "AWS Secrets Manager", target: "us-east-1 / production", status: "Healthy", lastSync: "1h ago" },
    { name: "Kubernetes Operator", target: "prod-cluster / payments", status: "Healthy", lastSync: "3h ago" },
  ]);

  const handleSync = (name: string) => {
    setIntegrations(prev => prev.map(i => i.name === name ? { ...i, lastSync: "Just now", status: "Healthy" } : i));
    toast.success(`Sync triggered for ${name}`);
    logEvent("integration.sync", name);
  };

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>Integrations & Connectors</h1>
          <p>Automated secret delivery to CI/CD pipelines, Kubernetes, and Cloud providers.</p>
        </div>
      </section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {integrations.map((item) => (
          <div key={item.name} className="panel p-4 flex items-center justify-between">
            <div>
              <strong className="text-xs text-white">{item.name}</strong>
              <p className="text-xs text-zinc-400">{item.target}</p>
              <span className="text-[11px] text-zinc-500">Last sync: {item.lastSync}</span>
            </div>
            <Button size="xs" variant="outline" onClick={() => handleSync(item.name)}>
              <RefreshCw size={12} className="mr-1" />
              Sync Now
            </Button>
          </div>
        ))}
      </div>
    </>
  );
}

function CertificatesPage({ certificates, setCertificates, logEvent }: CertificatesPageProps) {
  const [openIssue, setOpenIssue] = useState(false);
  const [cn, setCn] = useState("");
  const [san, setSan] = useState("");

  const handleIssueCert = () => {
    if (!cn.trim()) return toast.error("Common Name is required");
    const certId = generateId("cert");
    const created: Certificate = {
      id: certId,
      commonName: cn.trim(),
      issuer: "AegisVault Root CA",
      san: san ? san.split(",").map(s => s.trim()) : [cn.trim()],
      daysLeft: 90,
      autoRenew: true,
      status: "Active",
    };
    setCertificates([created, ...certificates]);
    setCn("");
    setSan("");
    setOpenIssue(false);
    toast.success(`Certificate issued for ${created.commonName}`);
    logEvent("pki.issue", created.commonName);
  };

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>PKI & Certificate Authority</h1>
          <p>Issue X.509 certificates, operate Root/Intermediate CAs, and automated renewals.</p>
        </div>
        <Button size="sm" onClick={() => setOpenIssue(true)}>
          <Plus size={15} className="mr-1.5" />
          Issue Certificate
        </Button>
      </section>

      <section className="panel p-5">
        <h2 className="text-sm font-semibold text-white mb-3">Active Certificates</h2>
        <div className="space-y-3">
          {certificates.map((c: Certificate) => (
            <div key={c.id} className="flex items-center justify-between p-3 rounded-lg border border-zinc-800 bg-zinc-900/60">
              <div>
                <strong className="text-xs text-white font-mono">{c.commonName}</strong>
                <p className="text-xs text-zinc-400">Issuer: {c.issuer} · SANs: {c.san.join(", ")}</p>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-zinc-400">{c.daysLeft} days left</span>
                <Badge variant="outline" className={c.status === "Active" ? "border-emerald-800 text-emerald-400" : "border-amber-800 text-amber-400"}>
                  {c.status}
                </Badge>
              </div>
            </div>
          ))}
        </div>
      </section>

      <Dialog open={openIssue} onOpenChange={setOpenIssue}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Issue X.509 Leaf Certificate</DialogTitle>
            <DialogDescription>
              Generate a signed X.509 certificate with Subject Alternative Names (SAN).
            </DialogDescription>
          </DialogHeader>
          <div className="dialog-form">
            <div>
              <label>Common Name (CN)</label>
              <Input value={cn} onChange={(e) => setCn(e.target.value)} placeholder="app.prod.acme.dev" />
            </div>
            <div>
              <label>SAN DNS (Comma separated)</label>
              <Input value={san} onChange={(e) => setSan(e.target.value)} placeholder="app.prod.acme.dev, app.internal" />
            </div>
            <Button onClick={handleIssueCert}>Generate & Sign Certificate</Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function KMSPage({ kmsKeys, logEvent }: KMSPageProps) {
  const [plaintext, setPlaintext] = useState("Confidential Payload 2026");
  const [ciphertext, setCiphertext] = useState("");

  const handleEncrypt = () => {
    const b64 = typeof window !== "undefined" ? btoa(encodeURIComponent(plaintext)) : "cGGF5bG9hZAE";
    const fakeCipher = `aegis_kms_v1:aes256gcm:${b64}:${generateToken("tag")}`;
    setCiphertext(fakeCipher);
    toast.success("Payload encrypted with KMS Master Key");
    logEvent("kms.encrypt", "payments-master");
  };

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>Key Management System (KMS)</h1>
          <p>Envelope encryption, asymmetric key signing, and auditable cryptographic keys.</p>
        </div>
      </section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <section className="panel p-4">
          <h2 className="text-sm font-semibold text-white mb-2">Cryptographic Sandbox</h2>
          <Input value={plaintext} onChange={(e) => setPlaintext(e.target.value)} placeholder="Input text to encrypt..." />
          <Button size="sm" onClick={handleEncrypt} className="mt-3">
            <Lock size={13} className="mr-1.5" />
            Encrypt Payload
          </Button>

          {ciphertext && (
            <div className="mt-4">
              <span className="text-[11px] text-zinc-400 block mb-1">Ciphertext Output:</span>
              <pre className="text-[11px] text-emerald-400 font-mono bg-zinc-950 p-2 rounded border border-zinc-800 break-all">{ciphertext}</pre>
            </div>
          )}
        </section>

        <section className="panel p-4">
          <h2 className="text-sm font-semibold text-white mb-3">Managed KMS Keys</h2>
          <div className="space-y-3">
            {kmsKeys.map((k: KMSKey) => (
              <div key={k.id} className="p-3 rounded-lg border border-zinc-800 bg-zinc-900/60 flex items-center justify-between">
                <div>
                  <strong className="text-xs text-white">{k.name}</strong>
                  <p className="text-xs text-zinc-400">{k.algorithm} · {k.purpose}</p>
                </div>
                <Badge variant="outline" className="border-emerald-800 text-emerald-400">{k.status}</Badge>
              </div>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}

function AccessPage({ requests, setRequests, logEvent }: AccessPageProps) {
  const handleApprove = (id: string, requester: string) => {
    setRequests((prev) => prev.map(r => r.id === id ? { ...r, status: "Approved" } : r));
    toast.success(`Approved access request for ${requester}`);
    logEvent("access.approve", requester);
  };

  const handleReject = (id: string, requester: string) => {
    setRequests((prev) => prev.map(r => r.id === id ? { ...r, status: "Rejected" } : r));
    toast.error(`Rejected access request for ${requester}`);
    logEvent("access.reject", requester, "Warning");
  };

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>Privileged Access (PAM)</h1>
          <p>Time-bound, just-in-time access workflows with multi-party approval.</p>
        </div>
      </section>

      <section className="panel p-5">
        <h2 className="text-sm font-semibold text-white mb-3">Access Requests</h2>
        <div className="space-y-3">
          {requests.map((r: AccessRequest) => (
            <div key={r.id} className="p-3 rounded-lg border border-zinc-800 bg-zinc-900/60 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <strong className="text-xs text-white">{r.requester}</strong>
                  <Badge variant="outline" className={r.status === "Approved" ? "border-emerald-800 text-emerald-400" : r.status === "Pending" ? "border-amber-800 text-amber-400" : "border-red-800 text-red-400"}>
                    {r.status}
                  </Badge>
                </div>
                <p className="text-xs text-zinc-300 mt-1">{r.resource} ({r.duration})</p>
                <span className="text-[11px] text-zinc-500">Reason: {r.reason}</span>
              </div>
              {r.status === "Pending" && (
                <div className="flex items-center gap-2">
                  <Button size="xs" onClick={() => handleApprove(r.id, r.requester)}>Approve</Button>
                  <Button size="xs" variant="destructive" onClick={() => handleReject(r.id, r.requester)}>Deny</Button>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

function AuditLogsPage({ auditLogs }: { auditLogs: AuditLog[] }) {
  const [filter, setFilter] = useState("");

  const filteredLogs = useMemo(() => {
    return auditLogs.filter(l => `${l.action} ${l.actor} ${l.resource}`.toLowerCase().includes(filter.toLowerCase()));
  }, [auditLogs, filter]);

  const handleExportLogs = () => {
    const csvContent = "data:text/csv;charset=utf-8," + ["Action,Actor,Resource,Status,Timestamp,IP", ...auditLogs.map(l => `${l.action},${l.actor},${l.resource},${l.status},${l.timestamp},${l.ip}`)].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "aegisvault_audit_logs.csv");
    document.body.appendChild(link);
    link.click();
    toast.success("Audit trail exported to CSV");
  };

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>Audit Logs</h1>
          <p>Immutable event log of every secret access, key usage, and system action.</p>
        </div>
        <Button size="sm" variant="outline" onClick={handleExportLogs}>
          <Download size={14} className="mr-1.5" />
          Export CSV
        </Button>
      </section>

      <div className="mb-4">
        <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter logs by action, actor, or resource..." className="max-w-md" />
      </div>

      <section className="panel overflow-hidden">
        <div className="table-head">
          <span>ACTION</span>
          <span>ACTOR</span>
          <span>RESOURCE</span>
          <span>STATUS</span>
          <span>TIME</span>
        </div>
        {filteredLogs.map((log) => (
          <div key={log.id} className="secret-row">
            <span className="font-mono text-xs text-white">{log.action}</span>
            <span className="text-xs text-zinc-300">{log.actor}</span>
            <span className="path">{log.resource}</span>
            <Badge variant="outline" className={log.status === "Success" ? "border-emerald-800 text-emerald-400" : "border-amber-800 text-amber-400"}>
              {log.status}
            </Badge>
            <span className="text-xs text-zinc-500">{log.timestamp}</span>
          </div>
        ))}
      </section>
    </>
  );
}
