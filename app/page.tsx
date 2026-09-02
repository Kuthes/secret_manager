"use client";

import { useMemo, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  AlertTriangle,
  Boxes,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  Copy,
  Database,
  Eye,
  EyeOff,
  FileKey2,
  Fingerprint,
  GitBranch,
  History,
  KeyRound,
  LayoutDashboard,
  MoreHorizontal,
  Network,
  Plus,
  RotateCw,
  Search,
  SearchX,
  Settings,
  ShieldCheck,
  Terminal,
  Users,
  Vault,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
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

interface Secret {
  key: string;
  value: string;
  path: string;
  updated: string;
  actor: string;
  version: number;
  rotation?: string;
}

const seedSecrets: Secret[] = [
  {
    key: "DATABASE_URL",
    value: "postgresql://aegis:demo@postgres:5432/app",
    path: "/backend",
    updated: "8 min ago",
    actor: "Maya Chen",
    version: 7,
    rotation: "30 days",
  },
  {
    key: "STRIPE_SECRET_KEY",
    value: "sk_live_51Nq••••••••7Xk",
    path: "/payments",
    updated: "42 min ago",
    actor: "Rotation bot",
    version: 12,
    rotation: "14 days",
  },
  {
    key: "REDIS_URL",
    value: "redis://cache:6379/0",
    path: "/backend",
    updated: "Yesterday",
    actor: "Noah Williams",
    version: 3,
  },
  {
    key: "JWT_SIGNING_KEY",
    value: "aegis_5tQ8••••••••wD2",
    path: "/auth",
    updated: "2 days ago",
    actor: "Maya Chen",
    version: 4,
    rotation: "60 days",
  },
  {
    key: "OPENAI_API_KEY",
    value: "sk-proj-xJ2••••••••9Np",
    path: "/ai",
    updated: "3 days ago",
    actor: "Noah Williams",
    version: 2,
  },
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

const overviewStats = [
  { label: "Active secrets", value: "128", detail: "+6 this week", icon: Vault },
  { label: "Certificates", value: "24", detail: "3 renew soon", icon: ShieldCheck },
  { label: "Healthy syncs", value: "8/9", detail: "1 needs attention", icon: Network },
  { label: "Access requests", value: "2", detail: "Awaiting review", icon: Users },
];

export default function Home() {
  const [section, setSection] = useState("Overview");
  const [environment, setEnvironment] = useState("production");
  const [query, setQuery] = useState("");
  const [revealed, setRevealed] = useState<string[]>([]);
  const [secrets, setSecrets] = useState<Secret[]>(seedSecrets);
  const [open, setOpen] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");

  const filtered = useMemo(
    () =>
      secrets.filter((s) =>
        `${s.key} ${s.path}`.toLowerCase().includes(query.toLowerCase())
      ),
    [query, secrets]
  );

  const copyToClipboard = async (val: string) => {
    await navigator.clipboard?.writeText(val);
    toast.success("Secret copied to clipboard");
  };

  const toggleReveal = (key: string) => {
    setRevealed((prev) =>
      prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]
    );
  };

  const handleAddSecret = () => {
    if (!newKey.trim() || !newValue.trim()) {
      return toast.error("Key and value are required");
    }
    setSecrets([
      {
        key: newKey.trim().toUpperCase(),
        value: newValue,
        path: "/",
        updated: "Just now",
        actor: "Saurabh Kuthe",
        version: 1,
      },
      ...secrets,
    ]);
    setNewKey("");
    setNewValue("");
    setOpen(false);
    toast.success("Secret encrypted and saved");
  };

  return (
    <div className="app-shell">
      <Toaster position="bottom-right" richColors />
      
      {/* Minimalist Sidebar */}
      <aside className="sidebar" aria-label="Sidebar Navigation">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={16} />
          </div>
          <span>AegisVault</span>
          <span className="version">OSS</span>
        </div>

        <button
          type="button"
          className="org-switcher"
          aria-label="Switch organization: Acme Cloud"
        >
          <div className="org-avatar" aria-hidden="true">AC</div>
          <div>
            <strong>Acme Cloud</strong>
            <span>Organization</span>
          </div>
          <ChevronDown size={14} aria-hidden="true" />
        </button>

        <nav className="nav-list" aria-label="Main menu">
          <p>Workspace</p>
          {navigationItems.slice(0, 6).map(([label, Icon]) => (
            <button
              type="button"
              key={label}
              className={section === label ? "active" : ""}
              onClick={() => setSection(label)}
              aria-current={section === label ? "page" : undefined}
            >
              <Icon size={15} aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}

          <p>Security</p>
          {navigationItems.slice(6).map(([label, Icon]) => (
            <button
              type="button"
              key={label}
              className={section === label ? "active" : ""}
              onClick={() => setSection(label)}
              aria-current={section === label ? "page" : undefined}
            >
              <Icon size={15} aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <button type="button">
            <CircleHelp size={15} aria-hidden="true" />
            <span>Documentation</span>
          </button>
          <button type="button">
            <Settings size={15} aria-hidden="true" />
            <span>Settings</span>
          </button>
          <div className="user">
            <div className="avatar" aria-hidden="true">SK</div>
            <div>
              <strong>Saurabh Kuthe</strong>
              <span>Owner</span>
            </div>
            <button
              type="button"
              className="bg-transparent border-0 p-1 text-muted-foreground hover:text-foreground cursor-pointer"
              aria-label="User account actions"
            >
              <MoreHorizontal size={14} aria-hidden="true" />
            </button>
          </div>
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
            <Badge variant="outline" className="text-xs font-normal">
              Production
            </Badge>
          </div>

          <div className="top-actions">
            <button
              type="button"
              className="command"
              aria-label="Open command palette"
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
          {section === "Overview" ? (
            <Overview setSection={setSection} />
          ) : section === "Secrets" ? (
            <>
              <section className="page-heading compact">
                <div>
                  <p className="eyebrow">Secret Management</p>
                  <h1>Secrets</h1>
                  <p>Encrypted environment variables and key-value credentials.</p>
                </div>

                <Dialog open={open} onOpenChange={setOpen}>
                  <DialogTrigger asChild>
                    <Button size="sm" className="h-9 gap-1.5">
                      <Plus size={15} aria-hidden="true" />
                      Add secret
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Add encrypted secret</DialogTitle>
                    </DialogHeader>
                    <div className="dialog-form">
                      <div>
                        <label htmlFor="secret-key">Secret key</label>
                        <Input
                          id="secret-key"
                          value={newKey}
                          onChange={(e) => setNewKey(e.target.value)}
                          placeholder="API_KEY"
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
                        <Input id="secret-path" value="/" readOnly />
                      </div>
                      <Button
                        type="button"
                        onClick={handleAddSecret}
                        className="mt-2 h-9"
                      >
                        Encrypt and save
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </section>

              <section className="secret-toolbar">
                <Tabs value={environment} onValueChange={setEnvironment}>
                  <TabsList className="h-9">
                    <TabsTrigger value="development" className="text-xs">Development</TabsTrigger>
                    <TabsTrigger value="staging" className="text-xs">Staging</TabsTrigger>
                    <TabsTrigger value="production" className="text-xs">Production</TabsTrigger>
                  </TabsList>
                </Tabs>

                <div className="searchbox">
                  <Search size={14} aria-hidden="true" />
                  <input
                    id="search-secrets"
                    aria-label="Filter secrets by key or path"
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

                {secrets.length === 0 ? (
                  <div className="empty-state" role="status" aria-live="polite">
                    <div className="empty-state-icon" aria-hidden="true">
                      <Vault size={18} />
                    </div>
                    <div className="empty-state-content">
                      <h3>No secrets yet</h3>
                      <p>Add your first secret to get started.</p>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => setOpen(true)}
                        className="h-8 text-xs"
                      >
                        <Plus size={14} className="me-1.5" aria-hidden="true" />
                        Add secret
                      </Button>
                    </div>
                  </div>
                ) : filtered.length === 0 ? (
                  <div className="empty-state" role="status" aria-live="polite">
                    <div className="empty-state-icon" aria-hidden="true">
                      <SearchX size={18} />
                    </div>
                    <div className="empty-state-content">
                      <h3>No matching secrets found</h3>
                      <p>Try adjusting your search or clearing the current filter.</p>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => setQuery("")}
                        className="h-8 text-xs"
                      >
                        Clear filter
                      </Button>
                    </div>
                  </div>
                ) : (
                  filtered.map((s) => {
                    const isRevealed = revealed.includes(s.key);
                    return (
                      <div className="secret-row" key={s.key}>
                        <div>
                          <KeyRound size={14} className="text-muted-foreground" aria-hidden="true" />
                          <strong className="font-mono text-xs">{s.key}</strong>
                          {s.rotation && (
                            <span
                              title={`Rotates every ${s.rotation}`}
                              aria-label={`Rotates every ${s.rotation}`}
                              className="text-muted-foreground"
                            >
                              <RotateCw size={11} aria-hidden="true" />
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
                          <button
                            type="button"
                            onClick={() => toggleReveal(s.key)}
                            aria-label={isRevealed ? `Hide ${s.key} value` : `Reveal ${s.key} value`}
                            aria-pressed={isRevealed}
                            title={isRevealed ? "Hide value" : "Reveal value"}
                          >
                            {isRevealed ? (
                              <EyeOff size={15} aria-hidden="true" />
                            ) : (
                              <Eye size={15} aria-hidden="true" />
                            )}
                          </button>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(s.value)}
                            aria-label={`Copy ${s.key} to clipboard`}
                            title="Copy secret"
                          >
                            <Copy size={15} aria-hidden="true" />
                          </button>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <button
                                type="button"
                                aria-label={`More options for ${s.key}`}
                                title="More options"
                              >
                                <MoreHorizontal size={15} aria-hidden="true" />
                              </button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem
                                onClick={() => toast.info(`Version history for ${s.key}`)}
                              >
                                Version history
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() => toast.success(`Rotation triggered for ${s.key}`)}
                              >
                                Rotate now
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </div>
                    );
                  })
                )}

                <div className="table-foot">
                  {filtered.length} secrets in {environment}
                  <span>Encrypted with AES-256-GCM</span>
                </div>
              </section>
            </>
          ) : (
            <FeaturePage section={section} onNavigate={setSection} />
          )}
        </div>
      </main>
    </div>
  );
}

const recentEvents: readonly [string, string, string, LucideIcon][] = [
  ["Secret rotated", "STRIPE_SECRET_KEY rotated automatically", "8m ago", RotateCw],
  ["Certificate issued", "api.prod.acme.dev · 90-day validity", "1h ago", FileKey2],
  ["Access granted", "Noah Williams · expires in 55m", "3h ago", Fingerprint],
  ["Sync failed", "Vercel Production · token expired", "5h ago", AlertTriangle],
];

const quickIntegrations: readonly [string, string, string, LucideIcon][] = [
  ["Universal Agent", "12 active workloads", "Active", Terminal],
  ["Kubernetes Sync", "prod-cluster / payments", "Healthy", Boxes],
  ["GitHub Actions", "acme/payments-api", "Healthy", GitBranch],
  ["AWS Secrets Manager", "us-east-1 / production", "Healthy", Database],
];

function Overview({ setSection }: { setSection: (s: string) => void }) {
  return (
    <>
      <section className="page-heading">
        <div>
          <p className="eyebrow">Project Overview</p>
          <h1>Good morning, Saurabh</h1>
          <p>Security control plane status and active workloads.</p>
        </div>
        <div className="heading-actions">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-9 gap-1.5"
            onClick={() => setSection("Audit logs")}
          >
            <History size={14} aria-hidden="true" />
            Audit log
          </Button>
          <Button
            type="button"
            size="sm"
            className="h-9 gap-1.5"
            onClick={() => setSection("Secrets")}
          >
            <Plus size={14} aria-hidden="true" />
            Add secret
          </Button>
        </div>
      </section>

      {/* Stats Cards */}
      <section className="stats" aria-label="Summary metrics">
        {overviewStats.map(({ label, value, detail, icon: Icon }) => (
          <article key={label}>
            <div className="stat-header">
              <span>{label}</span>
              <Icon size={16} className="stat-icon" aria-hidden="true" />
            </div>
            <strong>{value}</strong>
            <small>{detail}</small>
          </article>
        ))}
      </section>

      <div className="overview-grid">
        {/* Activity Feed */}
        <section className="panel activity-panel" aria-label="Recent activity">
          <div className="panel-head">
            <div>
              <h2>Recent activity</h2>
              <p>Security audit events for this project</p>
            </div>
            <button type="button" onClick={() => setSection("Audit logs")}>View all</button>
          </div>
          <div className="timeline">
            {recentEvents.map(([title, desc, time, Icon]) => (
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
        <section className="panel posture" aria-label="Security posture">
          <div className="panel-head">
            <div>
              <h2>Security posture</h2>
              <p>Configuration compliance score</p>
            </div>
            <span className="score">92%</span>
          </div>
          <div className="scorebar" role="progressbar" aria-valuenow={92} aria-valuemin={0} aria-valuemax={100}>
            <i style={{ width: "92%" }} />
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
              <X size={14} className="text-amber-500" aria-hidden="true" />
              <span>1 stale integration</span>
              <button type="button" onClick={() => setSection("Integrations")}>Resolve</button>
            </div>
          </div>
        </section>
      </div>

      {/* Quick Integrations */}
      <section className="panel quick" aria-label="Integrations and delivery">
        <div className="panel-head">
          <div>
            <h2>Integrations & delivery</h2>
            <p>Sync status across delivery targets</p>
          </div>
        </div>
        <div className="quick-grid">
          {quickIntegrations.map(([name, detail, status, Icon]) => (
            <button
              type="button"
              key={name}
              onClick={() => setSection("Integrations")}
              aria-label={`Integration: ${name}, Status: ${status}`}
            >
              <div>
                <Icon size={16} aria-hidden="true" />
              </div>
              <span>
                <strong>{name}</strong>
                <small>{detail}</small>
              </span>
              <Badge variant="outline" className="mt-2 text-xs font-normal">
                {status}
              </Badge>
            </button>
          ))}
        </div>
      </section>
    </>
  );
}

function FeaturePage({
  section,
  onNavigate,
}: {
  section: string;
  onNavigate: (s: string) => void;
}) {
  const info: Record<string, [string, string, LucideIcon, string[], string]> = {
    "Dynamic secrets": [
      "Dynamic secrets",
      "Issue short-lived database and cloud credentials on demand.",
      Clock3,
      ["PostgreSQL · checkout-db", "AWS IAM · deployer-role", "MongoDB · analytics"],
      "Create provider",
    ],
    "Secret rotations": [
      "Secret rotations",
      "Replace long-lived credentials automatically on a schedule.",
      RotateCw,
      [
        "Stripe API · every 14 days",
        "PostgreSQL · every 30 days",
        "JWT signing key · every 60 days",
      ],
      "Add rotation",
    ],
    "Secret scanning": [
      "Secret scanning",
      "Stop leaked credentials before they reach your repositories.",
      GitBranch,
      [
        "acme/payments-api · protected",
        "acme/web-checkout · protected",
        "Pre-commit hook · active",
      ],
      "Connect repository",
    ],
    Integrations: [
      "Integrations",
      "Sync protected values to your delivery platforms.",
      Boxes,
      [
        "GitHub Actions · Healthy",
        "Vercel Production · Needs attention",
        "AWS Secrets Manager · Healthy",
        "Kubernetes · Healthy",
      ],
      "Add integration",
    ],
    Certificates: [
      "Certificate management",
      "Operate private and external CAs, issuance, renewal and revocation.",
      FileKey2,
      [
        "api.prod.acme.dev · 71 days left",
        "internal-ca.acme · Root CA",
        "checkout.prod.svc · Auto-renew on",
      ],
      "Issue certificate",
    ],
    KMS: [
      "Key management",
      "Encrypt and decrypt data with managed, auditable keys.",
      KeyRound,
      [
        "payments-master · AES-256-GCM",
        "session-signing · Ed25519",
        "backup-wrapping · AES-256-GCM",
      ],
      "Create key",
    ],
    Access: [
      "Privileged access",
      "Time-bound approval for sensitive systems and production secrets.",
      Fingerprint,
      [
        "Noah Williams · Production DB · Pending",
        "Isha Patel · Kubernetes admin · Pending",
        "Maya Chen · Billing console · Active 42m",
      ],
      "New request",
    ],
    "Audit logs": [
      "Audit logs",
      "Search every secret, certificate, key and access event.",
      Activity,
      [
        "secret.read · Saurabh Kuthe · just now",
        "kms.encrypt · payments-api · 2 min ago",
        "certificate.issue · pki-agent · 1 hr ago",
      ],
      "Export logs",
    ],
  };

  const [title, desc, Icon, items, action] = info[section] || info.Integrations;

  return (
    <>
      <section className="page-heading compact">
        <div>
          <p className="eyebrow">Security Platform</p>
          <h1>{title}</h1>
          <p>{desc}</p>
        </div>
        <Button
          type="button"
          size="sm"
          className="h-9 gap-1.5"
          onClick={() => toast.success(`${action} flow opened`)}
        >
          <Plus size={15} aria-hidden="true" />
          {action}
        </Button>
      </section>

      <section className="feature-layout">
        <div className="panel feature-list" aria-label="Configured resources list">
          <div className="panel-head">
            <div>
              <h2>Configured resources</h2>
              <p>Demo workspace · operational view</p>
            </div>
            <Badge variant="outline" className="text-xs font-normal">
              {items.length} active
            </Badge>
          </div>

          {items.map((item) => {
            const isWarning = item.includes("attention") || item.includes("Pending");
            return (
              <button
                type="button"
                key={item}
                onClick={() => toast.info(item)}
                aria-label={`${item.split(" · ")[0]}: ${item.split(" · ").slice(1).join(" · ")}`}
              >
                <div className="feature-icon">
                  <Icon size={15} aria-hidden="true" />
                </div>
                <span>
                  <strong>{item.split(" · ")[0]}</strong>
                  <small>{item.split(" · ").slice(1).join(" · ")}</small>
                </span>
                <Badge
                  variant={isWarning ? "outline" : "secondary"}
                  className="text-xs font-normal"
                >
                  {item.includes("attention")
                    ? "Action needed"
                    : item.includes("Pending")
                    ? "Review"
                    : "Healthy"}
                </Badge>
                <MoreHorizontal size={14} className="text-muted-foreground" aria-hidden="true" />
              </button>
            );
          })}
        </div>

        <aside className="panel api-card" aria-label="API automation details">
          <div className="api-icon" aria-hidden="true">
            <Terminal size={16} />
          </div>
          <h2>Automate with CLI</h2>
          <p>Perform operations programmatically via the <code>av</code> CLI tool.</p>
          <pre>
            <span>$</span> av{" "}
            {section === "Certificates"
              ? "pki issue"
              : section === "KMS"
              ? "kms encrypt"
              : "secrets get"}{" "}
            \
            {"\n"}  --project payments-api \
            {"\n"}  --env production
          </pre>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="w-full mt-3 gap-1.5 text-xs h-9"
            onClick={() => toast.success("Command copied")}
          >
            <Copy size={13} aria-hidden="true" />
            Copy command
          </Button>
          <button
            type="button"
            className="text-link mt-3"
            onClick={() => onNavigate("Audit logs")}
          >
            View audit trail →
          </button>
        </aside>
      </section>
    </>
  );
}
