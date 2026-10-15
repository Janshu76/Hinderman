import { useEffect, useState } from "react"
import {
  Activity,
  ArrowUpRight,
  BookOpen,
  Check,
  ChevronDown,
  CircleHelp,
  ClipboardCheck,
  FileText,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  MessageSquareText,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserRound,
  X,
} from "lucide-react"
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { api, login, logout } from "./api.js"

const navItems = [
  { id: "chat", label: "Secure chat", icon: MessageSquareText },
  { id: "library", label: "Document library", icon: BookOpen },
  { id: "approvals", label: "Approvals", icon: ClipboardCheck },
  { id: "dashboard", label: "Security dashboard", icon: LayoutDashboard },
]

const demoUsers = [
  { id: "intern", label: "Intern · Engineering" },
  { id: "hr_officer", label: "HR officer · HR" },
  { id: "finance_manager", label: "Finance manager · Finance" },
  { id: "admin", label: "Admin · Operations" },
]

const starterPrompts = [
  "What is the CFO's salary?",
  "What are the employee leave guidelines?",
  "How does finance approve travel expenses?",
]

function cx(...classes) {
  return classes.filter(Boolean).join(" ")
}

function ErrorBanner({ children }) {
  if (!children) return null
  return (
    <div className="flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
      <ShieldAlert size={17} className="mt-0.5 shrink-0" />
      <span>{children}</span>
    </div>
  )
}

function LoginScreen({ onLogin }) {
  const [userId, setUserId] = useState("intern")
  const [password, setPassword] = useState("demo-password")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError("")
    try {
      await onLogin(userId, password)
    } catch (cause) {
      setError(cause.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login-shell">
      <div className="login-art">
        <div className="absolute inset-0 bg-grid opacity-20" />
        <div className="relative z-10 mx-auto flex h-full max-w-xl flex-col justify-between p-9 text-white sm:p-14">
          <div className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-2xl bg-white/15 ring-1 ring-white/20">
              <Shield size={23} />
            </div>
            <span className="text-lg font-semibold tracking-tight">hinderman</span>
          </div>
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-3 py-1.5 text-xs font-medium text-indigo-50">
              <Sparkles size={14} />
              AI security gateway
            </div>
            <h1 className="max-w-lg text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
              Your knowledge,
              <br />
              <span className="text-indigo-200">safely in reach.</span>
            </h1>
            <p className="mt-5 max-w-md text-sm leading-7 text-indigo-100/80">
              Ask questions across company knowledge. Every document is checked
              against your role, department, and clearance before retrieval.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-indigo-100/70">
            <LockKeyhole size={14} />
            Access-controlled retrieval · Privacy-safe audit
          </div>
        </div>
      </div>
      <div className="flex min-h-screen items-center justify-center px-6 py-12">
        <form onSubmit={submit} className="w-full max-w-sm">
          <div className="mb-9">
            <div className="mb-6 grid h-12 w-12 place-items-center rounded-2xl bg-indigo-50 text-brand md:hidden">
              <Shield size={24} />
            </div>
            <p className="text-sm font-semibold text-brand">M4 prototype</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-ink">
              Welcome back
            </h2>
            <p className="mt-2 text-sm text-muted">
              Sign in with one of the seeded demo identities.
            </p>
          </div>
          <ErrorBanner>{error}</ErrorBanner>
          <label className="field-label mt-5" htmlFor="user">
            Demo identity
          </label>
          <div className="relative mt-2">
            <UserRound size={17} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <select
              id="user"
              className="field-input appearance-none pl-10 pr-10"
              value={userId}
              onChange={(event) => setUserId(event.target.value)}
            >
              {demoUsers.map((user) => (
                <option value={user.id} key={user.id}>
                  {user.label}
                </option>
              ))}
            </select>
            <ChevronDown size={16} className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          </div>
          <label className="field-label mt-5" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            className="field-input mt-2"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
          <p className="mt-2 text-xs text-slate-400">
            Local demo default: <code>demo-password</code>
          </p>
          <button
            className="primary-button mt-7 w-full justify-center"
            type="submit"
            disabled={busy}
          >
            {busy ? "Signing in…" : "Sign in securely"}
            <ArrowUpRight size={17} />
          </button>
          <p className="mt-6 text-center text-xs leading-5 text-slate-400">
            Prototype access only. Use synthetic documents; do not enter
            production or personal data.
          </p>
        </form>
      </div>
    </main>
  )
}

function AppShell({ user, active, setActive, onLogout, children }) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="flex items-center gap-3 px-5 py-6">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 text-white shadow-lg shadow-indigo-900/20">
            <Shield size={21} />
          </div>
          <div>
            <p className="text-[15px] font-semibold tracking-tight text-white">hinderman</p>
            <p className="mt-0.5 text-[10px] font-semibold uppercase tracking-[.16em] text-slate-500">
              AI security gateway
            </p>
          </div>
        </div>
        <div className="px-4 pt-5">
          <p className="sidebar-caption">Workspace</p>
          <nav className="mt-2 space-y-1">
            {navItems.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setActive(id)}
                className={cx("nav-link", active === id && "nav-link-active")}
              >
                <Icon size={18} strokeWidth={1.8} />
                <span>{label}</span>
                {id === "approvals" && (
                  <span className="ml-auto rounded-md bg-white/10 px-1.5 py-0.5 text-[10px] text-slate-300">
                    Queue
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>
        <div className="mx-4 mt-auto mb-4 rounded-xl border border-white/[.08] bg-white/[.035] p-3.5">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
            <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,.6)]" />
            Gateway connected
          </div>
          <p className="mt-2 text-[11px] leading-5 text-slate-500">
            RAG access controls active for this session.
          </p>
        </div>
        <button
          type="button"
          onClick={onLogout}
          className="mx-4 mb-5 flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium text-slate-400 transition hover:bg-white/[.06] hover:text-white"
        >
          <LogOut size={15} />
          Sign out
        </button>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto">
        <header className="topbar">
          <div className="flex items-center gap-2 text-xs text-muted">
            <span>Workspace</span>
            <span className="text-slate-300">/</span>
            <span className="font-medium capitalize text-ink">
              {active === "dashboard" ? "Security dashboard" : active === "library" ? "Document library" : active}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden rounded-full bg-emerald-50 px-2.5 py-1 text-[11px] font-medium text-emerald-700 sm:inline-flex sm:items-center sm:gap-1.5">
              <ShieldCheck size={13} />
              Protected session
            </span>
            <span className="hidden rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[10px] font-medium text-slate-500 md:inline-flex">
              Clearance L{user.clearance}
            </span>
            <div className="flex items-center gap-2.5 border-l border-slate-200 pl-3">
              <div className="grid h-8 w-8 place-items-center rounded-full bg-indigo-100 text-xs font-semibold text-indigo-700">
                {user.display_name.split(" ").map((part) => part[0]).slice(0, 2).join("")}
              </div>
              <div className="hidden sm:block">
                <p className="text-xs font-semibold text-ink">{user.display_name}</p>
                <p className="mt-0.5 text-[10px] capitalize text-muted">
                  {user.role.replaceAll("_", " ")} · {user.department}
                </p>
              </div>
            </div>
          </div>
        </header>
        <div className="mx-auto max-w-[1440px] p-5 sm:p-7 lg:p-9">{children}</div>
      </main>
    </div>
  )
}

function PageHeading({ eyebrow, title, description, action }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div>
        {eyebrow && (
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-[.15em] text-brand">
            {eyebrow}
          </p>
        )}
        <h1 className="text-2xl font-semibold tracking-tight text-ink sm:text-[28px]">{title}</h1>
        {description && <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">{description}</p>}
      </div>
      {action}
    </div>
  )
}

function ChatPage() {
  const [query, setQuery] = useState("")
  const [result, setResult] = useState(null)
  const [documents, setDocuments] = useState({})
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api("/api/documents")
      .then(({ documents: rows }) => {
        setDocuments(Object.fromEntries(rows.map((document) => [document.doc_id, document])))
      })
      .catch((cause) => setError(cause.message))
  }, [])

  async function ask(question = query) {
    if (!question.trim()) return
    setBusy(true)
    setError("")
    setQuery(question)
    setResult(null)
    try {
      setResult(await api("/api/rag/retrieve", {
        method: "POST",
        body: JSON.stringify({ query: question.trim(), k: 4 }),
      }))
    } catch (cause) {
      setError(cause.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeading
        eyebrow="Access-controlled RAG"
        title="Ask your knowledge base"
        description="Only passages your identity is allowed to see can be retrieved. Try the same question with different demo roles."
        action={
          <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600">
            <LockKeyhole size={13} className="text-emerald-600" />
            ACL enforced
          </span>
        }
      />
      <div className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-card">
        <div className="flex items-center gap-3 border-b border-slate-100 px-5 py-4">
          <div className="grid h-9 w-9 place-items-center rounded-xl bg-indigo-50 text-brand">
            <Sparkles size={18} />
          </div>
          <div>
            <p className="text-sm font-semibold text-ink">Secure knowledge assistant</p>
            <p className="mt-0.5 text-xs text-muted">Retrieval is scoped to your access level</p>
          </div>
          <div className="ml-auto hidden items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-1 text-[10px] font-medium text-emerald-700 sm:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            Ready
          </div>
        </div>
        <div className="min-h-[330px] bg-gradient-to-b from-slate-50/70 to-white p-5 sm:p-8">
          {!result && !busy && (
            <div className="mx-auto max-w-lg py-10 text-center">
              <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-indigo-100 bg-white text-brand shadow-sm">
                <MessageSquareText size={23} />
              </div>
              <h2 className="mt-5 text-lg font-semibold text-ink">What would you like to know?</h2>
              <p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-muted">
                Ask about company guidance. The gateway checks document permissions before any passages are returned.
              </p>
              <div className="mt-6 flex flex-wrap justify-center gap-2">
                {starterPrompts.map((prompt) => (
                  <button
                    key={prompt}
                    type="button"
                    onClick={() => ask(prompt)}
                    className="rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-slate-600 transition hover:border-indigo-200 hover:bg-indigo-50/60 hover:text-indigo-700"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          )}
          {busy && (
            <div className="flex h-64 items-center justify-center gap-3 text-sm text-muted">
              <span className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-200 border-t-brand" />
              Checking access and searching approved documents…
            </div>
          )}
          {result && (
            <div className="space-y-5">
              <div className="ml-auto max-w-[85%] rounded-2xl rounded-br-md bg-brand px-4 py-3 text-sm leading-6 text-white shadow-sm">
                {query}
              </div>
              <div className="flex gap-3">
                <div className="grid h-8 w-8 shrink-0 place-items-center rounded-xl bg-indigo-50 text-brand">
                  <Sparkles size={16} />
                </div>
                <div className="min-w-0 flex-1">
                  {result.chunks.length ? (
                    <>
                      <p className="mb-3 text-sm font-medium text-ink">
                        {result.chunks.length} authorized passage{result.chunks.length === 1 ? "" : "s"} found
                      </p>
                      <div className="space-y-3">
                        {result.chunks.map((chunk, index) => (
                          <article key={`${chunk.doc_id}-${index}`} className="rounded-xl border border-slate-200 bg-white p-4">
                            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <FileText size={15} className="text-indigo-500" />
                                <span className="text-xs font-semibold text-ink">
                                  {documents[chunk.doc_id]?.title || chunk.doc_id}
                                </span>
                              </div>
                              <span className="rounded-full bg-emerald-50 px-2 py-1 text-[10px] font-medium text-emerald-700">
                                Authorized
                              </span>
                            </div>
                            <p className="text-xs leading-6 text-slate-600">{chunk.text}</p>
                          </article>
                        ))}
                      </div>
                      <p className="mt-3 text-[11px] leading-5 text-slate-400">
                        MVP retrieval preview: passages are returned from permitted documents; LLM answer generation is integrated through the gateway in a later stage.
                      </p>
                    </>
                  ) : (
                    <div className="rounded-xl border border-slate-200 bg-white p-4">
                      <p className="text-sm font-medium text-ink">No authorized passages found</p>
                      <p className="mt-1 text-xs leading-5 text-muted">
                        Try a general question, or ask your department approver for access.
                      </p>
                    </div>
                  )}
                  {result.denied_count > 0 && (
                    <div className="mt-3 flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 px-3.5 py-3 text-xs leading-5 text-amber-800">
                      <LockKeyhole size={15} className="mt-0.5 shrink-0" />
                      {result.denied_count} restricted document{result.denied_count === 1 ? "" : "s"} were excluded by access policy. The attempt was recorded without storing your question.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
          <ErrorBanner>{error}</ErrorBanner>
        </div>
        <form
          className="border-t border-slate-100 bg-white p-4 sm:p-5"
          onSubmit={(event) => {
            event.preventDefault()
            ask()
          }}
        >
          <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white p-1.5 pl-4 shadow-sm transition focus-within:border-indigo-300 focus-within:ring-4 focus-within:ring-indigo-50">
            <Search size={17} className="shrink-0 text-slate-400" />
            <input
              className="min-w-0 flex-1 border-0 bg-transparent py-2 text-sm text-ink outline-none placeholder:text-slate-400"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Ask a question about company documents…"
              maxLength={10_000}
            />
            <button className="primary-button !px-3.5 !py-2" type="submit" disabled={busy || !query.trim()}>
              Search <ArrowUpRight size={15} />
            </button>
          </div>
          <div className="mt-2.5 flex items-center justify-between px-1 text-[10px] text-slate-400">
            <span className="flex items-center gap-1.5">
            <LockKeyhole size={11} /> A keyed HMAC is logged, not your query text
            </span>
            <span>{query.length}/10,000</span>
          </div>
        </form>
      </div>
      <div className="mt-4 flex items-start gap-2 rounded-xl border border-indigo-100 bg-indigo-50/70 px-4 py-3 text-xs leading-5 text-indigo-800">
        <CircleHelp size={15} className="mt-0.5 shrink-0" />
        <span>
          Demo: search for “What is the CFO&apos;s salary?” as an intern and then as an HR officer. The restricted passage is only returned to HR.
        </span>
      </div>
      <section className="panel-card mt-5 p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[.14em] text-brand">
              Gateway report preview
            </p>
            <h2 className="mt-1.5 text-sm font-semibold text-ink">
              Original vs. masked prompt
            </h2>
          </div>
          <span className="rounded-full bg-slate-100 px-2.5 py-1 text-[10px] font-medium text-slate-500">
            Synthetic example
          </span>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Before inspection
            </p>
            <p className="text-xs leading-6 text-slate-700">
              “Please verify the employee record for [synthetic name], Aadhaar
              [synthetic number], and PAN [synthetic identifier].”
            </p>
          </div>
          <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-4">
            <p className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-700">
              <ShieldCheck size={12} /> After masking
            </p>
            <p className="text-xs leading-6 text-slate-700">
              “Please verify the employee record for{" "}
              <mark className="rounded bg-emerald-100 px-1 text-emerald-800">
                [PERSON_1]
              </mark>
              , Aadhaar{" "}
              <mark className="rounded bg-emerald-100 px-1 text-emerald-800">
                [AADHAAR_1]
              </mark>
              , and PAN{" "}
              <mark className="rounded bg-emerald-100 px-1 text-emerald-800">
                [PAN_1]
              </mark>
              .”
            </p>
          </div>
        </div>
        <p className="mt-3 text-[10px] leading-5 text-slate-400">
          Static synthetic UI example only. Live redaction values will come from
          the integrated gateway inspection report; this preview does not
          inspect or change the query above.
        </p>
      </section>
    </div>
  )
}

function LibraryPage() {
  const [documents, setDocuments] = useState([])
  const [error, setError] = useState("")
  const [filter, setFilter] = useState("")

  useEffect(() => {
    api("/api/documents")
      .then((result) => setDocuments(result.documents))
      .catch((cause) => setError(cause.message))
  }, [])

  const visible = documents.filter((document) =>
    `${document.title} ${document.department} ${document.classification}`
      .toLowerCase()
      .includes(filter.toLowerCase()),
  )
  const levels = {
    Public: "bg-emerald-50 text-emerald-700",
    Internal: "bg-sky-50 text-sky-700",
    Confidential: "bg-amber-50 text-amber-700",
    Restricted: "bg-rose-50 text-rose-700",
  }

  return (
    <>
      <PageHeading
        eyebrow="Permission-filtered"
        title="Document library"
        description="This list is generated from the same ACL-filtered document store used by retrieval. Restricted documents are not exposed to unauthorized roles."
        action={
          <div className="inline-flex items-center gap-2 rounded-full bg-emerald-50 px-3 py-1.5 text-xs font-medium text-emerald-700">
            <ShieldCheck size={14} /> {documents.length} documents available
          </div>
        }
      />
      <ErrorBanner>{error}</ErrorBanner>
      <div className="mb-4 flex max-w-sm items-center gap-2 rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 shadow-sm">
        <Search size={16} className="text-slate-400" />
        <input
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          className="w-full bg-transparent text-sm outline-none placeholder:text-slate-400"
          placeholder="Search accessible documents"
        />
      </div>
      {visible.length ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {visible.map((document) => (
            <article key={document.doc_id} className="panel-card group p-5 transition hover:-translate-y-0.5 hover:shadow-lg">
              <div className="flex items-start justify-between">
                <div className="grid h-10 w-10 place-items-center rounded-xl bg-indigo-50 text-brand">
                  <FileText size={18} />
                </div>
                <span className={cx("rounded-full px-2.5 py-1 text-[10px] font-semibold", levels[document.classification] || "bg-slate-100 text-slate-600")}>
                  {document.classification}
                </span>
              </div>
              <h2 className="mt-4 text-sm font-semibold text-ink">{document.title}</h2>
              <div className="mt-2 flex items-center justify-between text-xs text-muted">
                <span>{document.department}</span>
                <span className="font-mono text-[10px] text-slate-400">{document.doc_id}</span>
              </div>
              <div className="mt-4 flex items-center gap-1.5 border-t border-slate-100 pt-3 text-[11px] font-medium text-emerald-700">
                <ShieldCheck size={13} /> Available to your role
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="panel-card py-16 text-center text-sm text-muted">No matching documents in your permitted library.</div>
      )}
      <p className="mt-5 text-center text-[11px] text-slate-400">
        Synthetic demo corpus · 18 seeded documents across 5 access groups
      </p>
    </>
  )
}

function MetricCard({ label, value, note, icon: Icon, tone = "indigo" }) {
  const toneStyles = {
    indigo: "bg-indigo-50 text-brand",
    rose: "bg-rose-50 text-rose-600",
    amber: "bg-amber-50 text-amber-600",
    emerald: "bg-emerald-50 text-emerald-600",
  }
  return (
    <div className="panel-card p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-muted">{label}</p>
          <p className="mt-3 text-3xl font-semibold tracking-tight text-ink">{value}</p>
        </div>
        <div className={cx("grid h-10 w-10 place-items-center rounded-xl", toneStyles[tone])}>
          <Icon size={19} />
        </div>
      </div>
      <p className="mt-3 text-[11px] text-slate-400">{note}</p>
    </div>
  )
}

function DashboardPage() {
  const [metrics, setMetrics] = useState(null)
  const [error, setError] = useState("")

  useEffect(() => {
    api("/api/metrics")
      .then(setMetrics)
      .catch((cause) => setError(cause.message))
  }, [])

  return (
    <>
      <PageHeading
        eyebrow="Privacy-aware observability"
        title="Security dashboard"
        description="Monitor retrieval activity and restricted-document denials. Queries are never retained in the audit stream."
        action={
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-600">
            <Activity size={14} className="text-emerald-600" /> Live audit data
          </span>
        }
      />
      <ErrorBanner>{error}</ErrorBanner>
      {metrics && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard label="Retrieval requests" value={metrics.total_requests} note="Visible within your access scope" icon={Activity} />
            <MetricCard label="Denied attempts" value={metrics.denied_requests} note="Queries with restricted matches" icon={ShieldAlert} tone="rose" />
            <MetricCard label="Documents protected" value={metrics.denied_documents} note="Unauthorized passages withheld" icon={LockKeyhole} tone="amber" />
            <MetricCard label="Policies active" value="1" note="Role · department · clearance ACL" icon={ShieldCheck} tone="emerald" />
          </div>
          <div className="mt-5 grid gap-5 xl:grid-cols-[1.55fr_1fr]">
            <section className="panel-card p-5 sm:p-6">
              <div className="mb-5 flex items-start justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-ink">Retrieval activity</h2>
                  <p className="mt-1 text-xs text-muted">Daily requests · last 7 days</p>
                </div>
                <span className="rounded-md bg-slate-50 px-2 py-1 text-[10px] text-slate-500">UTC</span>
              </div>
              <div className="h-[250px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={metrics.incidents_over_time} margin={{ top: 8, right: 12, left: -22, bottom: 0 }}>
                    <defs>
                      <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#6477ed" stopOpacity={0.22} />
                        <stop offset="95%" stopColor="#6477ed" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#edf0f5" vertical={false} />
                    <XAxis dataKey="date" tickFormatter={(value) => value.slice(5)} axisLine={false} tickLine={false} tick={{ fill: "#929bad", fontSize: 10 }} dy={9} />
                    <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#929bad", fontSize: 10 }} />
                    <Tooltip contentStyle={{ borderRadius: 12, borderColor: "#e8ebf2", fontSize: 12 }} />
                    <Area type="monotone" dataKey="count" name="Requests" stroke="#5b6ee1" strokeWidth={2.5} fill="url(#activityFill)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>
            <section className="panel-card p-5 sm:p-6">
              <div className="mb-5">
                <h2 className="text-sm font-semibold text-ink">Activity breakdown</h2>
                <p className="mt-1 text-xs text-muted">Allowed retrievals vs protected content</p>
              </div>
              <div className="h-[250px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={metrics.category_breakdown} layout="vertical" margin={{ top: 4, right: 8, left: 15, bottom: 4 }}>
                    <CartesianGrid stroke="#edf0f5" horizontal={false} />
                    <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#929bad", fontSize: 10 }} />
                    <YAxis type="category" dataKey="category" width={122} axisLine={false} tickLine={false} tick={{ fill: "#687386", fontSize: 10 }} />
                    <Tooltip cursor={{ fill: "#f7f8fb" }} contentStyle={{ borderRadius: 12, borderColor: "#e8ebf2", fontSize: 12 }} />
                    <Bar dataKey="count" name="Events" radius={[0, 6, 6, 0]} fill="#6879e8" barSize={24} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>
          </div>
          <div className="mt-5 grid gap-5 xl:grid-cols-[1.4fr_1fr]">
            <section className="panel-card overflow-hidden">
              <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                <div>
                  <h2 className="text-sm font-semibold text-ink">Recent security activity</h2>
                  <p className="mt-1 text-xs text-muted">Privacy-safe retrieval event log</p>
                </div>
                <Shield size={16} className="text-slate-400" />
              </div>
              {metrics.recent_incidents.length ? (
                <div className="divide-y divide-slate-100">
                  {metrics.recent_incidents.slice(0, 6).map((row) => (
                    <div key={row.id} className="flex items-center gap-3 px-5 py-3.5">
                      <div className={cx("grid h-8 w-8 shrink-0 place-items-center rounded-lg", row.denied_count ? "bg-amber-50 text-amber-600" : "bg-emerald-50 text-emerald-600")}>
                        {row.denied_count ? <LockKeyhole size={15} /> : <Check size={15} />}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-xs font-medium text-ink">{row.event}</p>
                        <p className="mt-1 text-[10px] text-muted">{row.user_id} · {row.department}</p>
                      </div>
                      <span className="shrink-0 text-[10px] text-slate-400">
                        {new Date(row.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="px-5 py-10 text-center text-xs text-muted">No retrieval activity yet. Try a question in Secure chat.</div>
              )}
            </section>
            <section className="panel-card overflow-hidden">
              <div className="border-b border-slate-100 px-5 py-4">
                <h2 className="text-sm font-semibold text-ink">User risk overview</h2>
                <p className="mt-1 text-xs text-muted">Based on denied retrieval requests</p>
              </div>
              {metrics.per_user_risk.length ? (
                <div className="divide-y divide-slate-100">
                  {metrics.per_user_risk.map((row) => (
                    <div key={row.user_id} className="flex items-center gap-3 px-5 py-3.5">
                      <div className="grid h-8 w-8 place-items-center rounded-full bg-slate-100 text-[10px] font-semibold uppercase text-slate-600">
                        {row.user_id.slice(0, 2)}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <p className="truncate text-xs font-medium text-ink">{row.user_id}</p>
                          <span className={cx("text-[10px] font-semibold", row.risk_score > 50 ? "text-rose-600" : row.risk_score ? "text-amber-600" : "text-emerald-600")}>
                            {row.risk_score}% risk
                          </span>
                        </div>
                        <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-slate-100">
                          <div className={cx("h-full rounded-full", row.risk_score > 50 ? "bg-rose-400" : row.risk_score ? "bg-amber-400" : "bg-emerald-400")} style={{ width: `${row.risk_score}%` }} />
                        </div>
                        <p className="mt-1 text-[10px] text-slate-400">{row.department} · {row.denied_requests} denied / {row.total_requests}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="px-5 py-10 text-center text-xs text-muted">Risk indicators appear after retrieval activity.</div>
              )}
            </section>
          </div>
          <section className="panel-card mt-5 p-5 sm:p-6">
            <div className="mb-4 flex items-start justify-between">
              <div>
                <h2 className="text-sm font-semibold text-ink">Top triggered policies</h2>
                <p className="mt-1 text-xs text-muted">Access rules that withheld restricted material</p>
              </div>
              <ShieldCheck size={17} className="text-indigo-500" />
            </div>
            {metrics.top_policies.length ? (
              <div className="space-y-3">
                {metrics.top_policies.map((policy) => (
                  <div key={policy.policy} className="flex items-center gap-4">
                    <span className="min-w-0 flex-1 truncate text-xs font-medium text-slate-700">{policy.policy}</span>
                    <div className="h-2 w-24 overflow-hidden rounded-full bg-slate-100 sm:w-40">
                      <div
                        className="h-full rounded-full bg-indigo-500"
                        style={{
                          width: `${metrics.denied_requests ? Math.max(6, (policy.count / metrics.denied_requests) * 100) : 0}%`,
                        }}
                      />
                    </div>
                    <span className="w-8 text-right text-xs font-semibold tabular-nums text-ink">{policy.count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted">No access policies have been triggered yet.</p>
            )}
          </section>
        </>
      )}
      {!metrics && !error && <div className="panel-card py-20 text-center text-sm text-muted">Loading dashboard…</div>}
    </>
  )
}

function ApprovalsPage({ user }) {
  const [approvals, setApprovals] = useState([])
  const [error, setError] = useState("")
  const [busyId, setBusyId] = useState("")
  const isApprover = user.role !== "intern"

  useEffect(() => {
    api("/api/approvals")
      .then(setApprovals)
      .catch((cause) => setError(cause.message))
  }, [])

  async function decide(approvalId, decision) {
    setBusyId(approvalId)
    setError("")
    try {
      const updated = await api(`/api/approvals/${approvalId}`, {
        method: "PATCH",
        body: JSON.stringify({ decision }),
      })
      setApprovals((current) => current.map((item) => item.approval_id === approvalId ? updated : item))
    } catch (cause) {
      setError(cause.message)
    } finally {
      setBusyId("")
    }
  }

  const pending = approvals.filter((approval) => approval.status === "pending")
  const resolved = approvals.filter((approval) => approval.status !== "pending")

  return (
    <>
      <PageHeading
        eyebrow="Human review"
        title="Approval queue"
        description="Review requests within your department. Decisions are recorded with the authenticated reviewer and timestamp."
        action={
          <span className="rounded-full bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-700">
            {pending.length} pending
          </span>
        }
      />
      <ErrorBanner>{error}</ErrorBanner>
      {!isApprover && (
        <div className="mb-5 flex items-start gap-2 rounded-xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-xs leading-5 text-indigo-800">
          <LockKeyhole size={15} className="mt-0.5 shrink-0" />
          You can view your department&apos;s queue, but only HR, Finance, and Admin roles can decide requests.
        </div>
      )}
      <h2 className="mb-3 text-sm font-semibold text-ink">Needs your review</h2>
      {pending.length ? (
        <div className="space-y-3">
          {pending.map((approval) => (
            <article key={approval.approval_id} className="panel-card p-5 sm:p-6">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="flex gap-3">
                  <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-amber-50 text-amber-600">
                    <ClipboardCheck size={18} />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold text-ink">{approval.subject}</h3>
                      <span className="rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-semibold text-amber-700">Pending</span>
                    </div>
                    <p className="mt-1 text-xs text-muted">
                      Requested by <span className="font-medium text-slate-700">{approval.requested_by}</span> · {approval.department}
                    </p>
                  </div>
                </div>
                {isApprover && (
                  <div className="flex gap-2">
                    <button
                      type="button"
                      className="secondary-button !px-3 !py-2 !text-xs"
                      disabled={busyId === approval.approval_id}
                      onClick={() => decide(approval.approval_id, "rejected")}
                    >
                      <X size={14} /> Reject
                    </button>
                    <button
                      type="button"
                      className="primary-button !px-3 !py-2 !text-xs"
                      disabled={busyId === approval.approval_id}
                      onClick={() => decide(approval.approval_id, "approved")}
                    >
                      <Check size={14} /> Approve
                    </button>
                  </div>
                )}
              </div>
              <p className="mt-4 border-l-2 border-indigo-100 pl-3 text-xs leading-6 text-slate-600">
                {approval.details_redacted}
              </p>
              <p className="mt-3 text-[10px] text-slate-400">
                Submitted {new Date(approval.requested_at).toLocaleString()}
              </p>
            </article>
          ))}
        </div>
      ) : (
        <div className="panel-card py-12 text-center">
          <div className="mx-auto grid h-11 w-11 place-items-center rounded-xl bg-emerald-50 text-emerald-600"><Check size={20} /></div>
          <p className="mt-3 text-sm font-medium text-ink">You&apos;re all caught up</p>
          <p className="mt-1 text-xs text-muted">No pending approvals in your visible queue.</p>
        </div>
      )}
      {resolved.length > 0 && (
        <>
          <h2 className="mb-3 mt-8 text-sm font-semibold text-ink">Recently resolved</h2>
          <div className="panel-card divide-y divide-slate-100">
            {resolved.map((approval) => (
              <div key={approval.approval_id} className="flex items-center gap-3 px-5 py-4">
                <div className={cx("grid h-8 w-8 place-items-center rounded-lg", approval.status === "approved" ? "bg-emerald-50 text-emerald-600" : "bg-rose-50 text-rose-600")}>
                  {approval.status === "approved" ? <Check size={15} /> : <X size={15} />}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-xs font-medium text-ink">{approval.subject}</p>
                  <p className="mt-1 text-[10px] text-muted">Decision by {approval.decided_by}</p>
                </div>
                <span className="text-[10px] capitalize text-muted">{approval.status}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </>
  )
}

export default function App() {
  const [user, setUser] = useState(null)
  const [active, setActive] = useState("chat")
  const [checking, setChecking] = useState(Boolean(sessionStorage.getItem("hinderman_token")))

  useEffect(() => {
    if (!sessionStorage.getItem("hinderman_token")) return
    api("/api/auth/me")
      .then(setUser)
      .catch(() => logout())
      .finally(() => setChecking(false))
  }, [])

  async function handleLogin(userId, password) {
    const currentUser = await login(userId, password)
    setUser(currentUser)
    setActive("chat")
  }

  function handleLogout() {
    logout()
    setUser(null)
    setActive("chat")
  }

  if (checking) {
    return <div className="grid min-h-screen place-items-center text-sm text-muted">Verifying secure session…</div>
  }
  if (!user) return <LoginScreen onLogin={handleLogin} />

  let page
  if (active === "chat") page = <ChatPage />
  if (active === "library") page = <LibraryPage />
  if (active === "approvals") page = <ApprovalsPage user={user} />
  if (active === "dashboard") page = <DashboardPage />

  return (
    <AppShell user={user} active={active} setActive={setActive} onLogout={handleLogout}>
      {page}
    </AppShell>
  )
}
