import { useCallback, useEffect, useMemo, useState } from "react";
import { Copy, Target } from "lucide-react";
import { EngineClientError, engineCall } from "../lib/api";
import type { AttckCoverage, AttckSource, DraftRule, DraftRuleFormat } from "../lib/types";
import { cn } from "../lib/utils";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { SegmentedControl } from "./ui/segmented";
import { CenteredLoading, ImportEvidenceState } from "./CoverageStatus";

function sourceKindFor(source: AttckSource): "yara_match" | "capa_capability" | null {
  if (source.kind === "yara" && source.match_id) return "yara_match";
  if (source.kind === "capa" && source.capability_id) return "capa_capability";
  return null;
}

function sourceIdFor(source: AttckSource): string | null {
  return source.match_id ?? source.capability_id ?? null;
}

function DraftRuleDialog({
  draft,
  format,
  onFormatChange,
  busy,
  onClose,
}: {
  draft: DraftRule | null;
  format: DraftRuleFormat;
  onFormatChange: (f: DraftRuleFormat) => void;
  busy: boolean;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => setCopied(false), [draft]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-6"
      role="dialog"
      aria-modal="true"
      onClick={onClose}
    >
      <div
        className="flex max-h-[80vh] w-full max-w-2xl flex-col rounded-lg border border-border bg-surface shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
          <div className="text-sm font-semibold">Draft detection rule</div>
          <div className="flex items-center gap-2">
            <SegmentedControl
              value={format}
              onChange={onFormatChange}
              ariaLabel="Rule format"
              options={[
                { id: "sigma", label: "Sigma" },
                { id: "yara", label: "YARA" },
              ]}
            />
            <Button variant="ghost" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-4">
          {busy ? (
            <CenteredLoading label="Generating draft…" />
          ) : (
            <pre className="whitespace-pre-wrap break-words rounded-md border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed">
              {draft?.content ?? ""}
            </pre>
          )}
        </div>
        <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-2.5 text-xs text-muted">
          <span>
            Unreviewed draft — verify against known-good baselines before deploying. Not written to
            disk automatically.
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={!draft || busy}
            onClick={() => {
              if (!draft) return;
              void navigator.clipboard.writeText(draft.content).then(() => setCopied(true));
            }}
          >
            <Copy className="mr-1.5 h-3.5 w-3.5" strokeWidth={1.75} aria-hidden />
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      </div>
    </div>
  );
}

function TechniqueCard({
  technique,
  onGenerate,
}: {
  technique: AttckCoverage["techniques"][number];
  onGenerate: (source: AttckSource) => void;
}) {
  const uniqueSources = useMemo(() => {
    const seen = new Set<string>();
    return technique.sources.filter((s) => {
      const key = `${s.kind}:${s.name}:${sourceIdFor(s)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [technique.sources]);

  const techniqueUrl = `https://attack.mitre.org/techniques/${technique.technique_id.replace(".", "/")}/`;

  return (
    <article className="rounded-md border border-border bg-surface px-3 py-2.5 text-xs">
      <div className="mb-1.5 flex flex-wrap items-center gap-2">
        <Badge className="border-accent/40 bg-accent/10 text-accent">
          {technique.technique_id}
        </Badge>
        <a
          href={techniqueUrl}
          target="_blank"
          rel="noreferrer"
          className="text-xs text-muted hover:text-accent hover:underline"
        >
          View on attack.mitre.org
        </a>
        <span className="text-muted">
          {uniqueSources.length} finding{uniqueSources.length === 1 ? "" : "s"}
        </span>
      </div>
      <ul className="space-y-1">
        {uniqueSources.map((source, idx) => {
          const kind = sourceKindFor(source);
          return (
            <li
              key={`${source.kind}-${sourceIdFor(source)}-${idx}`}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md bg-surface-2 px-2 py-1.5"
            >
              <div className="flex min-w-0 items-center gap-2">
                <span
                  className={cn(
                    "shrink-0 rounded-sm px-1 py-0.5 text-[0.68rem] font-semibold uppercase tracking-wide",
                    source.kind === "capa"
                      ? "bg-accent/15 text-accent"
                      : "bg-amber-500/15 text-amber-600",
                  )}
                >
                  {source.kind}
                </span>
                <span className="min-w-0 truncate font-mono" title={source.name ?? undefined}>
                  {source.name ?? "unnamed"}
                </span>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="h-6 shrink-0 px-2 text-[0.7rem]"
                disabled={!kind}
                title={kind ? undefined : "This finding can't be traced back to a draftable row."}
                onClick={() => onGenerate(source)}
              >
                Generate draft rule
              </Button>
            </li>
          );
        })}
      </ul>
    </article>
  );
}

export function AttckView({
  evidenceId,
  onError,
  refreshToken,
}: {
  evidenceId: string | null;
  onError: (m: string) => void;
  refreshToken?: number | string;
}) {
  const [coverage, setCoverage] = useState<AttckCoverage | null>(null);
  const [loading, setLoading] = useState(false);
  const [draftSource, setDraftSource] = useState<AttckSource | null>(null);
  const [draft, setDraft] = useState<DraftRule | null>(null);
  const [draftFormat, setDraftFormat] = useState<DraftRuleFormat>("sigma");
  const [draftBusy, setDraftBusy] = useState(false);

  const load = useCallback(async () => {
    if (!evidenceId) return;
    setLoading(true);
    try {
      const res = await engineCall<AttckCoverage>("attck.coverage", { evidence_id: evidenceId });
      setCoverage(res);
    } catch (e) {
      setCoverage(null);
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [evidenceId, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const generate = useCallback(
    async (source: AttckSource, format: DraftRuleFormat) => {
      const kind = sourceKindFor(source);
      const id = sourceIdFor(source);
      if (!kind || !id) return;
      setDraftBusy(true);
      try {
        const res = await engineCall<DraftRule>("attck.generate_rule", {
          source_kind: kind,
          source_id: id,
          rule_format: format,
        });
        setDraft(res);
      } catch (e) {
        onError(e instanceof EngineClientError ? e.message : String(e));
        setDraft(null);
      } finally {
        setDraftBusy(false);
      }
    },
    [onError],
  );

  if (!evidenceId) return <ImportEvidenceState title="ATT&CK Coverage" />;

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col text-xs">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <Target className="h-4 w-4 text-muted" strokeWidth={1.75} aria-hidden />
        <div className="text-sm font-semibold">MITRE ATT&CK Coverage</div>
        <div className="text-xs text-muted">
          {coverage ? `${coverage.technique_count} technique(s) observed` : null}
        </div>
      </div>
      <div className="border-b border-border px-3 py-2 text-xs text-muted">
        Techniques inferred from CAPA capability matches and tagged Signature Detection (YARA)
        rules for this evidence. Pick a finding to generate a draft Sigma or YARA rule from it —
        every draft is unreviewed and meant to be refined before use.
      </div>
      {loading && !coverage ? (
        <CenteredLoading label="Loading ATT&CK coverage…" />
      ) : !coverage || coverage.techniques.length === 0 ? (
        <div className="p-6 text-sm text-muted">
          No ATT&CK-tagged findings yet. Run a Signature Detection (YARA) scan or CAPA analysis
          first — this view reads what those capabilities already produced.
        </div>
      ) : (
        <div className="min-h-0 flex-1 space-y-2 overflow-auto p-3">
          {coverage.techniques.map((t) => (
            <TechniqueCard
              key={t.technique_id}
              technique={t}
              onGenerate={(source) => {
                setDraftSource(source);
                setDraft(null);
                void generate(source, draftFormat);
              }}
            />
          ))}
        </div>
      )}
      {draftSource ? (
        <DraftRuleDialog
          draft={draft}
          format={draftFormat}
          busy={draftBusy}
          onFormatChange={(f) => {
            setDraftFormat(f);
            void generate(draftSource, f);
          }}
          onClose={() => {
            setDraftSource(null);
            setDraft(null);
          }}
        />
      ) : null}
    </div>
  );
}
