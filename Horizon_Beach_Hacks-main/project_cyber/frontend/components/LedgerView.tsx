"use client";

import { useState } from "react";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { api, type LedgerBlock, type LedgerVerification } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { Async, Button, Card, Modal, fmtDate, inputClass, titleCase } from "@/components/ui";
import Pager from "@/components/Pager";

const PAGE_SIZE = 25;

export default function LedgerView() {
  const info = useQuery(() => api.ledger.info(), [], 60000);
  const [page, setPage] = useState(1);
  const [eventType, setEventType] = useState("");
  const [term, setTerm] = useState("");
  const blocks = useQuery(
    () => api.ledger.blocks({ skip: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE, event_type: eventType, q: term.trim() }),
    [page, eventType, term],
    30000,
  );
  const [selected, setSelected] = useState<LedgerBlock | null>(null);
  const [verification, setVerification] = useState<LedgerVerification | null>(null);
  const verify = useAction(() => api.ledger.verify());

  return (
    <div className="space-y-3">
      <Card
        title="Cryptographic audit ledger"
        action={
          <Button
            disabled={verify.pending}
            onClick={async () => {
              const r = await verify.run();
              if (r) setVerification(r);
            }}
          >
            {verify.pending ? "Verifying…" : "Verify chain integrity"}
          </Button>
        }
      >
        <Async q={info}>
          {(i) => (
            <dl className="grid grid-cols-2 xl:grid-cols-4 gap-3 text-sm text-gray-800 dark:text-gray-100">
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">Blocks</dt><dd className="text-xl font-bold">{i.total_blocks}</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">Head hash</dt><dd className="font-mono text-xs break-all">{i.head_hash.slice(0, 24)}…</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">Signing key (Ed25519)</dt><dd className="font-mono text-xs break-all">{i.signing_key_fingerprint.slice(0, 24)}…</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">Latest entry</dt><dd>{fmtDate(i.latest_timestamp)}</dd></div>
            </dl>
          )}
        </Async>
        {verify.error && <p className="text-sm text-critical mt-3" role="alert">{verify.error}</p>}
        {verification && (
          <div className={`mt-4 p-3 rounded-md flex items-start gap-2 text-sm ${verification.valid ? "bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-200" : "bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200"}`}>
            {verification.valid ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <ShieldAlert className="w-5 h-5 shrink-0" />}
            <div>
              {verification.valid ? `Chain intact — ${verification.blocks_verified} blocks verified (hashes, links and signatures).` : `Integrity failure — ${verification.issues.length} issue(s) detected.`}
              {!verification.valid && <pre className="text-xs mt-1 overflow-auto max-h-40">{JSON.stringify(verification.issues.slice(0, 10), null, 2)}</pre>}
            </div>
          </div>
        )}
      </Card>

      <Card title="Blocks">
        <div className="flex flex-wrap gap-2 mb-3">
          <select aria-label="Event type" className={`${inputClass} !w-auto`} value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(1); }}>
            <option value="">All events</option>
            {Object.keys(info.data?.events_by_type ?? {}).sort().map((t) => <option key={t} value={t}>{titleCase(t)} ({info.data!.events_by_type[t]})</option>)}
          </select>
          <input aria-label="Search ledger" className={`${inputClass} !w-64`} placeholder="Search actor / resource…" value={term} onChange={(e) => { setTerm(e.target.value); setPage(1); }} />
        </div>
        <Async q={blocks} empty={{ when: (d) => d.total === 0, title: "No matching blocks" }}>
          {(d) => (
            <>
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs uppercase text-gray-500 dark:text-gray-300"><th className="py-1">#</th><th>Time</th><th>Event</th><th>Actor</th><th>Hash</th></tr></thead>
                <tbody>
                  {d.blocks.map((b) => (
                    <tr key={b.block_number} onClick={() => setSelected(b)} className="border-t border-gray-100 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50 text-gray-800 dark:text-gray-100">
                      <td className="py-1.5 pr-2">{b.block_number}</td>
                      <td className="pr-2 whitespace-nowrap">{fmtDate(b.timestamp)}</td>
                      <td className="pr-2">{titleCase(b.event_type)}</td>
                      <td className="pr-2 truncate max-w-48">{b.actor ?? "—"}</td>
                      <td className="font-mono text-xs">{b.block_hash.slice(0, 12)}…{b.signed && " ✔"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <Pager page={page} pageSize={PAGE_SIZE} total={d.total} onPage={setPage} />
            </>
          )}
        </Async>
      </Card>

      {selected && (
        <Modal title={`Block #${selected.block_number}`} onClose={() => setSelected(null)} wide>
          <dl className="grid grid-cols-1 gap-2 text-xs text-gray-800 dark:text-gray-100">
            {([["Event", titleCase(selected.event_type)], ["Actor", selected.actor], ["Resource", [selected.resource_type, selected.resource_id].filter(Boolean).join(" ")],
               ["Time", fmtDate(selected.timestamp)], ["Previous hash", selected.previous_hash], ["Data hash", selected.data_hash], ["Block hash", selected.block_hash],
               ["Signed", selected.signed ? "Yes (Ed25519)" : "No"]] as const).map(([k, v]) => (
              <div key={k}><dt className="text-gray-500 dark:text-gray-400">{k}</dt><dd className="font-mono break-all">{v || "—"}</dd></div>
            ))}
          </dl>
          <pre className="mt-3 text-xs bg-gray-100 dark:bg-gray-900 p-3 rounded overflow-auto max-h-64">{JSON.stringify(selected.data, null, 2)}</pre>
        </Modal>
      )}
    </div>
  );
}
