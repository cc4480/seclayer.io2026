// Billing & receipts tab: a table of credit purchase / scan-debit transactions.
export default function BillingTab({ transactions }: { transactions: any[] }) {
  if (transactions.length === 0) {
    return (
      <div className="space-y-4">
        <div className="text-center py-12 bg-black rounded border border-dashed border-[#27272a]">
          <span className="text-xs text-[#52525b] font-mono block mb-2">No billing transactions recorded yet</span>
          <p className="text-[11px] text-[#52525b] max-w-sm mx-auto font-mono">Transactions appear here when credits are added or debited during evaluation scans.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#27272a] text-[#52525b] font-mono text-[10px] uppercase tracking-wider pb-3">
              <th className="py-3 px-4">Transaction ID</th>
              <th className="py-3 px-4">Action Type</th>
              <th className="py-3 px-4">Amount</th>
              <th className="py-3 px-4">Reference ID</th>
              <th className="py-3 px-4 text-right font-mono">Timestamp</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#27272a]/20 text-xs font-mono">
            {transactions.map((tx) => {
              const isCreditAdded = tx.amount > 0;
              return (
                <tr key={tx.id} className="hover:bg-black/60 transition-colors">
                  <td className="py-3.5 px-4 font-mono font-bold text-white uppercase">{tx.id || "tx_system"}</td>
                  <td className="py-3.5 px-4">
                    {tx.type === 'purchase' ? (
                      <span className="bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e] px-2 py-0.5 rounded font-mono text-[9px] uppercase">Purchased Credits</span>
                    ) : (
                      <span className="bg-amber-950/40 border border-[#27272a] text-amber-400 px-2 py-0.5 rounded font-mono text-[9px] uppercase">Audit Cost Deducted</span>
                    )}
                  </td>
                  <td className={`py-3.5 px-4 font-bold ${isCreditAdded ? 'text-[#22c55e]' : 'text-rose-400'}`}>
                    {isCreditAdded ? `+${tx.amount}` : tx.amount} credits
                  </td>
                  <td className="py-3.5 px-4 text-[#a1a1aa] max-w-xs truncate font-mono text-[10px]">
                    {tx.stripeSessionId || tx.scanId || 'System Provision'}
                  </td>
                  <td className="py-3.5 px-4 text-right text-[#52525b] font-mono text-[11px]">
                    {new Date(tx.createdAt).toLocaleString()}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
