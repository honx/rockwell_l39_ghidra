// L3902 configuration propagator — Phase 4 of the bank-aware analyser.
//
// Walks the program's control-flow graph (in the default address space)
// to determine which configuration(s) each instruction runs under, then
// uses that information to rewrite cross-references targeting the
// swappable-bank region $0200-$7FFF: each such reference becomes a
// reference into the appropriate cfgN overlay block.
//
// Algorithm (worklist propagation, simplified):
//
//   1. Find the four switch_rom_cfgN functions by name. They were
//      labelled by Phase 2 (L3902BankingSetup.java).
//
//   2. Seed the worklist with one entry per *call site* of each
//      switch_rom_cfgN function: (fall-through address, N).
//
//   3. While the worklist is non-empty, pop (addr, cfg):
//        - If addr is already tagged with cfg, skip.
//        - Tag addr with cfg.
//        - Compute the post-instruction config:
//            * If the instruction is JSR to switch_rom_cfgM, fall-through
//              gets cfgM (the call returns with cfgM active).
//            * Otherwise fall-through gets the same config (assumes the
//              callee returns without changing the active config — this
//              is the simplified model; see "Known limitations" below).
//        - Push the fall-through with the post-instruction config.
//        - Push branch / call targets with the *current* config (callees
//          inherit caller's config on entry).
//
//   4. For each tagged instruction whose flow target lies in
//      $0200-$7FFF, add a memory reference to the same offset in each
//      of its active configurations' overlay address spaces.
//
// Known limitations:
//
//   * "Function returns with the same config as it was called with."
//     If a function internally invokes a switch_rom_cfgN and returns
//     without restoring, the analyser tags the caller's fall-through
//     with the wrong configuration. A proper fix is inter-procedural
//     fixpoint analysis (per-function exit-config). Not implemented.
//     The reference firmware seems to use only direct switch_rom calls
//     so this is unlikely to bite, but log a warning if a function's
//     body contains a switch_rom call that isn't followed by another
//     switch_rom or a return.
//
//   * Indirect calls (computed JMPs, JSB# slots) aren't followed. The
//     reference firmware uses JSB# only at boot for fixed targets in
//     $FFE0-$FFEE; those slots are unset on this firmware so no
//     propagation across JSB# is needed.
//
//   * Polymorphic functions (called from multiple configs) get all
//     applicable cfg tags, and their xrefs get rewritten to all
//     candidate overlays. Users should expect to see the same
//     instruction with multiple cfgN-resolved targets in the xref
//     panel and pick the right one based on context.
//
// @category L3902
// @keybinding
// @menupath Tools.L3902.Propagate configurations
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayDeque;
import java.util.BitSet;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class L3902PropagateConfigs extends GhidraScript {

    private static final long CFG_LOW = 0x0200L;
    private static final long CFG_HIGH = 0x7FFFL;

    @Override
    public void run() throws Exception {
        LanguageID lang = currentProgram.getLanguageID();
        if (!lang.toString().startsWith("RockwellL39")) {
            popup("L3902PropagateConfigs: language is " + lang
                    + ", expected RockwellL39:LE:16:default. Aborting.");
            return;
        }

        Memory mem = currentProgram.getMemory();
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        // --- Step 1: locate switch_rom_cfgN functions.
        Map<Address, Integer> switchAddrs = locateSwitchFunctions(ram);
        if (switchAddrs.size() != 4) {
            popup("L3902PropagateConfigs: expected 4 switch_rom_cfgN "
                    + "functions, found " + switchAddrs.size()
                    + ". Run L3902BankingSetup.java first.");
            return;
        }
        println("Found switch_rom_cfgN functions at:");
        switchAddrs.forEach((a, n) ->
                println(String.format("  cfg%d -> %s", n, a)));

        // --- Step 2: seed the worklist.
        // Per Phase-3 redirects we have references to switch_rom_cfgN at
        // both default:$Exxx and default:$6xxx. Use the references-to
        // each function entry to find call sites; only consider call-type
        // references (JSR) — jumps don't return and don't seed a
        // post-call config.
        Deque<long[]> worklist = new ArrayDeque<>(); // [addr, cfg]
        Map<Address, BitSet> activeCfgs = new HashMap<>();
        int seeded = 0;
        for (Map.Entry<Address, Integer> e : switchAddrs.entrySet()) {
            Address swAddr = e.getKey();
            int targetCfg = e.getValue();
            for (Reference r : refMgr.getReferencesTo(swAddr)) {
                if (!r.getReferenceType().isCall()) continue;
                Instruction callInsn = listing.getInstructionAt(r.getFromAddress());
                if (callInsn == null) continue;
                if (!callInsn.getAddress().getAddressSpace().equals(ram)) continue;
                Address ft = callInsn.getFallThrough();
                if (ft == null) continue;
                worklist.push(new long[] { ft.getOffset(), targetCfg });
                seeded++;
            }
        }
        println("Seeded worklist with " + seeded + " call-site fall-throughs.");

        // --- Step 3: worklist propagation.
        int visits = 0;
        Set<Address> warnedFunctions = new HashSet<>();
        while (!worklist.isEmpty()) {
            long[] item = worklist.pop();
            Address addr = ram.getAddress(item[0]);
            int cfg = (int) item[1];
            visits++;

            BitSet tags = activeCfgs.computeIfAbsent(addr, k -> new BitSet(5));
            if (tags.get(cfg)) continue;
            tags.set(cfg);

            Instruction insn = listing.getInstructionAt(addr);
            if (insn == null) continue;
            // Only propagate within the default address space; overlay
            // instructions belong to a different propagation problem
            // (Ghidra would need separate disassembly of each overlay).
            if (!addr.getAddressSpace().equals(ram)) continue;

            FlowType flow = insn.getFlowType();
            // The instruction's "post-config" is the config the
            // following instruction will execute under. Default: same
            // as current. If we're calling switch_rom_cfgM, the
            // fall-through executes in cfgM.
            int postCfg = cfg;
            if (flow.isCall()) {
                for (Address tgt : insn.getFlows()) {
                    Integer m = switchAddrs.get(tgt);
                    if (m != null) {
                        postCfg = m;
                        break;
                    }
                }
            }

            // Fall-through.
            Address ft = insn.getFallThrough();
            if (ft != null && ft.getAddressSpace().equals(ram)) {
                worklist.push(new long[] { ft.getOffset(), postCfg });
            }

            // Branch / call / jump targets — propagate with current cfg
            // (callees inherit caller's config on entry).
            if (flow.isJump() || flow.isCall() || flow.isConditional()) {
                for (Address tgt : insn.getFlows()) {
                    if (!tgt.getAddressSpace().equals(ram)) continue;
                    worklist.push(new long[] { tgt.getOffset(), cfg });
                }
            }
        }
        println(String.format("Propagation: %d visits, %d instructions tagged.",
                visits, activeCfgs.size()));

        // Warn on instructions that ended up "polymorphic" (more than
        // one cfg tag). These are usually shared helpers (the dispatcher
        // at $E81B / file 0x681B is the canonical example) and indicate
        // the analyser is doing the right thing — but the user should
        // know how many there are.
        int polyCount = 0;
        for (BitSet bs : activeCfgs.values()) {
            if (bs.cardinality() > 1) polyCount++;
        }
        println(String.format("  %d instructions are polymorphic "
                + "(reachable from multiple configurations).", polyCount));

        // --- Step 4: rewrite cfgN cross-references.
        Map<Integer, AddressSpace> cfgSpaces = new HashMap<>();
        for (int n = 1; n <= 4; n++) {
            MemoryBlock blk = mem.getBlock("cfg" + n);
            if (blk != null) {
                cfgSpaces.put(n, blk.getStart().getAddressSpace());
            }
        }
        if (cfgSpaces.size() != 4) {
            popup("L3902PropagateConfigs: expected 4 cfg overlays "
                    + "(cfg1..cfg4), found " + cfgSpaces.size()
                    + ". Run L3902BankingSetup.java first.");
            return;
        }

        int rewritten = 0;
        Map<Integer, Integer> rewrittenPerCfg = new HashMap<>();
        for (Map.Entry<Address, BitSet> e : activeCfgs.entrySet()) {
            Address from = e.getKey();
            BitSet tags = e.getValue();
            Instruction insn = listing.getInstructionAt(from);
            if (insn == null) continue;

            for (Reference r : insn.getReferencesFrom()) {
                Address tgt = r.getToAddress();
                if (!tgt.getAddressSpace().equals(ram)) continue;
                long off = tgt.getOffset();
                if (off < CFG_LOW || off > CFG_HIGH) continue;

                for (int n = tags.nextSetBit(0); n >= 0; n = tags.nextSetBit(n + 1)) {
                    AddressSpace cfgSpace = cfgSpaces.get(n);
                    if (cfgSpace == null) continue;
                    Address cfgTarget = cfgSpace.getAddress(off);
                    refMgr.addMemoryReference(from, cfgTarget,
                            r.getReferenceType(), SourceType.ANALYSIS,
                            r.getOperandIndex());
                    rewritten++;
                    rewrittenPerCfg.merge(n, 1, Integer::sum);
                }
            }
        }
        println("Rewrote " + rewritten + " cfgN reference(s):");
        for (int n = 1; n <= 4; n++) {
            int cnt = rewrittenPerCfg.getOrDefault(n, 0);
            println(String.format("  cfg%d: %d", n, cnt));
        }
        println("Phase 4 complete.");
    }

    /**
     * Locate switch_rom_cfg1..switch_rom_cfg4 functions in the default
     * address space by symbol name. Returns a map from function entry
     * address to configuration number.
     */
    private Map<Address, Integer> locateSwitchFunctions(AddressSpace ram) {
        Map<Address, Integer> result = new HashMap<>();
        SymbolTable st = currentProgram.getSymbolTable();
        for (int n = 1; n <= 4; n++) {
            String name = "switch_rom_cfg" + n;
            SymbolIterator it = st.getSymbols(name);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.getAddress().getAddressSpace().equals(ram)) {
                    result.put(s.getAddress(), n);
                    break;
                }
            }
        }
        return result;
    }
}
