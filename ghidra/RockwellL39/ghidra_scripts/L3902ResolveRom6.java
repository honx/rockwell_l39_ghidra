// L3902 ROM6 reference resolver — Phase 3 of the bank-aware analyser.
//
// At runtime, BSR7 = $73 maps file offsets 0x6000-0x7FFF (the persistent
// "ROM6" code bank: switch_rom_cfgX, the dispatcher at $E81B, the IRQ
// handlers at $E2E7-$E3C2, and the third-stage boot stub at $E7B6) into
// the CPU's $E000-$FFFF window. The boot-time view that BinaryLoader
// produces has those same ROM6 bytes at default:$6000-$7FFF (1:1 file
// mapping). So any $Exxx-targeted reference in the firmware should
// resolve to default:(target - $8000).
//
// This script does two things, both small:
//
//   1. Creates a rom6 overlay block at $E000-$FFFF holding file
//      0x6000-0x7FFF bytes. Disassembling the overlay gives an
//      "as the firmware sees it at runtime" view (addresses ending in
//      $Exxx instead of $6xxx). Disassembly is left to auto-analysis;
//      this script just creates the block.
//
//   2. Walks every instruction in the program and, for each one with a
//      flow-target in [$E000, $FFFF], adds a memory reference to the
//      corresponding default:$6xxx address. That makes the xref panel
//      and the decompiler resolve runtime ROM6 calls correctly.
//
// What this still doesn't fix: references in [$0200, $7FFF] (the
// swappable-bank region). Resolving those needs to know which
// configuration is active at the call site, which is config propagation
// — Phase 4.
//
// @category L3902
// @keybinding
// @menupath Tools.L3902.Resolve ROM6 references
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;

public class L3902ResolveRom6 extends GhidraScript {

    private static final long ROM6_FILE_OFFSET = 0x6000L;   // physical bank 3 start
    private static final long ROM6_BANK_LEN    = 0x2000L;   // 8 KiB
    private static final long RUNTIME_ROM6_BASE = 0xE000L;  // logical at runtime
    private static final long ROM6_OFFSET_DELTA = 0x8000L;  // $E000 - $6000

    @Override
    public void run() throws Exception {
        LanguageID lang = currentProgram.getLanguageID();
        if (!lang.toString().startsWith("RockwellL39")) {
            popup("L3902ResolveRom6: language is " + lang
                    + ", expected RockwellL39:LE:16:default. Aborting.");
            return;
        }

        Memory mem = currentProgram.getMemory();
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // --- Step 1: create the rom6 overlay (idempotent).
        if (mem.getBlock("rom6") == null) {
            createRom6Overlay(mem, ram);
        } else {
            println("rom6 overlay already exists; skipping creation");
        }

        // --- Step 2: rewrite $Exxx-targeted references to point at default:$6xxx.
        int rewritten = rewriteRom6References(mem, ram);
        println("Added " + rewritten + " ROM6 references "
                + "($Exxx targets redirected to default:$6xxx).");
    }

    // ---------------------------------------------------------------
    // rom6 overlay
    // ---------------------------------------------------------------

    private void createRom6Overlay(Memory mem, AddressSpace ram) throws Exception {
        // Read ROM6 bytes from disk (BinaryLoader's FileBytes is clipped
        // to 64 KiB but file 0x6000-0x7FFF is well within that, so we
        // could also pull from FileBytes; reading from disk is simpler
        // and matches the L3902BankingSetup script's pattern).
        String[] args = getScriptArgs();
        File fwFile;
        if (args.length > 0) {
            fwFile = new File(args[0]);
        } else {
            String execPath = currentProgram.getExecutablePath();
            if (execPath == null || execPath.isEmpty()) {
                popup("L3902ResolveRom6: program has no executable path. "
                        + "Pass the firmware file as a script argument.");
                return;
            }
            fwFile = new File(execPath);
        }
        if (!fwFile.canRead()) {
            popup("L3902ResolveRom6: cannot read firmware file at "
                    + fwFile.getAbsolutePath());
            return;
        }
        byte[] fw = Files.readAllBytes(fwFile.toPath());
        if (fw.length < ROM6_FILE_OFFSET + ROM6_BANK_LEN) {
            popup("L3902ResolveRom6: firmware is shorter than 0x"
                    + Long.toHexString(ROM6_FILE_OFFSET + ROM6_BANK_LEN)
                    + " bytes; cannot extract ROM6.");
            return;
        }

        Address start = ram.getAddress(RUNTIME_ROM6_BASE);
        MemoryBlock block = mem.createInitializedBlock("rom6", start,
                ROM6_BANK_LEN, (byte) 0xFF, monitor, /*overlay=*/true);
        block.setRead(true);
        block.setWrite(false);
        block.setExecute(true);
        block.setComment("L3902 persistent code bank (BSR7 = $73 maps file "
                + "0x6000-0x7FFF here at runtime). Contains: switch_rom_cfgX "
                + "at $E000-$E033, NMI/IRQ dispatcher at $E2E7-$E3C2, "
                + "third-stage boot stub at $E7B6, AT-command dispatcher at "
                + "$E81B.");

        AddressSpace ovSpace = block.getStart().getAddressSpace();
        byte[] rom6 = Arrays.copyOfRange(fw,
                Math.toIntExact(ROM6_FILE_OFFSET),
                Math.toIntExact(ROM6_FILE_OFFSET + ROM6_BANK_LEN));
        mem.setBytes(ovSpace.getAddress(RUNTIME_ROM6_BASE), rom6);

        println(String.format("Created rom6 overlay: $%04X-$%04X, %d bytes "
                + "from file 0x%04X.",
                RUNTIME_ROM6_BASE, RUNTIME_ROM6_BASE + ROM6_BANK_LEN - 1,
                rom6.length, ROM6_FILE_OFFSET));
    }

    // ---------------------------------------------------------------
    // Reference rewriting
    // ---------------------------------------------------------------

    private int rewriteRom6References(Memory mem, AddressSpace ram)
            throws Exception {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();
        int added = 0;

        // Walk every instruction in the default address space.
        InstructionIterator it = listing.getInstructions(currentProgram.getMemory(), true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            // Only consider instructions in default RAM (skip overlays —
            // they have their own address spaces and references inside an
            // overlay are already correct).
            if (!insn.getAddress().getAddressSpace().equals(ram)) {
                continue;
            }
            // Look at all references the instruction already emits.
            Reference[] refs = insn.getReferencesFrom();
            for (Reference r : refs) {
                Address tgt = r.getToAddress();
                // Only rewrite default-RAM targets in the runtime ROM6
                // window $E000-$FFFF. Non-flow references (data loads
                // from $Exxx — there shouldn't be any meaningful ones
                // in this firmware, but be defensive) get the same
                // treatment.
                if (!tgt.getAddressSpace().equals(ram)) continue;
                long off = tgt.getOffset();
                if (off < RUNTIME_ROM6_BASE || off > 0xFFFFL) continue;

                // Compute the boot-time-view counterpart and add a
                // memory reference to it. Don't remove the original —
                // keeping both means xref panels show users a clear
                // "$E000 (also at $6000)" linkage.
                long redirected = off - ROM6_OFFSET_DELTA;
                Address redirectedAddr = ram.getAddress(redirected);
                RefType rt = r.getReferenceType();
                refMgr.addMemoryReference(insn.getAddress(), redirectedAddr,
                        rt, SourceType.ANALYSIS, r.getOperandIndex());
                added++;
            }
        }
        return added;
    }
}
