// L3902 banking setup — Phase 1+2 of the bank-aware analyser.
//
// Run this script after the binary has been imported under the
// RockwellL39 language. It does two things:
//
//   1. Creates four overlay memory blocks named cfg1, cfg2, cfg3, cfg4
//      at the swappable-ROM region $0200-$7FFF. Each overlay is
//      initialised from the four physical 8 KiB banks that the
//      corresponding configuration maps in (per the contributor's
//      table in binary/banking-configurations.png).
//
//   2. Locates the four switch_rom_cfgX() entry points by pattern-
//      matching on the canonical eight-write BSR sequence followed by
//      RTS. Renames them, attaches a comment listing the BSR values,
//      and identifies cfg2 (the post-reset configuration) by matching
//      the known BSR sequence from the third-stage boot stub.
//
// What this *doesn't* do (yet): rewrite cross-references to point at
// the correct overlay block based on which configuration is active in
// each region. That's Phases 3-4, which will live in a proper
// Ghidra Analyzer rather than this one-shot script.
//
// @category L3902
// @keybinding
// @menupath Tools.L3902.Setup banking model
// @toolbar
//
// Usage (headless):
//   analyzeHeadless <project> <name> -process <fw> -postScript L3902BankingSetup.java
// Usage (GUI):
//   Script Manager -> L3902 -> L3902BankingSetup -> Run

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class L3902BankingSetup extends GhidraScript {

    // The four runtime banking configurations, identified by the file
    // offsets of the four physical 8 KiB banks each one maps into the
    // swappable region $0200-$7FFF. Per the contributor's diagram in
    // binary/banking-configurations.png.
    //
    // Index: [config_index][window_index]
    //   window_index 0 = B0 ($0200-$1FFF)  (special: 7.5 KiB, starts at $0200)
    //   window_index 1 = B2 ($2000-$3FFF)  (8 KiB)
    //   window_index 2 = B4 ($4000-$5FFF)  (8 KiB)
    //   window_index 3 = B6 ($6000-$7FFF)  (8 KiB)
    //
    // Value -1L for the cfg2/B6 "INX" cell — that selection isn't a
    // physical ROM bank, so the overlay there gets filled with $FF.
    private static final long[][] CFG_BANK_OFFSETS = {
        { 0x00000L, 0x02000L, 0x04000L, 0x0E000L }, // cfg1: ROM0/ROM2/ROM4/ROME
        { 0x08000L, 0x0A000L, 0x0C000L,       -1L }, // cfg2: ROM8/ROMA/ROMC/INX
        { 0x10000L, 0x12000L, 0x14000L, 0x16000L }, // cfg3: ROM10/ROM12/ROM14/ROM16
        { 0x18000L, 0x1A000L, 0x1C000L, 0x1E000L }, // cfg4: ROM18/ROM1A/ROM1C/ROM1E
    };

    // Per-window logical start addresses and lengths in the CPU view.
    private static final long[] WINDOW_STARTS  = { 0x0200L, 0x2000L, 0x4000L, 0x6000L };
    private static final long[] WINDOW_LENGTHS = { 0x1E00L, 0x2000L, 0x2000L, 0x2000L };

    // BSR0 immediate-value to configuration mapping. Each switch_rom_cfgX
    // function writes a known BSR0 value as its first instruction; the
    // contributor's table maps those values to configurations. (Mapping
    // derived empirically from the four 13-byte switch functions found
    // in the reference firmware at file offsets 0x06000-0x06033.)
    private static final java.util.Map<Integer, Integer> BSR0_TO_CFG;
    static {
        java.util.Map<Integer, Integer> m = new java.util.HashMap<>();
        m.put(0x7C, 1); // Cfg1 — ROM0  in B0
        m.put(0x70, 2); // Cfg2 — ROM8  in B0 (post-reset)
        m.put(0x74, 3); // Cfg3 — ROM10 in B0
        m.put(0x78, 4); // Cfg4 — ROM18 in B0
        BSR0_TO_CFG = java.util.Collections.unmodifiableMap(m);
    }

    // Pattern for a switch_rom_cfgX function: four sequential STI writes
    // to BSR0..BSR3 (the four swappable windows; BSR4..BSR7 are the
    // always-mapped windows the firmware never reprograms after init),
    // followed by RTS. Total 13 bytes:
    //   B2 ?? 18  B2 ?? 19  B2 ?? 1A  B2 ?? 1B  60
    private static final int[] SWITCH_PATTERN_BYTES = {
        0xB2, 0x00, 0x18, 0xB2, 0x00, 0x19, 0xB2, 0x00, 0x1A, 0xB2, 0x00, 0x1B,
        0x60,
    };
    private static final boolean[] SWITCH_PATTERN_FIXED = {
        true,  false, true,  true,  false, true,  true,  false, true,  true,  false, true,
        true,
    };
    private static final int SWITCH_PATTERN_LEN = SWITCH_PATTERN_BYTES.length; // 13

    @Override
    public void run() throws Exception {
        LanguageID lang = currentProgram.getLanguageID();
        if (!lang.toString().startsWith("RockwellL39")) {
            popup("L3902BankingSetup: language is " + lang
                    + ", expected RockwellL39:LE:16:default. Aborting.");
            return;
        }

        Memory mem = currentProgram.getMemory();
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // --- Step 1: read the full firmware from disk.
        // BinaryLoader's FileBytes is clipped to the 64 KiB address space,
        // so we can't get banks 8-15 (file 0x10000-0x1FFFF) out of it. Read
        // the original file directly via getExecutablePath() (or via an
        // explicit override passed as a script argument).
        String[] args = getScriptArgs();
        File fwFile;
        if (args.length > 0) {
            fwFile = new File(args[0]);
        } else {
            String execPath = currentProgram.getExecutablePath();
            if (execPath == null || execPath.isEmpty()) {
                popup("L3902BankingSetup: program has no executable path. "
                        + "Pass the firmware file as the first script "
                        + "argument: -postScript L3902BankingSetup.java <path>.");
                return;
            }
            fwFile = new File(execPath);
        }
        if (!fwFile.canRead()) {
            popup("L3902BankingSetup: cannot read firmware file at "
                    + fwFile.getAbsolutePath());
            return;
        }
        byte[] fwBytes = Files.readAllBytes(fwFile.toPath());
        long fileLen = fwBytes.length;
        if (fileLen < 0x20000L) {
            popup(String.format("L3902BankingSetup: firmware is only 0x%X "
                    + "bytes; need at least 0x20000 (128 KiB) to host the "
                    + "four configurations. Aborting.", fileLen));
            return;
        }
        println(String.format("Firmware: %s (0x%X bytes, %d KiB)",
                fwFile.getName(), fileLen, fileLen / 1024));

        // --- Step 2: create overlays for cfg1..cfg4.
        int overlaysCreated = 0;
        for (int cfgIdx = 0; cfgIdx < 4; cfgIdx++) {
            String name = "cfg" + (cfgIdx + 1);
            if (mem.getBlock(name) != null) {
                println("  skipping " + name + " — already exists");
                continue;
            }
            createCfgOverlay(mem, ram, name, cfgIdx, fwBytes);
            overlaysCreated++;
        }
        println("Created " + overlaysCreated + " configuration overlay(s).");

        // --- Step 3: locate the four switch_rom_cfgX entry points.
        List<SwitchHit> hits = findSwitchFunctions(mem, ram);
        println("Found " + hits.size() + " switch_rom_cfg candidate(s).");
        for (SwitchHit h : hits) {
            String values = bsrValuesString(h.bsrValues);
            int recognisedCfg = recogniseCfg(h.bsrValues);
            String name = (recognisedCfg > 0)
                    ? ("switch_rom_cfg" + recognisedCfg)
                    : ("switch_rom_cfg_" + h.address.toString());
            // Create / rename function.
            Function f = currentProgram.getListing().getFunctionAt(h.address);
            if (f == null) {
                createFunction(h.address, name);
                f = currentProgram.getListing().getFunctionAt(h.address);
            }
            if (f != null) {
                f.setName(name, SourceType.IMPORTED);
                String comment = "L3902 banking-configuration switch.\n"
                        + "Writes to BSR0..BSR7 (in order):\n  " + values
                        + (recognisedCfg > 0
                                ? "\nIdentified as Cfg" + recognisedCfg
                                  + (recognisedCfg == 2 ? " (post-reset)." : ".")
                                : "\nConfiguration not yet identified — see "
                                  + "binary/banking-configurations.png.");
                f.setComment(comment);
            }
            println(String.format("  %s @ %s  values=%s  cfg=%d",
                    name, h.address, values, recognisedCfg));
        }

        println("Phase 1+2 complete. Phase 3 (config propagation) will arrive "
                + "as a separate Analyzer.");
    }

    // ---------------------------------------------------------------
    // Overlay creation
    // ---------------------------------------------------------------

    private void createCfgOverlay(Memory mem, AddressSpace ram, String name,
            int cfgIdx, byte[] fwBytes) throws Exception {
        long[] bankOffsets = CFG_BANK_OFFSETS[cfgIdx];

        // First create one initialised overlay block at $0200, length
        // 0x7E00, fully filled with $FF (reflects unused EPROM bytes
        // and the cfg2/B6 "INX" hole). Then `setBytes` the four bank
        // contents over it.
        Address start = ram.getAddress(WINDOW_STARTS[0]);
        long totalLen = (WINDOW_STARTS[3] + WINDOW_LENGTHS[3]) - WINDOW_STARTS[0];
        MemoryBlock block = mem.createInitializedBlock(name, start, totalLen,
                (byte) 0xFF, monitor, /*overlay=*/true);
        block.setRead(true);
        block.setWrite(false);
        block.setExecute(true);
        block.setComment("L3902 runtime banking configuration "
                + name.substring(3) + ". See binary/elsa_microlink_336tqv.md "
                + "and binary/banking-configurations.png for the bank layout.");

        AddressSpace ovSpace = block.getStart().getAddressSpace();

        // Copy each of the four 8 KiB windows into the overlay.
        for (int win = 0; win < 4; win++) {
            long fileOff = bankOffsets[win];
            if (fileOff < 0) {
                continue; // INX cell — leave the $FF fill in place
            }
            long winStart = WINDOW_STARTS[win];
            long winLen = WINDOW_LENGTHS[win];

            // For the B0 window only, the first 0x200 bytes of the
            // physical bank aren't visible at runtime (covered by
            // pages 0+1 on-chip RAM in the base address space). Skip
            // the first 0x200 bytes of the bank when copying.
            long bankReadOff = (win == 0) ? (fileOff + 0x200L) : fileOff;

            int srcOff = Math.toIntExact(bankReadOff);
            int len    = Math.toIntExact(winLen);
            byte[] buf = Arrays.copyOfRange(fwBytes, srcOff, srcOff + len);
            mem.setBytes(ovSpace.getAddress(winStart), buf);
        }
    }

    // ---------------------------------------------------------------
    // switch_rom_cfgX detection
    // ---------------------------------------------------------------

    private static class SwitchHit {
        Address address;
        int[] bsrValues = new int[4]; // BSR0..BSR3
    }

    private List<SwitchHit> findSwitchFunctions(Memory mem, AddressSpace ram)
            throws Exception {
        List<SwitchHit> hits = new ArrayList<>();
        // The switch_rom_cfgX functions live in ROM6 (the persistent
        // dispatcher bank). At boot time the BinaryLoader maps file
        // bytes 1:1 to logical addresses, so ROM6's bytes are at
        // logical $6000-$7FFF. Scan that region for the 13-byte
        // four-STI-plus-RTS pattern.
        long scanStart = 0x6000L;
        long scanEnd   = 0x7FFFL - SWITCH_PATTERN_LEN;
        for (long addr = scanStart; addr <= scanEnd; addr++) {
            if (matchesPattern(mem, ram, addr)) {
                SwitchHit hit = new SwitchHit();
                hit.address = ram.getAddress(addr);
                for (int i = 0; i < 4; i++) {
                    int valueOffset = i * 3 + 1; // index of imm byte in pattern
                    hit.bsrValues[i] = mem.getByte(ram.getAddress(addr + valueOffset)) & 0xFF;
                }
                hits.add(hit);
                addr += SWITCH_PATTERN_LEN - 1; // skip past this hit
            }
        }
        return hits;
    }

    private boolean matchesPattern(Memory mem, AddressSpace ram, long addr) {
        try {
            for (int i = 0; i < SWITCH_PATTERN_LEN; i++) {
                if (!SWITCH_PATTERN_FIXED[i]) {
                    continue;
                }
                int got = mem.getByte(ram.getAddress(addr + i)) & 0xFF;
                if (got != SWITCH_PATTERN_BYTES[i]) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String bsrValuesString(int[] vals) {
        StringBuilder sb = new StringBuilder("{ ");
        for (int i = 0; i < vals.length; i++) {
            sb.append(String.format("$%02X", vals[i]));
            if (i < vals.length - 1) sb.append(", ");
        }
        sb.append(" }");
        return sb.toString();
    }

    private static int recogniseCfg(int[] vals) {
        // BSR0's value is unique per configuration in this firmware. See
        // the BSR0_TO_CFG table.
        Integer cfg = BSR0_TO_CFG.get(vals[0]);
        return (cfg == null) ? 0 : cfg;
    }
}
