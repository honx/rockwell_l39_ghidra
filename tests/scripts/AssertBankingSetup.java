// Headless assertion script for test_04_banking_setup.sh.
//
// Asserts that L3902BankingSetup.java created the expected overlay
// blocks and identified the four switch_rom_cfgX functions correctly.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

import java.util.HashMap;
import java.util.Map;

public class AssertBankingSetup extends GhidraScript {

    private int failures = 0;

    private void check(boolean cond, String desc) {
        if (cond) {
            println("OK  " + desc);
        } else {
            printerr("FAIL " + desc);
            failures++;
        }
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // 1. Each cfg overlay block should exist, be initialised, and start at $0200.
        String[] cfgNames = { "cfg1", "cfg2", "cfg3", "cfg4" };
        for (String name : cfgNames) {
            MemoryBlock blk = mem.getBlock(name);
            check(blk != null, "overlay block '" + name + "' exists");
            if (blk == null) continue;
            check(blk.isInitialized(),
                    name + " is initialised");
            check(blk.getStart().getOffset() == 0x0200L,
                    name + " starts at $0200 (got $" +
                            Long.toHexString(blk.getStart().getOffset()).toUpperCase() + ")");
            check(blk.getSize() == 0x7E00L,
                    name + " size is 0x7E00 (got 0x" +
                            Long.toHexString(blk.getSize()).toUpperCase() + ")");
        }

        // 2. Spot-check overlay contents:
        //    - cfg2:$2000 should match file 0xA000 (start of ROMA, mapped to B2 in cfg2)
        //    - cfg1:$6000 should match file 0xE000 (start of ROME, mapped to B6 in cfg1)
        //    - cfg2:$4000 should match file 0xC000 (start of ROMC, mapped to B4 in cfg2)
        spotCheck(mem, "cfg2", 0x2000L,
                new byte[] { (byte)0x37, (byte)0x03, (byte)0xCD, (byte)0x3D,
                             (byte)0x03, (byte)0x90, (byte)0x85, (byte)0xAD },
                "cfg2:$2000 = first 8 bytes of ROMA");
        spotCheck(mem, "cfg2", 0x4000L,
                new byte[] { (byte)0x9C, (byte)0xF0, (byte)0x01, (byte)0x60,
                             (byte)0xF2, (byte)0x6C, (byte)0x03, (byte)0x40 },
                "cfg2:$4000 = first 8 bytes of ROMC");
        spotCheck(mem, "cfg1", 0x6000L,
                new byte[] { (byte)0x56, (byte)0x65, (byte)0x72, (byte)0x2E,
                             (byte)0x20, (byte)0x00, (byte)0x20, (byte)0x76 },
                "cfg1:$6000 = first 8 bytes of ROME (\"Ver. \\0 v\")");

        // 3. The four switch_rom_cfgX functions exist at the expected
        // addresses (in the boot-time view).
        Map<String, Long> expectedFns = new HashMap<>();
        expectedFns.put("switch_rom_cfg2", 0x6000L);
        expectedFns.put("switch_rom_cfg3", 0x600DL);
        expectedFns.put("switch_rom_cfg4", 0x601AL);
        expectedFns.put("switch_rom_cfg1", 0x6027L);

        FunctionIterator fi = listing.getFunctions(true);
        Map<String, Address> seen = new HashMap<>();
        while (fi.hasNext()) {
            Function f = fi.next();
            if (f.getName().startsWith("switch_rom_cfg")) {
                seen.put(f.getName(), f.getEntryPoint());
            }
        }

        for (Map.Entry<String, Long> e : expectedFns.entrySet()) {
            String wantName = e.getKey();
            long wantAddr = e.getValue();
            Address gotAddr = seen.get(wantName);
            check(gotAddr != null && gotAddr.getOffset() == wantAddr,
                    String.format("function %s at $%04X (got %s)",
                            wantName, wantAddr,
                            gotAddr == null ? "<missing>" : "$" +
                                    Long.toHexString(gotAddr.getOffset()).toUpperCase()));
        }

        // 4. The rom6 overlay should exist (Phase 3) and have the expected size.
        MemoryBlock rom6 = mem.getBlock("rom6");
        check(rom6 != null, "overlay block 'rom6' exists (Phase 3)");
        if (rom6 != null) {
            check(rom6.isInitialized(), "rom6 is initialised");
            check(rom6.getStart().getOffset() == 0xE000L,
                    "rom6 starts at $E000 (got $" +
                            Long.toHexString(rom6.getStart().getOffset()).toUpperCase() + ")");
            check(rom6.getSize() == 0x2000L,
                    "rom6 size is 0x2000 (got 0x" +
                            Long.toHexString(rom6.getSize()).toUpperCase() + ")");
            // Spot-check: rom6:$E7B6 should be the third-stage boot stub
            // (file 0x67B6), starting with SEI ($78).
            byte[] got = new byte[1];
            mem.getBytes(rom6.getStart().getAddressSpace().getAddress(0xE7B6L), got);
            check((got[0] & 0xFF) == 0x78,
                    String.format("rom6:$E7B6 = SEI byte $78 (got $%02X)", got[0] & 0xFF));
        }

        // 5. The Phase-3 reference resolver should have added many
        // ROM6 redirects. Count them: any reference whose target is in
        // the boot-time-view ROM6 region $6000-$7FFF and whose source
        // also has a sibling reference to the corresponding $E000-$FFFF
        // address (i.e., the original encoded target) is one of our
        // redirects. We accept anything >= 30 as evidence the resolver
        // ran and found real call sites — the actual count on the
        // reference firmware is around 149.
        int rom6Redirects = countRom6Redirects();
        check(rom6Redirects >= 30,
                String.format("ROM6 redirects added (>=30): got %d", rom6Redirects));

        // 6. Phase-4 config propagation: every cfgN overlay should now
        // be the target of a meaningful number of references from
        // default-RAM instructions. Reference firmware sees roughly:
        //   cfg1: 460, cfg2: 473, cfg3: 622, cfg4: 570 = 2125 total
        // We use loose lower bounds since the actual count varies with
        // analyser heuristics; we mainly want to know that all four
        // configs got tagged with non-trivial reference counts.
        int[] cfgRefCounts = countCfgReferences();
        check(cfgRefCounts[1] >= 100, String.format("cfg1 refs >= 100 (got %d)", cfgRefCounts[1]));
        check(cfgRefCounts[2] >= 100, String.format("cfg2 refs >= 100 (got %d)", cfgRefCounts[2]));
        check(cfgRefCounts[3] >= 100, String.format("cfg3 refs >= 100 (got %d)", cfgRefCounts[3]));
        check(cfgRefCounts[4] >= 100, String.format("cfg4 refs >= 100 (got %d)", cfgRefCounts[4]));
        int totalCfgRefs = cfgRefCounts[1] + cfgRefCounts[2] + cfgRefCounts[3] + cfgRefCounts[4];
        check(totalCfgRefs >= 1000,
                String.format("total cfgN refs >= 1000 (got %d)", totalCfgRefs));

        // 7. Spot-check: the third-stage boot stub at $67B6 establishes
        // cfg2. The very first instruction *after* its eight BSR writes
        // is at $67E5 (= file 0x67E5, where the post-BSR-establishment
        // peripheral init continues). The propagator should have
        // tagged that address as belonging to cfg2 — verifiable by
        // looking at any subsequent reference into the swappable bank
        // and checking it has a cfg2 redirect.
        // (Generic spot-check: at least one default-RAM instruction
        // has a cfg2 reference.)
        check(cfgRefCounts[2] > 0, "at least one cfg2 reference exists");

        if (failures > 0) {
            printerr(String.format("AssertBankingSetup: %d assertion(s) failed", failures));
            System.exit(1);
        }
        println("AssertBankingSetup: all assertions passed");
    }

    private int countRom6Redirects() throws Exception {
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int count = 0;
        for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
            if (!ins.getAddress().getAddressSpace().equals(ram)) continue;
            // For each instruction, look for the (original $Exxx ref,
            // redirected $6xxx ref) pair — both pointing into default RAM.
            boolean hasOriginal = false;
            boolean hasRedirect = false;
            for (Reference r : ins.getReferencesFrom()) {
                if (!r.getToAddress().getAddressSpace().equals(ram)) continue;
                long off = r.getToAddress().getOffset();
                if (off >= 0xE000L && off <= 0xFFFFL) hasOriginal = true;
                if (off >= 0x6000L && off <= 0x7FFFL) hasRedirect = true;
            }
            if (hasOriginal && hasRedirect) count++;
        }
        return count;
    }

    private void spotCheck(Memory mem, String overlayName, long offset,
            byte[] expected, String desc) throws Exception {
        MemoryBlock blk = mem.getBlock(overlayName);
        if (blk == null) {
            check(false, desc + " — overlay block missing");
            return;
        }
        AddressSpace sp = blk.getStart().getAddressSpace();
        byte[] got = new byte[expected.length];
        mem.getBytes(sp.getAddress(offset), got);
        boolean match = true;
        StringBuilder sb = new StringBuilder(desc + ": got");
        for (int i = 0; i < got.length; i++) {
            sb.append(String.format(" %02X", got[i] & 0xFF));
            if (got[i] != expected[i]) match = false;
        }
        check(match, sb.toString());
    }

    /**
     * Count cross-references whose target lies in each cfgN overlay's
     * address space. Returns a 5-element array: [unused, cfg1, cfg2, cfg3, cfg4].
     */
    private int[] countCfgReferences() throws Exception {
        int[] counts = new int[5];
        for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
            for (Reference r : ins.getReferencesFrom()) {
                String spaceName = r.getToAddress().getAddressSpace().getName();
                if (spaceName.startsWith("cfg") && spaceName.length() == 4) {
                    char c = spaceName.charAt(3);
                    if (c >= '1' && c <= '4') {
                        counts[c - '0']++;
                    }
                }
            }
        }
        return counts;
    }
}
