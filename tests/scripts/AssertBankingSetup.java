// Headless assertion script for test_04_banking_setup.sh.
//
// Asserts that L3902BankingSetup.java created the expected overlay
// blocks and identified the four switch_rom_cfgX functions correctly.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

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

        if (failures > 0) {
            printerr(String.format("AssertBankingSetup: %d assertion(s) failed", failures));
            System.exit(1);
        }
        println("AssertBankingSetup: all assertions passed");
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
}
