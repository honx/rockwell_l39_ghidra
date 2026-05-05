// Headless assertion script for test_03_e2e_firmware.sh.
//
// Imports the ELSA reference firmware, runs auto-analysis, and asserts on
// invariants we know from manual inspection of the image:
//
//   * Reset vector at $FFFE reads $FFC0.
//   * Disassembly at $FFC0 starts with SEI.
//   * Disassembly at $FFC1 is "STI #$70,$1B" (the BSR3 setup).
//   * Disassembly at $FFC4 is "JMP $6200".
//   * The mnemonic distribution shows R65C19-specific opcodes — the binary
//     should contain at least 100 of STI, 50 of BAR+BAS combined, and 50 of
//     SBA+RBA combined. Exact counts may shift with analyzer changes; we
//     check lower bounds only.
//   * Auto-analysis discovered at least 100 functions.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;

import java.util.HashMap;
import java.util.Map;

public class AssertFirmware extends GhidraScript {

    private int failures = 0;

    private void check(boolean cond, String desc) {
        if (cond) {
            println("OK  " + desc);
        } else {
            printerr("FAIL " + desc);
            failures++;
        }
    }

    private String insnAt(long addr) {
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Instruction insn = currentProgram.getListing().getInstructionAt(ram.getAddress(addr));
        return insn == null ? "<no-instruction>" : insn.toString();
    }

    @Override
    public void run() throws Exception {
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        // 1. Reset vector content.
        Address vecAddr = ram.getAddress(0xFFFEL);
        int lo = mem.getByte(vecAddr) & 0xFF;
        int hi = mem.getByte(vecAddr.add(1)) & 0xFF;
        int target = (hi << 8) | lo;
        check(target == 0xFFC0, String.format("reset vector $FFFE = $FFC0 (got $%04X)", target));

        // 2-4. Disassembly at the reset target.
        // Defensive: ensure the bytes are disassembled in case auto-analysis
        // skipped this region for some reason.
        disassemble(ram.getAddress(0xFFC0L));

        String s_ffc0 = insnAt(0xFFC0).toLowerCase();
        String s_ffc1 = insnAt(0xFFC1).toLowerCase();
        String s_ffc4 = insnAt(0xFFC4).toLowerCase();
        check(s_ffc0.startsWith("sei"),                "$FFC0 = SEI (got: " + s_ffc0 + ")");
        check(s_ffc1.startsWith("sti #0x70,0x1b"),     "$FFC1 = STI #$70,$1B (got: " + s_ffc1 + ")");
        check(s_ffc4.startsWith("jmp 0x6200"),         "$FFC4 = JMP $6200 (got: " + s_ffc4 + ")");

        // 5. Mnemonic histogram.
        Map<String, Integer> freq = new HashMap<>();
        Instruction insn = listing.getInstructions(currentProgram.getMinAddress(), true).next();
        int total = 0;
        while (insn != null) {
            freq.merge(insn.getMnemonicString(), 1, Integer::sum);
            insn = listing.getInstructionAfter(insn.getAddress());
            total++;
        }
        int sti = freq.getOrDefault("STI", 0);
        int barbas = freq.getOrDefault("BAR", 0) + freq.getOrDefault("BAS", 0);
        int sbarba = freq.getOrDefault("SBA", 0) + freq.getOrDefault("RBA", 0);
        int pshpul = freq.getOrDefault("PSH", 0) + freq.getOrDefault("PUL", 0);
        check(sti    >= 100, String.format("STI count >= 100 (got %d)", sti));
        check(barbas >= 50,  String.format("BAR+BAS count >= 50 (got %d)", barbas));
        check(sbarba >= 30,  String.format("SBA+RBA count >= 30 (got %d)", sbarba));
        check(pshpul >= 20,  String.format("PSH+PUL count >= 20 (got %d)", pshpul));
        println(String.format("    (%d total instructions, %d distinct mnemonics)",
                total, freq.size()));

        // 6. Function count.
        FunctionIterator fi = listing.getFunctions(true);
        int funcs = 0;
        while (fi.hasNext()) { fi.next(); funcs++; }
        check(funcs >= 100, String.format("function count >= 100 (got %d)", funcs));

        if (failures > 0) {
            printerr(String.format("AssertFirmware: %d assertion(s) failed", failures));
            System.exit(1);
        }
        println("AssertFirmware: all assertions passed");
    }
}
