// Headless assertion script for test_03_e2e_firmware.sh.
//
// Imports the ELSA reference firmware, runs auto-analysis, and asserts on
// invariants we know from manual inspection of the image (see the writeup
// at binary/elsa_microlink_336tqv.md):
//
//   * Reset vector at $FFFE reads $FFC0.
//   * Stage-1 boot stub at $FFC0: SEI / STI #$70,$1B / JMP $6200.
//     ($1B is BSR3 — programs it to expose physical bank 0 at $6000-$7FFF.)
//   * Stage-2 boot stub at $0200: STI #$73,$1F / JMP $E7B6.
//     ($1F is BSR7 — programs it to expose physical bank 3 at $E000-$FFFF.
//     We can read $0200 directly because BinaryLoader maps the first 64 KiB
//     of the file at $0000-$FFFF 1:1; bank 0 *is* file 0x0000-0x1FFF.)
//   * Stage-3 hardware initialiser at file offset 0x67B6 begins SEI / STI
//     #$00,$32 / CLD. (Reachable as $67B6 in the boot-time view because
//     bank 3 = file 0x6000-0x7FFF, which is also where $E000-$FFFF reads
//     after stage 2 swaps BSR7.)
//   * Runtime IRQ vectors at file 0x7FE0-0x7FFF (visible at logical
//     $7FE0-$7FFF in the boot-time view) point to the runtime IRQ
//     dispatcher block: NMI -> $E2E7, RESET -> $E7B6.
//   * The mnemonic distribution shows R65C19-specific opcodes — the binary
//     should contain at least 100 of STI, 50 of BAR+BAS combined, and 50 of
//     SBA+RBA combined. Exact counts may shift with analyser changes; we
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

        // Stage-2 boot stub at file 0x0200 (= logical $0200 with 1:1 load).
        disassemble(ram.getAddress(0x0200L));
        String s_0200 = insnAt(0x0200).toLowerCase();
        String s_0203 = insnAt(0x0203).toLowerCase();
        check(s_0200.startsWith("sti #0x73,0x1f"),     "$0200 = STI #$73,$1F (got: " + s_0200 + ")");
        check(s_0203.startsWith("jmp 0xe7b6"),         "$0203 = JMP $E7B6 (got: " + s_0203 + ")");

        // Stage-3 hardware initialiser at file 0x67B6.
        disassemble(ram.getAddress(0x67B6L));
        String s_67b6 = insnAt(0x67B6).toLowerCase();
        String s_67b7 = insnAt(0x67B7).toLowerCase();
        String s_67ba = insnAt(0x67BAL).toLowerCase();
        check(s_67b6.startsWith("sei"),                "$67B6 = SEI (got: " + s_67b6 + ")");
        check(s_67b7.startsWith("sti #0x0,0x32"),      "$67B7 = STI #$00,$32 (got: " + s_67b7 + ")");
        check(s_67ba.startsWith("cld"),                "$67BA = CLD (got: " + s_67ba + ")");

        // The third-stage stub establishes Cfg2 with a fixed BSR sequence
        // (per binary/elsa_microlink_336tqv.md "runtime banking model"):
        //   BSR0:=$70 BSR1:=$71 BSR2:=$72 BSR3:=$77 BSR4:=$B0 BSR5:=$B1 BSR6:=$B2 BSR7:=$73
        // The eight STI writes start at file 0x67CD (after the port/timer
        // setup that precedes them in the third-stage stub). Verify the
        // byte sequence on the eight three-byte STI instructions.
        long[] cfg2Bsr = { 0x70, 0x71, 0x72, 0x77, 0xB0, 0xB1, 0xB2, 0x73 };
        long bsrSeqBase = 0x67CDL;
        boolean cfg2_ok = true;
        StringBuilder cfg2_msg = new StringBuilder(String.format("Cfg2 BSR setup at $%04X:", bsrSeqBase));
        for (int i = 0; i < 8; i++) {
            long pc = bsrSeqBase + 3L * i;
            int b0 = mem.getByte(ram.getAddress(pc))     & 0xFF;
            int b1 = mem.getByte(ram.getAddress(pc + 1)) & 0xFF;
            int b2 = mem.getByte(ram.getAddress(pc + 2)) & 0xFF;
            // Each entry must be the STI opcode ($B2), the expected value, the BSR address ($18+i).
            int wantBsrAddr = 0x18 + i;
            boolean ok = (b0 == 0xB2) && (b1 == (int)cfg2Bsr[i]) && (b2 == wantBsrAddr);
            cfg2_ok &= ok;
            cfg2_msg.append(String.format(" BSR%d=$%02X%s", i, cfg2Bsr[i], ok ? "" : "!"));
        }
        check(cfg2_ok, cfg2_msg.toString());

        // Runtime IRQ vectors live at the top of bank 3 (file 0x7FE0-0x7FFF),
        // visible at logical $7FE0-$7FFF in the boot-time view.
        int v_reset = (mem.getByte(ram.getAddress(0x7FFEL)) & 0xFF)
                | ((mem.getByte(ram.getAddress(0x7FFFL)) & 0xFF) << 8);
        int v_nmi   = (mem.getByte(ram.getAddress(0x7FFCL)) & 0xFF)
                | ((mem.getByte(ram.getAddress(0x7FFDL)) & 0xFF) << 8);
        check(v_reset == 0xE7B6, String.format("runtime RESET vector (file 0x7FFE) = $E7B6 (got $%04X)", v_reset));
        check(v_nmi   == 0xE2E7, String.format("runtime NMI vector (file 0x7FFC) = $E2E7 (got $%04X)", v_nmi));

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
