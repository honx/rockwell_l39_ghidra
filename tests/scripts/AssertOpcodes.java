// Headless assertion script for test_02_opcode_decode.sh.
//
// Disassembles an opcode-fixture binary and verifies that each instruction
// decodes to the expected mnemonic at the expected address. The fixture
// places instructions back-to-back starting at $FF00; this script reads an
// expectations file (passed via the analyzeHeadless -propertiesPath
// mechanism via a sidecar file) and asserts on each.
//
// Failure mode: print the offending disassembly and call exit(1) so that
// analyzeHeadless surfaces a non-zero exit status to the shell driver.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class AssertOpcodes extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("AssertOpcodes: missing expectations-file path argument");
            System.exit(2);
        }
        String expectFile = args[0];

        // Read expectations: each non-blank, non-comment line is "ADDR  MNEMONIC".
        List<String[]> expectations = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(expectFile))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\\s+", 2);
                if (parts.length < 2) {
                    printerr("AssertOpcodes: malformed expectation '" + line + "'");
                    System.exit(2);
                }
                expectations.add(parts);
            }
        }

        // Force a disassembly attempt at each expected address. Linear
        // disassembly stops at unconditional control-flow boundaries (BRA,
        // JMP indirect, RTS, ...) and the fixture deliberately contains
        // such instructions, so we have to seed each address ourselves.
        Listing listing = currentProgram.getListing();
        int failures = 0;
        for (String[] e : expectations) {
            long addr = Long.parseLong(e[0].replace("0x", ""), 16);
            String want = e[1].toLowerCase();
            Address a = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(addr);
            if (listing.getInstructionAt(a) == null) {
                disassemble(a);
            }
            Instruction insn = listing.getInstructionAt(a);
            String got = (insn == null) ? "<no-instruction>" : insn.toString().toLowerCase();
            // Expectations are mnemonic-only ('LDA') or mnemonic+operand
            // ('LDA #0x42'); we accept either as a prefix-match against the
            // full instruction string to keep operand-formatting tolerant.
            if (!got.startsWith(want)) {
                printerr(String.format("MISMATCH at $%04X: expected '%s', got '%s'",
                        addr, want, got));
                failures++;
            } else {
                println(String.format("OK $%04X: %s", addr, got));
            }
        }

        if (failures > 0) {
            printerr(String.format("AssertOpcodes: %d of %d expectations failed",
                    failures, expectations.size()));
            System.exit(1);
        }
        println(String.format("AssertOpcodes: all %d expectations satisfied", expectations.size()));
    }
}
