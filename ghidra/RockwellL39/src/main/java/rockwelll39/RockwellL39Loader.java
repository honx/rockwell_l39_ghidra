/* Loader for Rockwell C40 / L39 / L3902 modem-MCU firmware images.
 *
 * Convention: the first 64 KiB of the image maps 1:1 to the CPU address
 * space at reset (the L3902 BSR registers default such that logical
 * $0000-$FFFF reads from physical bank 0). On-chip RAM, I/O, and CRC
 * locations overlay parts of that range at runtime; this loader treats
 * the whole 64 KiB block as ROM-from-file and additionally creates
 * volatile, uninitialized blocks for the I/O and RAM regions so users
 * can label them.
 *
 * Images larger than 64 KiB (typical: 128 KiB / 256 KiB / 512 KiB)
 * have their additional 64 KiB chunks loaded as overlay blocks named
 * BANK_HIGH_n at the same logical $0000-$FFFF address. Switching to
 * the overlay in Ghidra's listing then disassembles that physical
 * 64 KiB window.
 */
package rockwelll39;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RockwellL39Loader extends AbstractProgramWrapperLoader {

    private static final String LANGUAGE_ID = "RockwellL39:LE:16:default";
    private static final String COMPILER_ID = "default";

    @Override
    public String getName() {
        return "Rockwell C40/L39/L3902 firmware";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        long len = provider.length();
        // Accept any multiple of 8 KiB up to 512 KiB — covers single-bank
        // 8 KiB ROM dumps as well as fully-banked 128/256/512 KiB images.
        if (len < 0x2000 || len > 0x80000 || (len % 0x2000) != 0) {
            return Collections.emptyList();
        }
        List<LoadSpec> specs = new ArrayList<>(1);
        specs.add(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_ID), true));
        return specs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        Memory memory = program.getMemory();
        AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
        FlatProgramAPI api = new FlatProgramAPI(program, monitor);

        long fileLen = provider.length();
        long primaryLen = Math.min(fileLen, 0x10000L);

        try {
            createInitialized(memory, ram, "ROM", 0x0000L, provider, 0L, primaryLen, log);

            // Carve out on-chip I/O and RAM regions as separate, volatile
            // blocks. These are uninitialized so default to all-undefined; the
            // pspec attaches symbols (PORTA, BSR0, ...) to register addresses.
            createUninitialized(memory, ram, "IOREG",   0x0000L, 0x0040L, true,  false, log);
            createUninitialized(memory, ram, "HOSTBUS", 0x0020L, 0x0020L, true,  false, log);
            createUninitialized(memory, ram, "USART",   0x0033L, 0x000DL, true,  false, log);
            createUninitialized(memory, ram, "PAGE0",   0x0040L, 0x00C0L, false, false, log);
            createUninitialized(memory, ram, "STACK",   0x0100L, 0x0100L, false, false, log);
            createUninitialized(memory, ram, "PAGE2",   0x0200L, 0x0100L, false, false, log);
            createUninitialized(memory, ram, "PAGE3",   0x0300L, 0x0100L, false, false, log);
            createUninitialized(memory, ram, "PAGE4",   0x0400L, 0x0100L, false, false, log);
            createUninitialized(memory, ram, "PAGE5",   0x0500L, 0x00FEL, false, false, log);
            createUninitialized(memory, ram, "CRC",     0x05FEL, 0x0002L, true,  false, log);

            // Tag each 8 KiB bank as a label for cross-reference.
            SymbolTable st = program.getSymbolTable();
            for (int bank = 0; bank * 0x2000 < primaryLen; bank++) {
                Address bankAddr = ram.getAddress(bank * 0x2000L);
                st.createLabel(bankAddr, String.format("bank%d_start", bank), SourceType.IMPORTED);
            }

            // Fetch RESET vector ($FFFE little-endian) and mark as entry point.
            Address resetVecAddr = ram.getAddress(0xFFFEL);
            int lo = memory.getByte(resetVecAddr) & 0xFF;
            int hi = memory.getByte(resetVecAddr.add(1)) & 0xFF;
            int resetTarget = (hi << 8) | lo;
            if (resetTarget != 0xFFFF && resetTarget != 0x0000) {
                Address entry = ram.getAddress(resetTarget);
                api.addEntryPoint(entry);
                api.createFunction(entry, "_reset");
                log.appendMsg(String.format("Reset vector -> $%04X (file offset 0x%04X)",
                        resetTarget, resetTarget));
            } else {
                log.appendMsg("Reset vector is blank ($FFFF or $0000); not setting entry.");
            }

            // For images >64 KiB, load each additional 64 KiB chunk as an
            // overlay at $0000-$FFFF so users can switch between physical
            // halves of the firmware in the same address space.
            int overlayIdx = 1;
            for (long fileOff = 0x10000L; fileOff < fileLen; fileOff += 0x10000L) {
                long chunkLen = Math.min(0x10000L, fileLen - fileOff);
                String name = String.format("BANK_HIGH_%d", overlayIdx++);
                createOverlay(memory, ram, name, 0x0000L, provider, fileOff, chunkLen, log);
            }
        } catch (Exception e) {
            log.appendException(e);
            throw new IOException("Failed to load L39 firmware", e);
        }
    }

    private static void createInitialized(Memory memory, AddressSpace space, String name,
            long addr, ByteProvider provider, long fileOffset, long length, MessageLog log)
            throws Exception {
        Address start = space.getAddress(addr);
        try (InputStream is = provider.getInputStream(fileOffset)) {
            MemoryBlock blk = memory.createInitializedBlock(name, start, is, length,
                    TaskMonitor.DUMMY, false);
            blk.setRead(true);
            blk.setWrite(false);
            blk.setExecute(true);
            blk.setSourceName("Rockwell L39 firmware");
            blk.setComment("ROM image: file offset 0x" + Long.toHexString(fileOffset)
                    + ", length 0x" + Long.toHexString(length));
        } catch (Exception e) {
            log.appendMsg("Failed creating block " + name + ": " + e.getMessage());
            throw e;
        }
    }

    private static void createUninitialized(Memory memory, AddressSpace space, String name,
            long addr, long length, boolean volatil, boolean execute, MessageLog log)
            throws Exception {
        Address start = space.getAddress(addr);
        try {
            MemoryBlock blk = memory.createUninitializedBlock(name, start, length, false);
            blk.setRead(true);
            blk.setWrite(true);
            blk.setExecute(execute);
            blk.setVolatile(volatil);
        } catch (Exception e) {
            log.appendMsg("Failed creating block " + name + ": " + e.getMessage());
            throw e;
        }
    }

    private static void createOverlay(Memory memory, AddressSpace space, String name,
            long addr, ByteProvider provider, long fileOffset, long length, MessageLog log)
            throws Exception {
        Address start = space.getAddress(addr);
        try (InputStream is = provider.getInputStream(fileOffset)) {
            MemoryBlock blk = memory.createInitializedBlock(name, start, is, length,
                    TaskMonitor.DUMMY, true);
            blk.setRead(true);
            blk.setWrite(false);
            blk.setExecute(true);
            blk.setComment("Overlay bank: file offset 0x" + Long.toHexString(fileOffset)
                    + ", length 0x" + Long.toHexString(length));
        } catch (Exception e) {
            log.appendMsg("Failed creating overlay " + name + ": " + e.getMessage());
            throw e;
        }
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean loadIntoProgram) {
        return super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
    }
}
