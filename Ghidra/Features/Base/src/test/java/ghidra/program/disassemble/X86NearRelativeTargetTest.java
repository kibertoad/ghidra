/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.disassemble;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/**
 * Near relative transfers keep CS and wrap IP at 64K, so the target is
 * CS:((IP after the instruction + displacement) & 0xFFFF).
 */
public class X86NearRelativeTargetTest extends AbstractGenericTest {

	private static final String REAL = "x86:LE:16:Real Mode";
	private static final String PROTECTED = "x86:LE:16:Protected Mode";
	private static final String X86_32 = "x86:LE:32:default";

	private ProgramBuilder builder;

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	/**
	 * Creates a 64K code block at {@code blockStart} and, when {@code cs} is not null, sets
	 * realModeCS over it.
	 */
	private void load(String language, String blockStart, Integer cs) throws Exception {
		builder = new ProgramBuilder("NearTarget", language);
		builder.createMemory("code", blockStart, 0x10000);
		if (cs != null) {
			Address start = builder.addr(blockStart);
			builder.setRegisterValue("realModeCS", blockStart, start.add(0xffff).toString(), cs);
		}
	}

	/** Disassembles {@code bytes} at {@code at} and returns the linear flow target. */
	private long target(String at, String bytes) throws Exception {
		builder.setBytes(at, bytes);
		builder.disassemble(at, bytes.split(" ").length, false);
		Program program = builder.getProgram();
		Instruction insn = program.getListing().getInstructionAt(builder.addr(at));
		assertNotNull("no instruction at " + at, insn);
		Address[] flows = insn.getFlows();
		assertEquals(insn.toString(), 1, flows.length);
		return flows[0].getOffset();
	}

	// CS 0x1FF0 has base 0x1FF00, so its offsets 0x0100 and up lie past the linear 0x20000.

	@Test
	public void testJmpRel16AcrossLinear64kBoundary() throws Exception {
		load(REAL, "1ff0:0000", 0x1ff0);
		// JMP 0x0103 at 1FF0:00F0 (linear 0x1FFF0)
		assertEquals(0x20003L, target("1ff0:00f0", "e9 10 00"));
	}

	@Test
	public void testCallRel16AcrossLinear64kBoundary() throws Exception {
		load(REAL, "1ff0:0000", 0x1ff0);
		// CALL 0x0103 at 1FF0:00F0
		assertEquals(0x20003L, target("1ff0:00f0", "e8 10 00"));
	}

	@Test
	public void testJccRel16BackAcrossLinear64kBoundary() throws Exception {
		load(REAL, "1ff0:0000", 0x1ff0);
		// JZ 0x00F0 at 1FF0:0110 (linear 0x20010)
		assertEquals(0x1fff0L, target("1ff0:0110", "0f 84 dc ff"));
	}

	@Test
	public void testJmpRel16WrapsIpInsideSegment() throws Exception {
		load(REAL, "1ff0:0000", 0x1ff0);
		// JMP 0xF000 at 1FF0:0010: IP 0x0013 + 0xEFED wraps to 0xF000
		assertEquals(0x2ef00L, target("1ff0:0010", "e9 ed ef"));
	}

	@Test
	public void testJmpRel8WrapsIpInsideSegment() throws Exception {
		load(REAL, "2000:0000", 0x2000);
		// JMP 0x0012 at 2000:FFF0: IP 0xFFF2 + 0x20 wraps to 0x0012
		assertEquals(0x20012L, target("2000:fff0", "eb 20"));
	}

	@Test
	public void testLoopRel8WrapsIpInsideSegment() throws Exception {
		load(REAL, "2000:0000", 0x2000);
		// LOOP 0xFFF0 at 2000:0000: IP 0x0002 - 0x12 wraps to 0xFFF0
		assertEquals(0x2fff0L, target("2000:0000", "e2 ee"));
	}

	@Test
	public void testJmpRel8AcrossLinear64kBoundary() throws Exception {
		load(REAL, "1ff0:0000", 0x1ff0);
		// JMP 0x0102 at 1FF0:00F0
		assertEquals(0x20002L, target("1ff0:00f0", "eb 10"));
	}

	@Test
	public void testUnknownCsKeepsLinearPageWrap() throws Exception {
		load(REAL, "1ff0:0000", null);
		// Without realModeCS the code segment is taken to start at the instruction's 64K page
		assertEquals(0x10003L, target("1ff0:00f0", "e9 10 00"));
		assertEquals(0x1ef00L, target("1ff0:0010", "e9 ed ef"));
	}

	@Test
	public void testProtectedModeRel8WrapsInsideSelector() throws Exception {
		load(PROTECTED, "1000:0000", null);
		// JMP 0x0012 at 1000:FFF0
		assertEquals(0x10000012L, target("1000:fff0", "eb 20"));
	}

	@Test
	public void testProtectedModeRel16WrapsInsideSelector() throws Exception {
		load(PROTECTED, "1000:0000", null);
		// JMP 0x0012 at 1000:FFF0
		assertEquals(0x10000012L, target("1000:fff0", "e9 1f 00"));
	}

	@Test
	public void test32BitTargetsUnchanged() throws Exception {
		builder = new ProgramBuilder("NearTarget", X86_32);
		builder.createMemory("code", "0x10000", 0x20000);
		assertEquals(0x20012L, target("0x1fff0", "eb 20"));
		assertEquals(0x200f5L, target("0x1fff4", "e9 fc 00 00 00"));
		// 16-bit operand size keeps its existing 64K page wrap
		assertEquals(0x1001aL, target("0x1fffa", "66 e9 1c 00"));
	}
}
