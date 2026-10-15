# Ghidra headless post-script: export decompiled pseudo-C.
# Invoked by reverence_mcp.analysis.decompile via analyzeHeadless.
# Args: <output_file> <function_name|address|__ALL__>
# This runs inside Ghidra's Jython (Python 2) interpreter.
# @category Reverence
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _decompile(ifc, func, monitor):
    res = ifc.decompileFunction(func, 60, monitor)
    if res is not None and res.decompileCompleted():
        return res.getDecompiledFunction().getC()
    return "// <decompilation failed for %s>\n" % func.getName()


def run():
    args = getScriptArgs()
    if len(args) < 2:
        print("DecompileExport: missing args")
        return
    out_path = args[0]
    target = args[1]

    program = getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.openProgram(program)

    fm = program.getFunctionManager()
    chunks = []

    if target == "__ALL__":
        funcs = fm.getFunctions(True)  # forward iterator
        for func in funcs:
            if monitor.isCancelled():
                break
            chunks.append(_decompile(ifc, func, monitor))
    else:
        found = None
        for func in fm.getFunctions(True):
            if func.getName() == target:
                found = func
                break
        if found is None:
            # try as an address
            try:
                addr = program.getAddressFactory().getAddress(target)
                found = fm.getFunctionContaining(addr)
            except Exception:
                found = None
        if found is not None:
            chunks.append(_decompile(ifc, found, monitor))
        else:
            chunks.append("// function not found: %s\n" % target)

    f = open(out_path, "w")
    try:
        f.write("\n\n".join(chunks))
    finally:
        f.close()
    print("DecompileExport: wrote %d function(s) to %s" % (len(chunks), out_path))


run()
