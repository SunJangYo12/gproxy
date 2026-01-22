
#NEW
#/media/jin/4abb279b-6d65-4663-97c2-26987f64673a/usr/share/ghidra/support/analyzeHeadless /tmp/ghidra_proj tes -import a.out -postScript ghidra.py out.txt

#OPEN PROJECT
#/media/jin/4abb279b-6d65-4663-97c2-26987f64673a/usr/share/ghidra/support/analyzeHeadless /tmp/ghidra_proj tes -process a.out -postScript ghidra.py out.txt

# function name
from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor

outfile = getScriptArgs()[0]
fm = currentProgram.getFunctionManager()

with open(outfile, "w") as f:
    for func in fm.getFunctions(True):
        f.write("0x%x %s\n" % (func.getEntryPoint().getOffset(), func.getName()))



# all decompiler
from ghidra.app.decompiler import DecompInterface

ifc = DecompInterface()
ifc.openProgram(currentProgram)

with open("decomp.txt", "w") as f:
    for func in currentProgram.getFunctionManager().getFunctions(True):
        res = ifc.decompileFunction(func, 60, monitor)
        if res.decompileCompleted():
            f.write("// %s\n" % func.getName())
            f.write(res.getDecompiledFunction().getC())
            f.write("\n\n")




#xref
refmgr = currentProgram.getReferenceManager()

for ref in refmgr.getReferencesTo(func.getEntryPoint()):
    print(ref)


#cfg
from ghidra.program.model.block import BasicBlockModel

bbm = BasicBlockModel(currentProgram)
blocks = bbm.getCodeBlocksContaining(func.getEntryPoint(), monitor)

