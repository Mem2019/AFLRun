#define AFL_LLVM_PASS

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#if LLVM_VERSION_MAJOR >= 11
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
#endif

#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "debug.h"

using namespace llvm;

#include <iostream>
#include <string>
#include <unistd.h>

namespace
{
#if LLVM_VERSION_MAJOR >= 11
class LTOMarker : public PassInfoMixin<LTOMarker>
{
public:
	LTOMarker() { }
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};
#else
class LTOMarker : public ModulePass
{
public:
	static char ID;
	LTOMarker() : ModulePass(ID) { }
	bool runOnModule(Module &M) override;
};
#endif // LLVM_VERSION_MAJOR >= 11
} // namespace

#if LLVM_MAJOR >= 11
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
	return {LLVM_PLUGIN_API_VERSION, "LTOMarker", "v0.1",
			/* lambda to insert our pass into the pass pipeline. */
			[](PassBuilder &PB)
			{

#if LLVM_VERSION_MAJOR <= 13
			using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
        PB.registerOptimizerLastEPCallback(
				[](ModulePassManager &MPM, OptimizationLevel OL)
				{
					MPM.addPass(LTOMarker());
        });
			}};
}
#else
char LTOMarker::ID = 0;
#endif

#if LLVM_VERSION_MAJOR >= 11
PreservedAnalyses LTOMarker::run(Module &M, ModuleAnalysisManager &MAM)
#else
bool LTOMarker::runOnModule(Module &M)
#endif
{
	using namespace std;
	LLVMContext &C = M.getContext();
	bool output = isatty(2) && !getenv("AFL_QUIET");
	if (output)
		OKF("Start LTO Marking");
	for (auto &F : M)
	{
		// cout << F.getName().str() << endl;
		for (auto &BB : F)
		{
			BB.getTerminator()->setMetadata(
				M.getMDKindID("keybranch"), MDNode::get(C, None));
		}
	}
	if (output)
		OKF("Finish LTO Marking");
#if LLVM_VERSION_MAJOR >= 11
	return PreservedAnalyses::all();
#else
	return true;
#endif
}

#if LLVM_VERSION_MAJOR < 11
static void registerLTOPass(
	const PassManagerBuilder &, legacy::PassManagerBase &PM)
{
	PM.add(new LTOMarker());
}

static RegisterStandardPasses RegisterLTOPass(
	PassManagerBuilder::EP_OptimizerLast, registerLTOPass);

static RegisterStandardPasses RegisterLTOPass0(
	PassManagerBuilder::EP_EnabledOnOptLevel0, registerLTOPass);
#endif