#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <queue>
#include <unordered_set>
#include <unordered_map>
#include <exception>
#include <limits>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/PostDominators.h"

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
namespace bo = boost;

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

static void getDebugLoc(
	const Instruction *I, std::string &Filename, unsigned &Line)
{
#ifdef LLVM_OLD_DEBUG_API
	DebugLoc Loc = I->getDebugLoc();
	if (!Loc.isUnknown())
	{
		DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
		DILocation oDILoc = cDILoc.getOrigLocation();

		Line = oDILoc.getLineNumber();
		Filename = oDILoc.getFilename().str();

		if (filename.empty())
		{
			Line = cDILoc.getLineNumber();
			Filename = cDILoc.getFilename().str();
		}
	}
#else
	if (DILocation *Loc = I->getDebugLoc())
	{
		Line = Loc->getLine();
		Filename = Loc->getFilename().str();

		if (Filename.empty())
		{
			DILocation *oDILoc = Loc->getInlinedAt();
			if (oDILoc)
			{
				Line = oDILoc->getLine();
				Filename = oDILoc->getFilename().str();
			}
		}
	}
#endif /* LLVM_OLD_DEBUG_API */
}

static bool isBlacklisted(const Function *F)
{
	static const SmallVector<std::string, 8> Blacklist =
	{
		"asan.",
		"__asan",
		"llvm.",
		"sancov.",
		"__ubsan_handle_",
		"free",
		"malloc",
		"calloc",
		"realloc",
		"aflrun_"
	};

	for (auto const &BlacklistFunc : Blacklist)
	{
		if (F->getName().startswith(BlacklistFunc))
		{
			return true;
		}
	}

	return false;
}

static void parseReachableHeader(const char* line,
	reach_t* num_targets, reach_t* num_reachables)
{
	char* endptr;
	u64 nt, nr;
	nt = strtoul(line, &endptr, 10);
	if (*endptr != ',')
		FATAL("Wrong format for [BB/F]reachable.txt");
	nr = strtoul(endptr + 1, &endptr, 10);
	if (*endptr != 0 && *endptr != '\n')
		FATAL("Wrong format for [BB/F]reachable.txt");
	if (nt > nr)
		FATAL("Targets must be less than or equal to reachables");
	if (nr >= (1uLL << 32))
		FATAL("Too many reachables");
	*num_targets = (reach_t)nt;
	*num_reachables = (reach_t)nr;
}

namespace
{
	using Weight = double;
	using Property = bo::property<bo::edge_weight_t, Weight>;
	using Graph = bo::adjacency_list<
		bo::vecS, bo::vecS, bo::directedS, bo::no_property,
		Property>;
	using Vertex = bo::graph_traits<Graph>::vertex_descriptor;
	using Edge = std::pair<Vertex, Vertex>;
}

static void parseReachables(
	reach_t& num_targets, reach_t& num_reachables,
	reach_t& num_ftargets, reach_t& num_freachables,
	std::unordered_map<Vertex, u32>& bb_to_idx,
	std::unordered_map<std::string, u32>& f_to_idx,
	const std::string& temp_path)
{
	std::ifstream reachablefile(temp_path + "/BBreachable.txt");
	assert(reachablefile.is_open());
	std::string line;
	std::getline(reachablefile, line);

	parseReachableHeader(line.c_str(), &num_targets, &num_reachables);

	size_t idx = 0;
	while (std::getline(reachablefile, line))
	{
		size_t end = line.find(',');
		assert(end != std::string::npos);
		line = line.substr(0, end);
		end = line.find(':');
		assert(end != std::string::npos);
		line = line.substr(0, end);
		Vertex bb = strtoul(line.c_str(), NULL, 10);
		assert(bb_to_idx.find(bb) == bb_to_idx.end());
		bb_to_idx.emplace(bb, idx++);
	}

	if (idx > num_reachables)
		FATAL("Number of basic blocks is more than num_reachables");
	reachablefile.close();

	reachablefile.open(temp_path + "/Freachable.txt");
	assert(reachablefile.is_open());
	std::getline(reachablefile, line);

	parseReachableHeader(line.c_str(), &num_ftargets, &num_freachables);

	idx = 0;
	while (std::getline(reachablefile, line))
	{
		assert(f_to_idx.find(line) == f_to_idx.end());
		f_to_idx.emplace(line, idx++);
	}

	if (idx > num_freachables)
		FATAL("Number of functions is more than num_freachables");
	reachablefile.close();
}

static std::unordered_set<BasicBlock*> getOriginalBlocks(Module &M, Function& F)
{
	if (F.begin() == F.end())
		return std::unordered_set<BasicBlock*>();

	std::unordered_set<BasicBlock*> ret({&F.getEntryBlock()});

	for (auto &BB : F)
	{
		// For all basic blocks with marked terminators,
		// the successors of these terminators are original basic blocks
		Instruction* Term = BB.getTerminator();
		if (Term->getMetadata(M.getMDKindID("keybranch")))
		{
			unsigned n = Term->getNumSuccessors();
			for (unsigned i = 0; i < n; ++i)
			{
				ret.insert(Term->getSuccessor(i));
			}
		}
	}

	return ret;
}

using BlockOriData =
	std::pair<std::vector<Instruction*>, std::unordered_set<BasicBlock*>>;
// The BB must be original BB returned from `getOriginalBlocks`
static BlockOriData getBlockOriginalData(Module &M, BasicBlock* BB,
	std::unordered_set<BasicBlock*>* TermBlocks = nullptr)
{
	std::vector<Instruction*> instructions;
	std::unordered_set<BasicBlock*> successors;

	// Perform bread first search for blocks belonging to original block
	std::queue<BasicBlock*> q; std::unordered_set<BasicBlock*> explored;
	q.push(BB); explored.insert(BB);

	while (!q.empty())
	{
		BasicBlock* v = q.front(); q.pop();

		// Process the basic block, insert all instructions
		for (auto& I : *v)
			instructions.push_back(&I);

		// Insert to successors for terminator of original block
		Instruction* Term = v->getTerminator();
		if (Term->getMetadata(M.getMDKindID("keybranch")))
		{
			if (TermBlocks) TermBlocks->insert(v);
			unsigned n = Term->getNumSuccessors();
			for (unsigned i = 0; i < n; ++i)
			{
				successors.insert(Term->getSuccessor(i));
			}
		}
		// Continue search for asan generated block
		else
		{
			unsigned n = Term->getNumSuccessors();
			for (unsigned i = 0; i < n; ++i)
			{
				BasicBlock* w = Term->getSuccessor(i);

				if (explored.find(w) == explored.end())
				{
					explored.insert(w);
					q.push(w);
				}
			}
		}
	}

	return make_pair(std::move(instructions), std::move(successors));
}

/* remove warning, TODO: re-enable target filtering
static bool isUnreachableBlock(Module& M, BasicBlock& BB)
{
	auto* Term = BB.getTerminator();
	return dyn_cast<UnreachableInst>(Term) != nullptr &&
		Term->getMetadata(M.getMDKindID("keybranch")) == nullptr;
}

static std::unordered_map<BasicBlock*, Instruction*> replaceBr(
	Module& M, Function& F)
{
	std::unordered_map<BasicBlock*, Instruction*> ret;

	for (auto& BB : F)
	{
		auto* I = BB.getTerminator();

		// Original terminator should not be modified
		if (I->getMetadata(M.getMDKindID("keybranch")))
			continue;

		// Must be BranchInst
		auto* Br = dyn_cast<BranchInst>(I);
		if (Br == nullptr)
			continue;

		// Must has exactly 2 successors
		if (Br->getNumSuccessors() != 2)
			continue;

		BasicBlock* BB0 = Br->getSuccessor(0);
		BasicBlock* BB1 = Br->getSuccessor(1);
		bool b0 = isUnreachableBlock(M, *BB0);
		bool b1 = isUnreachableBlock(M, *BB1);

		if (b0 && !b1)
		{
			auto* BrClone = Br->clone();
			ret.emplace(&BB, BrClone);
			ReplaceInstWithInst(Br, BranchInst::Create(BB1));
		}
		else if (!b0 && b1)
		{
			auto* BrClone = Br->clone();
			ret.emplace(&BB, BrClone);
			ReplaceInstWithInst(Br, BranchInst::Create(BB0));
		}
	}

	return ret;
}
*/

// Get name of basic block,
static std::string getBlockName(Module &M, const BlockOriData& data)
{
	for (auto* I : data.first)
	{
		std::string filename;
		unsigned line = 0;
		getDebugLoc(I, filename, line);

		/* Don't worry about external libs */
		static const std::string Xlibs("/usr/");
		if (filename.empty() || line == 0 ||
			!filename.compare(0, Xlibs.size(), Xlibs))
			continue;

		std::size_t found = filename.find_last_of("/\\");
		if (found != std::string::npos)
			filename = filename.substr(found + 1);

		return filename + ":" + std::to_string(line);
	}

	return "none";
}

// Return all targets covered by block; if empty, the block is not target
static std::unordered_set<std::string> getBlockTargets(const BlockOriData& data,
	const std::unordered_map<std::string, double>& targets)
{
	std::unordered_set<Instruction*> visited;
	std::unordered_set<std::string> ret;
	for (auto* I : data.first)
	{
		if (visited.find(I) != visited.end())
			continue;
		visited.insert(I);

		std::string filename;
		unsigned line = 0;
		getDebugLoc(I, filename, line);

		/* Don't worry about external libs */
		static const std::string Xlibs("/usr/");
		if (filename.empty() || line == 0 ||
			!filename.compare(0, Xlibs.size(), Xlibs))
			continue;

		std::size_t found = filename.find_last_of("/\\");
		if (found != std::string::npos)
			filename = filename.substr(found + 1);

		std::string location(filename + ":" + std::to_string(line));
		if (targets.find(location) != targets.end())
			ret.insert(location);
	}

	return ret;
}

// Given a function, we process it with respect to target information.
// Result:
//	Name for each basic block is stored in `bb_to_name`;
//	all target blocks are stored in `target_blocks`.
static void processTargets(Module &M, Function& F, size_t& next_bb,
	const std::unordered_map<std::string, double>& targets,
	std::unordered_map<BasicBlock*, std::string>& bb_to_name,
	std::unordered_map<BasicBlock*,
		std::unordered_set<std::string>>& target_blocks,
	size_t& num_rm, std::vector<std::string>& id_to_name)
{
	if (F.begin() == F.end())
		return;

	auto BBs = getOriginalBlocks(M, F);

	for (auto* BB : BBs)
	{
		auto data = getBlockOriginalData(M, BB);
		std::string bb_name = getBlockName(M, data);

		auto res = getBlockTargets(data, targets);
		if (!res.empty())
			target_blocks.emplace(BB, std::move(res));

		auto name = std::to_string(next_bb++) + ':' + bb_name;
		bb_to_name.emplace(BB, name);
		id_to_name.push_back(std::move(name));
	}

	/* TODO: filter out redundant targets, and sum the weights of removed ones
	auto bak = replaceBr(M, F);
	DominatorTree Dom(F);
	PostDominatorTree PostDom(F);

	std::unordered_set<BasicBlock*> to_remove;
	for (auto& bw0 : target_blocks)
	{
		auto* BB0 = p0.first;
		if (to_remove.find(BB0) != to_remove.end())
			continue;
		for (auto& bw1 : target_blocks)
		{
			auto* BB1 = p1.first;
			if (BB0 == BB1)
				continue;
			if (Dom.dominates(BB0, BB1) && PostDom.dominates(BB1, BB0))
			{
				to_remove.insert(BB0);
				++num_rm;

				// weight of block to remove is accumutated
				bw1.second += bw0.second;
				break;
			}
		}
	}
	for (auto* BB : to_remove)
		target_blocks.erase(BB);

	// Resume the function
	for (const auto& iter : bak)
		ReplaceInstWithInst(iter.first->getTerminator(), iter.second);//*/
}

static Vertex getBlockId(BasicBlock& BB)
{
	std::string bb_name = BB.getName().str();
	size_t end = bb_name.find(':');
	assert(end != std::string::npos);
	bb_name = bb_name.substr(0, end);
	assert(!bb_name.empty());
	return strtoul(bb_name.c_str(), NULL, 10);
}

// parse the CFG from module used for boost graph,
// note that the edge is inverse, because we want to start dijktra from targets
static void getGraph(Module& M, std::vector<Edge>& edges,
	std::vector<Weight>& weights)
{
	for (auto& F : M)
	{
		if (isBlacklisted(&F))
			continue;

		auto BBs = getOriginalBlocks(M, F);

		for (auto* BB : BBs)
		{
			Vertex u = getBlockId(*BB);

			auto p = getBlockOriginalData(M, BB);

			for (auto* I : p.first)
			{
				if (auto *c = dyn_cast<CallInst>(I))
				{
					if (auto *CalledF = c->getCalledFunction())
					{
						if (!isBlacklisted(CalledF) &&
							CalledF->begin() != CalledF->end())
						{
							// link caller BB to entry BB of callee with weight 0
							edges.emplace_back(
								getBlockId(CalledF->getEntryBlock()), u);
							weights.push_back(0);
						}
					}
				}
			}

			double w = log2(p.second.size());
			for (auto* Succ : p.second)
			{
				edges.emplace_back(getBlockId(*Succ), u);
				weights.push_back(w);
			}
		}
	}
}

std::unordered_map<std::string, double> aflrunParseTargets(std::string targets_file)
{
	std::unordered_map<std::string, double> targets;
	std::ifstream targetsfile(targets_file); assert(targetsfile.is_open());
	std::string line;
	while (std::getline(targetsfile, line))
	{
		std::size_t found = line.find_last_of("/\\");
		if (found != std::string::npos)
			line = line.substr(found + 1);
		found = line.find_last_of('|');
		if (found != std::string::npos)
		{
			double w = std::stod(line.substr(found + 1));
			assert(w >= 0 && !std::isinf(w));
			targets.emplace(line.substr(0, found), w);
		}
		else
			targets.emplace(line, 1); // Default weight is 1
	}
	targetsfile.close();
	return targets;
}

void aflrunAddGlobals(Module& M,
	reach_t num_targets, reach_t num_reachables, reach_t num_freachables)
{
	// Compile num_targets, num_reachables and num_freachables to binary constants.
	LLVMContext &C = M.getContext();
	IntegerType *ReachTy =
		sizeof(reach_t) == 4 ? IntegerType::getInt32Ty(C) : IntegerType::getInt64Ty(C);
	new GlobalVariable(M, ReachTy, true, GlobalValue::ExternalLinkage,
		ConstantInt::get(ReachTy, num_targets), "__aflrun_num_targets");
	new GlobalVariable(M, ReachTy, true, GlobalValue::ExternalLinkage,
		ConstantInt::get(ReachTy, num_reachables), "__aflrun_num_reachables");
	new GlobalVariable(M, ReachTy, true, GlobalValue::ExternalLinkage,
		ConstantInt::get(ReachTy, num_freachables), "__aflrun_num_freachables");
}

bool aflrunPreprocess(
	Module &M, const std::unordered_map<std::string, double>& targets,
	size_t& num_rm, char be_quiet, std::string out_directory)
{
	bool ret = false;

	std::ofstream bbreaches(out_directory + "/BBreachable.txt", std::ofstream::out);
	std::ofstream freaches(out_directory + "/Freachable.txt", std::ofstream::out);
	std::ofstream bbedges(out_directory + "/BBedges.txt", std::ofstream::out);

	/* Create directory to put distance result */
	std::string distances(out_directory + "/distance.cfg");
	if (sys::fs::create_directory(distances))
	{
		FATAL("Could not create directory %s.", distances.c_str());
	}

	size_t next_bb = 0;
	std::vector<std::string> id_to_name; // convert BB id to name
	std::unordered_map<Vertex, std::string> id_to_fname; // entry BB id to func
	std::vector<Vertex> bb_reachable, f_reachable;

	// Map each target string to set of basic blocks containing the target
	// Note that each block can also have multiple string (e.i. n to n relation)
	std::unordered_map<std::string, std::unordered_set<reach_t>> association;

	for (auto &F : M)
	{
		bool has_BBs = false;
		std::string funcName = F.getName().str();

		/* Black list of function names */
		if (isBlacklisted(&F))
			continue;

		std::unordered_map<BasicBlock*, std::string> bb_to_name;
		std::unordered_map<BasicBlock*,
			std::unordered_set<std::string>> target_blocks;
		processTargets(M, F, next_bb, targets, bb_to_name,
			target_blocks, num_rm, id_to_name);

		bool is_target = !target_blocks.empty();
		// if there is any target block, the function should be target

		for (const auto &b2n : bb_to_name)
		{
			auto& BB = *b2n.first;
			const std::string& bb_name = b2n.second;
			bool is_target_bb =
				target_blocks.find(b2n.first) != target_blocks.end();

			BB.setName(bb_name + ":");
			if (!BB.hasName())
			{
				std::string newname = bb_name + ":";
				Twine t(newname);
				SmallString<256> NameData;
				StringRef NameRef = t.toStringRef(NameData);
				MallocAllocator Allocator;
				BB.setValueName(ValueName::Create(NameRef, Allocator));
			}
			assert(BB.getName().str().find(':') != std::string::npos);

			if (is_target_bb)
				ret = true;
			has_BBs = true;
		}

		if (has_BBs)
		{
			for (const auto& ts : target_blocks)
			{
				reach_t idx = bb_reachable.size();
				for (const auto& t : ts.second)
					association[t].insert(idx);
				bb_reachable.push_back(getBlockId(*ts.first));
			}

			Vertex entry_id = getBlockId(F.getEntryBlock());
			if (is_target)
				f_reachable.push_back(entry_id);

			id_to_fname.emplace(entry_id, F.getName().str());
		}
	}

	reach_t num_targets = bb_reachable.size();
	std::vector<double> target_weights(num_targets, 0.0);
	for (const auto& ta : association)
	{ // Iterate each target, with corresponding weight and blocks
		double w = targets.find(ta.first)->second;
		for (reach_t t : ta.second)
		{ // For each block, increment its weight
			target_weights[t] += w / ta.second.size();
		}
	}

	std::vector<Edge> edges;
	std::vector<Weight> weights;
	getGraph(M, edges, weights);
	Graph cfg(edges.begin(), edges.end(), weights.begin(), next_bb);
	assert(bo::num_vertices(cfg) == next_bb && next_bb == id_to_name.size());

	// These 2 structures should contain same vertexes
	std::unordered_map<Vertex, std::unordered_set<reach_t>> bb_reachable_map;
	for (reach_t i = 0; i < bb_reachable.size(); ++i)
		bb_reachable_map.emplace(
			bb_reachable[i], std::unordered_set<reach_t>({i}));
	assert(bb_reachable.size() == bb_reachable_map.size());

	// this should contain same vertexes as f_reachable
	std::unordered_set<Vertex> f_reachable_set(
		f_reachable.begin(), f_reachable.end());
	assert(f_reachable.size() == f_reachable_set.size());
	size_t num_f_targets = f_reachable.size();

	std::vector<Edge> reachable_edges;

	Weight* d = new Weight[next_bb];
	Vertex* p = new Vertex[next_bb];
	for (reach_t i = 0; i < num_targets; ++i)
	{
		Vertex target = bb_reachable[i];

		dijkstra_shortest_paths(
			cfg, target, bo::predecessor_map(p).distance_map(d));

		std::ofstream dist(distances + "/" + std::to_string(i) + ".txt",
			std::ofstream::out);

		bo::graph_traits<Graph>::vertex_iterator vi, vend;
		for (bo::tie(vi, vend) = bo::vertices(cfg); vi != vend; ++vi)
		{
			// Skip unreachable vertexes
			if (p[*vi] == *vi && *vi != target)
				continue;

			dist << id_to_name[*vi] << ',' << d[*vi] << std::endl;

			// for each reachable vertex,
			// add to BBreachable with targets it reaches
			auto tmp = bb_reachable_map.find(*vi);
			if (tmp == bb_reachable_map.end())
			{
				bb_reachable.push_back(*vi);
				bb_reachable_map.emplace(*vi, std::unordered_set<reach_t>({i}));
			}
			else
			{
				tmp->second.insert(i);
			}

			// for each reachable function entry vertex, add to Freachable
			if (id_to_fname.find(*vi) != id_to_fname.end() &&
				f_reachable_set.find(*vi) == f_reachable_set.end())
			{
				f_reachable.push_back(*vi);
				f_reachable_set.insert(*vi);

			}

			// for each reachable vertex, add all of its out edges
			for (auto ed : bo::make_iterator_range(bo::out_edges(*vi, cfg)))
			{
				// since cfg constructed is inverse,
				// we swap source and target here
				reachable_edges.emplace_back(ed.m_target, *vi);
				// TODO: remove replicate
			}

		}

	}

	// Output info to BBreachable
	if (!be_quiet)
		OKF("Basic Block: %u targets, %lu reachables",
			num_targets, bb_reachable.size());
	bbreaches << num_targets <<
		',' << bb_reachable.size() << std::endl;
	assert(num_targets == target_weights.size());
	size_t idx = 0;
	bbreaches.precision(std::numeric_limits<double>::max_digits10);
	for (Vertex bb : bb_reachable)
	{
		bbreaches << id_to_name[bb];
		const auto& ts = bb_reachable_map.find(bb)->second;
		for (reach_t t : ts)
			bbreaches << ',' << t;
		if (idx < target_weights.size())
			bbreaches << '|' << target_weights[idx++];
		bbreaches << std::endl;
	}

	// Output info to Freachable
	if (!be_quiet)
		OKF("Function: %lu targets, %lu reachables",
			num_f_targets, f_reachable.size());
	freaches << num_f_targets << ',' << f_reachable.size() << std::endl;
	for (Vertex f : f_reachable)
		freaches << id_to_fname.find(f)->second << std::endl;

	// Reverse bb_reachable
	std::unordered_map<Vertex, reach_t> bb_reachable_inv;
	for (reach_t i = 0; i < bb_reachable.size(); ++i)
		bb_reachable_inv.emplace(bb_reachable[i], i);

	// Output info to BBedges
	for (const Edge& e : reachable_edges)
	{
		auto src = bb_reachable_inv.find(e.first);
		if (src == bb_reachable_inv.end())
			continue;
		bbedges << src->second << ',' <<
			bb_reachable_inv.find(e.second)->second << std::endl;
	}

	delete[] d; delete[] p;
	aflrunAddGlobals(M, num_targets, bb_reachable.size(), f_reachable.size());
	return ret;
}

void aflrun_laf_targets(
	Module& M, const std::unordered_set<BasicBlock*>& target_bb);

void aflrunInstrument(
	Module &M, std::string out_directory)
{
	reach_t num_targets = 0, num_reachables = 0;
	reach_t num_ftargets = 0, num_freachables = 0;
	std::unordered_map<std::string, u32> f_to_idx;
	std::unordered_map<Vertex, u32> bb_to_idx;
	parseReachables(
		num_targets, num_reachables, num_ftargets, num_freachables,
		bb_to_idx, f_to_idx, out_directory);

	LLVMContext &C = M.getContext();
#ifdef AFLRUN_CTX // remove unused var warning
	IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
#endif
	IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
	IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

#ifdef __x86_64__
	IntegerType *LargestType = Int64Ty;
#else
	IntegerType *LargestType = Int32Ty;
#endif

#ifdef AFLRUN_CTX
	GlobalVariable *AFLCallCtx = new GlobalVariable(
		M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_call_ctx",
		0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

	std::unordered_set<size_t> index_used, findex_used;
	std::vector<std::tuple<reach_t, reach_t, u32>> call_hashes;
	std::unordered_set<BasicBlock*> TargetBB;
	bool switch_laf = getenv("AFLRUN_SWITCH_LAF") != NULL;
	bool target_laf = getenv("AFLRUN_NO_TARET_LAF") == NULL;
	if (switch_laf && target_laf)
		FATAL("Switch LAF and Target LAF currently is exclusive!");

	for (auto &F : M)
	{
		size_t findex; bool has_findex = false;
		if (isBlacklisted(&F))
		{
			continue;
		}

		std::string f_name = F.getName().str();
		if (!f_name.empty())
		{
			auto it = f_to_idx.find(f_name);
			if (it != f_to_idx.end())
			{
				findex = it->second;
				has_findex = true;
			}
		}

		size_t index; bool has_index = false;

		// Fetch all basic blocks first,
		// so SplitBlock will not affect iteration of original blocks
		auto BBs = getOriginalBlocks(M, F);
		if (BBs.empty())
			continue;

#ifdef AFLRUN_CTX
		Value* CurCallCtx = nullptr;
#endif
		{
			BasicBlock::iterator IP = F.getEntryBlock().getFirstInsertionPt();
			IRBuilder<> IRB(&(*IP));

#ifdef AFLRUN_CTX
			// Load current call context value
			LoadInst* CtxOld = IRB.CreateLoad(Int32Ty, AFLCallCtx);
			CtxOld->setMetadata(
				M.getMDKindID("nosanitize"), MDNode::get(C, None));
			CurCallCtx = IRB.CreateZExt(CtxOld, IRB.getInt32Ty());
#endif

			// Instrument `aflrun_f_inst` at start of each reachable function
			if (has_findex)
			{
// When doing overhead measurement, we don't instrument function,
// because it is not used in our algorithm but only to show the status.
#ifndef AFLRUN_OVERHEAD
				ConstantInt* FuncIdx = ConstantInt::get(LargestType, findex);

				Type *Args[] = {LargestType};
				FunctionType *FTy = FunctionType::get(
					Type::getVoidTy(C), Args, false);

				IRB.CreateCall(
					M.getOrInsertFunction("aflrun_f_inst", FTy), {FuncIdx});
#endif // AFLRUN_OVERHEAD

				assert(findex_used.find(findex) == findex_used.end());
				findex_used.insert(findex);
			}
		}

		std::unordered_set<CallInst*> visited;

		for (auto BB_ : BBs)
		{
			auto& BB = *BB_;
			has_index = false;
			Vertex bb_name = getBlockId(BB);

			auto it2 = bb_to_idx.find(bb_name);
			if (it2 != bb_to_idx.end())
			{
				index = it2->second;
				has_index = true;
			}

			BasicBlock::iterator IP = BB.getFirstInsertionPt();
			IRBuilder<> IRB(&(*IP));
			CallInst* LAF = nullptr;

			if (has_index)
			{
				// Call `aflrun_inst` at start of each reachable basic block

				ConstantInt* BlockIdx = ConstantInt::get(LargestType, index);

				Type *Args[] = {LargestType};
				FunctionType *FTy = FunctionType::get(Int1Ty, Args, false);

				LAF = IRB.CreateCall(
					M.getOrInsertFunction("aflrun_inst", FTy), {BlockIdx});

				assert(index_used.find(index) == index_used.end());
				index_used.insert(index);
			}

			// Instrument each call to update and restore contexts
			auto p = getBlockOriginalData(M, BB_,
				target_laf && has_index && index < num_targets ?
				&TargetBB : nullptr);
#ifdef AFLRUN_CTX

			for (auto* I : p.first)
			{
				auto* Call = dyn_cast<CallInst>(I);
				if (Call == nullptr)
					continue;

				// Ensure each call instruction is only instrumented once
				if (visited.find(Call) != visited.end())
					continue;
				visited.insert(Call);

				// We don't instrument Call to blacklisted function
				auto* CalledF = Call->getCalledFunction();
				if (CalledF != nullptr && isBlacklisted(CalledF))
					continue;

				// Instrument to any call,
				// in case context may be changed in these calls
				IRB.SetInsertPoint(Call);

				// Generate current context value
				unsigned int cur_ctx = AFL_R(CTX_SIZE);
				ConstantInt *CurCtx = ConstantInt::get(Int32Ty, cur_ctx);

				// Record context value
				if (CalledF != nullptr && CalledF->begin() != CalledF->end())
				{
					call_hashes.emplace_back(
						bb_name, getBlockId(CalledF->getEntryBlock()), cur_ctx);
				}

				// Xor current context and old context
				// and store the result to __afl_call_ctx
				IRB.CreateStore(IRB.CreateXor(CurCallCtx, CurCtx), AFLCallCtx)
					->setMetadata(
						M.getMDKindID("nosanitize"), MDNode::get(C, None));

				// Restore contexts to old context value after call
				IRB.SetInsertPoint(Call->getNextNode());
				IRB.CreateStore(CurCallCtx, AFLCallCtx)
					->setMetadata(
						M.getMDKindID("nosanitize"), MDNode::get(C, None));
			}
#endif
			if (LAF && switch_laf)
			{ // For reachable block, we split all compare instructions
				for (auto* I : p.first)
				{
					CmpInst* Cmp = dyn_cast<CmpInst>(I);
					if (Cmp == nullptr)
						continue;

					// When we encounter a Cmp, we split an if-else before it,
					// using return value from `aflrun_inst` function.
					Instruction* LAFTerm = nullptr;
					Instruction* NoLAFTerm = nullptr;
					SplitBlockAndInsertIfThenElse(LAF, Cmp, &LAFTerm, &NoLAFTerm);

					// Clone the Cmp instruction, and insert to these 2 blocks
					Instruction* LAFCmp = Cmp->clone();
					LAFCmp->insertBefore(LAFTerm);
					Instruction* NoLAFCmp = Cmp->clone();
					NoLAFCmp->insertBefore(NoLAFTerm);

					// Create a phi node to receive them
					PHINode *PN = PHINode::Create(Int1Ty, 2);
					BasicBlock* LAFBlock = LAFCmp->getParent();
					BasicBlock* NoLAFBlock = NoLAFCmp->getParent();
					PN->addIncoming(LAFCmp, LAFBlock);
					PN->addIncoming(NoLAFCmp, NoLAFBlock);
					ReplaceInstWithInst(Cmp, PN);

					// We don't want to instrument these 3 new blocks
					LAFBlock->getTerminator()->setMetadata(
						M.getMDKindID("laf"), MDNode::get(C, None));
					NoLAFBlock->getTerminator()->setMetadata(
						M.getMDKindID("laf"), MDNode::get(C, None));
					PN->getParent()->getTerminator()->setMetadata(
						M.getMDKindID("laf"), MDNode::get(C, None));

					TargetBB.insert(LAFCmp->getParent());
				}
			}
		}
	}
	// Each index should be instrumented exactly once
	assert(findex_used.size() == f_to_idx.size());
	assert(index_used.size() == bb_to_idx.size());

	std::ofstream chash(out_directory + "/Chash.txt", std::ofstream::out);
	for (const auto& p : call_hashes)
	{
		auto src = bb_to_idx.find(std::get<0>(p));
		auto dst = bb_to_idx.find(std::get<1>(p));
		if (src != bb_to_idx.end() && dst != bb_to_idx.end())
			chash << src->second << ',' << dst->second <<
				'|' << std::get<2>(p) << std::endl;;
	}
	chash.close();

	if (switch_laf || target_laf) aflrun_laf_targets(M, TargetBB);
}