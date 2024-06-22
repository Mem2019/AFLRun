#include <fstream>
#include <memory>
#include <vector>
#include <queue>
#include <stack>
#include <cassert>
#include <string>
#include <cstring>
#include <cmath>
#include <functional>
#include <algorithm>
#include <numeric>
#include <iostream>
#include <tuple>
#include <random>

#include <boost/functional/hash.hpp>
#include <boost/make_shared.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/algorithm/string.hpp>
#include "robin_hood.h"
namespace bo = boost;
namespace rh = robin_hood;

#include "aflrun.h"

namespace { struct Fringe; struct SeedFringes; struct ClusterPair; }
template<> struct std::hash<Fringe>
{
	std::size_t operator()(const Fringe&) const noexcept;
};
template<> struct std::hash<SeedFringes>
{
	std::size_t operator()(const SeedFringes&) const noexcept;
};
template<> struct std::hash<std::pair<reach_t, reach_t>>
{
	std::size_t operator()(const std::pair<reach_t, reach_t>&) const noexcept;
};
template<> struct std::hash<ClusterPair>
{
	std::size_t operator()(const ClusterPair&) const noexcept;
};

using namespace std;

/* ----- Global data structures for AFLRUN ----- */
namespace
{

struct AFLRunUpdateTime
{
	/* Record the time of last update of our maintained information */
	u64 last_reachable, last_fringe,
		last_pro_fringe, last_target;
	u64 last_ctx_reachable, last_ctx_fringe,
		last_ctx_pro_fringe, last_ctx_target;

	AFLRunUpdateTime() :
		last_reachable(0), last_fringe(0),
		last_pro_fringe(0), last_target(0),
		last_ctx_reachable(0), last_ctx_fringe(0),
		last_ctx_pro_fringe(0), last_ctx_target(0) {}
};

AFLRunUpdateTime update_time;

struct AFLRunConfig
{
	bool slow_ctx_bfs;
	bool check_at_begin, log_at_begin;
	u64 log_check_interval;
	double cycle_energy; int max_cycle_count;
	bool check_fringe;
	double supp_cnt_thr; double conf_thr; bool count_seed;
	double trim_thr; double linear_cycle_energy;
	double exp_ratio; bool favor_high_cov;
	bool disable_mode[4]; u8 reset_level; bool reset_target;
	bool no_diversity; bool uni_whole_cycle; bool show_all_seeds;
	double init_cov_quant; double col_weight_k;
	u8 div_level; u32 div_seed_thr; bool trim_col; u8 init_cov_reset;
	bool seed_based_energy; bool assign_ctx;
	bool unite_assign; double unite_ratio[4]; bool single_supp_thr;
	double dist_k; double queue_quant_thr; u32 min_num_exec;
	bool uniform_targets; bool extra_cov; bool no_critical;
	/*
	This callback function takes in information about seeds and fringes,
	and allocate given `total_energy` to `ret` array by adding to it.
	In other word, increase of sum of `ret` array should equal to `total_energy`.
	*/

	explicit AFLRunConfig() : slow_ctx_bfs(false),
	check_at_begin(false), log_at_begin(false),
	log_check_interval(36000),
	cycle_energy(60 * 10), max_cycle_count(32), check_fringe(false),
	supp_cnt_thr(100), conf_thr(0.9), count_seed(true), trim_thr(1),
	linear_cycle_energy(0), exp_ratio(1), favor_high_cov(false),
	disable_mode{false, false, false, false}, reset_level(1),
	reset_target(true), no_diversity(false), uni_whole_cycle(false),
	show_all_seeds(false), init_cov_quant(10 * 60 * 10),
	col_weight_k(1.0), div_level(1), div_seed_thr(100), trim_col(true),
	init_cov_reset(0), seed_based_energy(true), assign_ctx(false),
	unite_assign(true), unite_ratio{1, 1, 1, 3}, single_supp_thr(false),
	dist_k(1), queue_quant_thr(0), min_num_exec(1), uniform_targets(false),
	extra_cov(false), no_critical(false) {}

	static const rh::unordered_map<string,
		function<void(AFLRunConfig*, const string&)>> loaders;

	void load(const string& cmd)
	{
		if (cmd.empty())
			return;
		size_t idx = cmd.find('=');
		if (idx == string::npos)
			throw string("Format of config must be 'key=value'");
		auto key = cmd.substr(0, idx);
		auto callback = loaders.find(key);
		if (callback == loaders.end())
			throw string("No such option: " + key);
		callback->second(this, cmd.substr(idx + 1));
	}
	void check() const
	{
		if (!check_fringe && check_at_begin)
			throw string("If you want to check at beginning, "
				"please enable check_fringe.");
		if (no_critical && !unite_assign)
			throw string("For no critical block ablation study, "
				"please enable unite_assign.");
	}
private:
	static void check_digit(const string& val, string name)
	{
		if (val.empty())
			throw string("'"+name+"' must be digit");
		for (char c : val)
		{
			if (!isdigit(c))
				throw string("'"+name+"' must be digit");
		}
	}
};

const rh::unordered_map<string, function<void(AFLRunConfig*, const string&)>>
AFLRunConfig::loaders(
{
	#define BOOL_AFLRUN_ARG(name) \
		if (val == "1") \
			config->name = true; \
		else if (val == "0") \
			config->name = false; \
		else \
			throw string("Invalid value '"+val+"' for '"#name"'");

	{"slow_ctx_bfs", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(slow_ctx_bfs)
	}},
	{"check_at_begin", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(check_at_begin)
	}},
	{"log_at_begin", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(log_at_begin)
	}},
	{"log_check_interval", [](AFLRunConfig* config, const string& val)
	{
		check_digit(val, "log_check_interval");
		config->log_check_interval = stoull(val);
	}},
	{"count_seed", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(count_seed);
	}},
	{"cycle_energy", [](AFLRunConfig* config, const string& val)
	{
		config->cycle_energy = stod(val);
		if (isnan(config->cycle_energy) || isinf(config->cycle_energy) ||
			config->cycle_energy <= 0)
			throw string("Invalid 'cycle_energy'");
	}},
	{"max_cycle_count", [](AFLRunConfig* config, const string& val)
	{
		check_digit(val, "max_cycle_count");
		config->max_cycle_count = stoi(val);
	}},
	{"check_fringe", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(check_fringe)
	}},
	{"supp_cnt_thr", [](AFLRunConfig* config, const string& val)
	{ // To disable target diversity, set "supp_cnt_thr=0:conf_thr=0"
		config->supp_cnt_thr = stod(val);
		if (isnan(config->supp_cnt_thr) || isinf(config->supp_cnt_thr) ||
			config->supp_cnt_thr < 0)
			throw string("Invalid 'supp_cnt_thr'");
	}},
	{"conf_thr", [](AFLRunConfig* config, const string& val)
	{
		if (val == "inf")
		{ // For infinite threshold, we don't cluster anything
			config->conf_thr = numeric_limits<double>::infinity();
			return;
		}
		config->conf_thr = stod(val);
		if (isnan(config->conf_thr) ||
			config->conf_thr < 0 || config->conf_thr > 1)
			throw string("Invalid 'conf_thr'");
	}},
	{"dist_k", [](AFLRunConfig* config, const string& val)
	{
		if (val == "inf")
		{ // If `k` is infinity, we distribute weight uniformly
			config->dist_k = numeric_limits<double>::infinity();
			return;
		}
		config->dist_k = stod(val);
		if (isnan(config->dist_k) || config->dist_k <= 0)
			throw string("Invalid 'dist_k'");
	}},
	{"trim_thr", [](AFLRunConfig* config, const string& val)
	{
		if (val == "inf")
		{ // For infinite threshold, we don't trim any seed.
			config->trim_thr = numeric_limits<double>::infinity();
			return;
		}
		config->trim_thr = stod(val);
		// For 0 threshold, we always trim every seed.
		if (isnan(config->trim_thr) || config->trim_thr < 0)
			throw string("Invalid 'trim_thr'");
	}},
	{"linear_cycle_energy", [](AFLRunConfig* config, const string& val)
	{
		// If this value is non-zero, we will have cycle energy to be:
		// max(cycle_energy, linear_cycle_energy * num_active_seeds)
		config->linear_cycle_energy = stod(val);
		if (isnan(config->linear_cycle_energy) ||
			isinf(config->linear_cycle_energy) ||
			config->linear_cycle_energy < 0)
			throw string("Invalid 'linear_cycle_energy'");
	}},
	{"exp_ratio", [](AFLRunConfig* config, const string& val)
	{
		// Ratio of desired exploitation / exploration:
		// if >1, more energy will be allocated to exploitation;
		// if <1, more energy will be allocated to exploration;
		// if =1, exploitation and exploration are equal;
		// if =inf, it almost only does exploitation;
		// if =0, it amlmost only does exploration.
		config->exp_ratio = stod(val);
		if (isnan(config->exp_ratio) || config->exp_ratio < 0)
			throw string("Invalid 'exp_ratio'");
	}},
	{"favor_high_cov", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(favor_high_cov)
	}},
	{"disable_mode", [](AFLRunConfig* config, const string& val)
	{ // Same as order in enum Mode:
		// 0 for cov; 1 for ctx fringe; 2 for fringe; 3 for target
		unsigned long m = stoul(val);
		if (m > 3)
			throw string("Invalid 'disable_mode'");
		config->disable_mode[m] = true;
	}},
	{"reset_level", [](AFLRunConfig* config, const string& val)
	{
		unsigned long l = stoul(val);
		if (l > 1) // TODO: level=2, reset when new ctx fringe is reached
			throw string("Invalid 'reset_level'");
		config->reset_level = static_cast<u8>(l);
	}},
	{"reset_target", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(reset_target)
	}},
	{"no_diversity", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(no_diversity)
	}},
	{"uni_whole_cycle", [](AFLRunConfig* config, const string& val)
	{ // If set, whole_count will not increase, use cautiously because
		// this will make some AFL stuff based on cycle count not work.
		BOOL_AFLRUN_ARG(uni_whole_cycle)
	}},
	{"show_all_seeds", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(show_all_seeds)
	}},
	{"init_cov_quant", [](AFLRunConfig* config, const string& val)
	{
		config->init_cov_quant = stod(val);
		if (isnan(config->init_cov_quant) || config->init_cov_quant < 0)
			throw string("Invalid 'init_cov_quant'");
	}},
	{"col_weight_k", [](AFLRunConfig* config, const string& val)
	{
		config->col_weight_k = stod(val);
		if (isnan(config->col_weight_k) || isinf(config->col_weight_k) ||
			config->col_weight_k < 0)
			throw string("Invalid 'col_weight_k'");
	}},
	{"div_level", [](AFLRunConfig* config, const string& val)
	{ // 0: only target diversity; 1: +pro fringe diversity; 2. +fringe diversity
		config->div_level = stoi(val);
		if (config->div_level > 1)
			throw string("Invalid 'div_level'");
		/* TODO: diversity for context-sensitive fringe
		Current implementation is problematic. Instead, we should use a switch
		bitmap with context for these context sensitive fringe, which is leaved
		as future work.
		*/
	}},
	{"div_seed_thr", [](AFLRunConfig* config, const string& val)
	{
		if (val == "inf")
		{
			config->div_seed_thr = numeric_limits<u32>::max();
			return;
		}
		config->div_seed_thr = stoi(val);
		if (config->div_seed_thr < 2)
			throw string("Invalid 'div_seed_thr'");
	}},
	{"trim_col", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(trim_col)
	}},
	{"init_cov_reset", [](AFLRunConfig* config, const string& val)
	{
		// 0: no reset;
		// 1: reset at update on reachable;
		// 2: reset at update on context reachable;
		// 3: reset at new seed covering fringe.
		config->init_cov_reset = stoi(val);
		if (config->init_cov_reset > 2)
			throw string("Invalid 'init_cov_reset'");
	}},
	{"seed_based_energy", [](AFLRunConfig* config, const string& val)
	{ // Use new energy assignment algorithm!
		BOOL_AFLRUN_ARG(seed_based_energy)
	}},
	{"assign_ctx", [](AFLRunConfig* config, const string& val)
	{ // If we should assign uniformly among different contexts in new allocation
		BOOL_AFLRUN_ARG(assign_ctx)
	}},
	{"unite_assign", [](AFLRunConfig* config, const string& val)
	{ // If true, we don't use state machine, instead we do everything together
		BOOL_AFLRUN_ARG(unite_assign)
	}},
	{"unite_ratio", [](AFLRunConfig* config, const string& val)
	{ // Format: "cov,ctx,pro,tgt"
		vector<string> ratios;
		bo::split(ratios, val, [](char c) -> bool { return c == ','; });
		if (ratios.size() != 4)
			throw string("Invalid 'unite_ratio'");
		for (size_t i = 0; i < 4; ++i)
		{
			double r = stod(ratios[i]);
			if (isnan(r) || isinf(r) || r < 0)
				throw string("Invalid 'unite_ratio'");
			config->unite_ratio[i] = r;
		}
	}},
	{"single_supp_thr", [](AFLRunConfig* config, const string& val)
	{ // If true, we only use LHS as support count threshold
		BOOL_AFLRUN_ARG(single_supp_thr)
	}},
	{"queue_quant_thr", [](AFLRunConfig* config, const string& val)
	{
		config->queue_quant_thr = stod(val);
		if (config->queue_quant_thr < 0 || isnan(config->queue_quant_thr) ||
			isinf(config->queue_quant_thr))
			throw string("Invalid 'queue_quant_thr'");
	}},
	{"min_num_exec", [](AFLRunConfig* config, const string& val)
	{
		config->min_num_exec = stoul(val);
		if (config->min_num_exec < 1)
			throw string("Invalid 'min_num_exec'");
	}},
	{"uniform_targets", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(uniform_targets)
	}},
	{"extra_cov", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(extra_cov)
	}},
	{"no_critical", [](AFLRunConfig* config, const string& val)
	{
		BOOL_AFLRUN_ARG(no_critical)
	}},
	#undef BOOL_AFLRUN_ARG
});

AFLRunConfig config;

struct AFLRunGlobals
{
	reach_t num_targets, num_reachables;
	reach_t num_ftargets, num_freachables;
	u8* virgin_reachables;
	u8* virgin_freachables;
	u8* virgin_ctx;
	char** reachable_names;
	reach_t** reachable_to_targets;
	reach_t* reachable_to_size;
	reach_t num_reached, num_freached; /* Number of non-virgin */
	reach_t num_reached_targets, num_freached_targets;
	string out_dir;
	const double* target_weights;
	u32 map_size;
	void* afl;
	u64 init_time, cycle_time;

	explicit AFLRunGlobals(reach_t num_targets, reach_t num_reachables,
		reach_t num_ftargets, reach_t num_freachables,
		u8* virgin_reachables, u8* virgin_freachables, u8* virgin_ctx,
		char** reachable_names, reach_t** reachable_to_targets,
		reach_t* reachable_to_size, const char* out_dir,
		const double* target_weights, u32 map_size, void* afl,
		u64 init_time, u64 cycle_time)
	: num_targets(num_targets), num_reachables(num_reachables),
	num_ftargets(num_ftargets), num_freachables(num_freachables),
	virgin_reachables(virgin_reachables), virgin_freachables(virgin_freachables),
	virgin_ctx(virgin_ctx), reachable_names(reachable_names),
	reachable_to_targets(reachable_to_targets),
	reachable_to_size(reachable_to_size),
	num_reached(0), num_freached(0), num_reached_targets(0),
	num_freached_targets(0), out_dir(out_dir),
	target_weights(target_weights), map_size(map_size), afl(afl),
	init_time(init_time), cycle_time(cycle_time)
	{
		if (this->out_dir.back() != '/')
			this->out_dir.push_back('/');
	}

	inline double get_tw(reach_t t) const
	{
		return config.uniform_targets ? 1 : target_weights[t];
	}
};

unique_ptr<AFLRunGlobals> g = nullptr;

struct AFLRunGraph
{
	vector<rh::unordered_flat_set<reach_t>> src_to_dst;
	vector<vector<reach_t>> dst_to_src;
	rh::unordered_map<pair<reach_t, reach_t>, vector<u32>> call_hashes;
	explicit AFLRunGraph(reach_t num)
		: src_to_dst(num), dst_to_src(num) {}
};

struct BasicBlockGraph : public AFLRunGraph
{
	explicit BasicBlockGraph(const char* bb_edges, reach_t num_reachables)
		: AFLRunGraph(num_reachables)
	{
		ifstream in(bb_edges); assert(in.is_open());
		string line; char* endptr;
		while (getline(in, line))
		{
			const char* l = line.c_str();
			reach_t src = strtoul(l, &endptr, 10); assert(*endptr == ',');
			reach_t dst = strtoul(endptr+1, &endptr, 10); assert(*endptr == 0);
			assert(src < num_reachables && dst < num_reachables);
			src_to_dst[src].insert(dst);
			dst_to_src[dst].push_back(src);
		}
		in.close();
	}
};

struct Fringe
{
	reach_t block;
	u32 context;
	explicit Fringe(reach_t block, u32 context) :
		block(block), context(context) {}
	bool operator==(const Fringe& rhs) const
	{
		return this->block == rhs.block && this->context == rhs.context;
	}
};

class TargetGrouper;

struct SeedFringes
{
	bo::shared_ptr<u8[]> bitmap;
	size_t bitmap_size;
	size_t num_ones;
	explicit SeedFringes(size_t num_fringes)
		: bitmap_size((num_fringes + 7) / 8), num_ones(0)
	{
		bitmap = bo::make_shared<u8[]>(bitmap_size);
		fill(bitmap.get(), bitmap.get() + bitmap_size, 0);
	}
	bool operator==(const SeedFringes& rhs) const
	{
		size_t size = this->bitmap_size;
		const u8* ptr = this->bitmap.get();
		return size == rhs.bitmap_size &&
			equal(ptr, ptr + size, rhs.bitmap.get());
	}
	inline void set(size_t idx)
	{
		if (!get(idx)) ++num_ones;
		bitmap[idx / 8] |= 1 << (idx % 8);
	}
	inline bool get(size_t idx)
	{
		return ((bitmap[idx / 8]) & (1 << (idx % 8))) != 0;
	}
};

template <typename F, typename D>
struct FringeBlocks
{
	struct Info
	{
		rh::unordered_set<u32> seeds; // Set of all seeds that cover the fringe
		rh::unordered_map<reach_t, rh::unordered_set<D>> decisives;
		// decisives for each target of this fringe
		double fuzzed_quant;

		// We can only access these 2 variables when `has_top_rated == true`
		u64 top_rated_factor;
		u32 top_rated_seed; bool has_top_rated;
		Info() : fuzzed_quant(0), has_top_rated(false) {}
	};

	vector<rh::unordered_set<F>> target_to_fringes;
	// maps each target to a set of fringe blocks
	rh::unordered_map<reach_t, rh::unordered_set<F>> block_to_fringes;
	// maps each block of fringe to fringes with that block

	rh::unordered_map<F, Info> fringes;
	// Maps each fringe block to set of targets that contain such block as fringe,
	// this information should be consistent with `target_to_fringes`;
	// for each target a set of neighbor virgin blocks are recorded,
	// which are the blocks that make this fringe block a fringe.
	// Note that when set of neighbors are emptied, we need to delete target;
	// similarly when set of targets are emptied, we need to delete fringe.

	rh::unordered_map<D, rh::unordered_set<F>> decisive_to_fringes;
	// Map decisive blocks to corresponding fringes,
	// works for both normal and progressive fringes.

	rh::unordered_map<F, size_t> freq_idx;
	vector<pair<size_t, u64>> freq; // frequency for each current fringe
	// first element is index to bitmap and second is frequency
	rh::unordered_map<u32, rh::unordered_set<F>> seed_fringes;
	// map seed to all fringes covered by it, must be consistent as above

	rh::unordered_set<u32> favored_seeds;

	explicit FringeBlocks(reach_t num_targets) : target_to_fringes(num_targets) {}

	void add_fringe(
		const F& f, reach_t t, rh::unordered_set<D>&& decisives);
	bool del_fringe(const F& f, const vector<reach_t>& ts);
	bool del_fringe(const F& f);
	bool fringe_coverage(const u8* bitmap, u32 seed,
		const rh::unordered_set<Fringe>* new_criticals = nullptr,
		const rh::unordered_set<reach_t>* new_bits_targets = nullptr);
	void inc_freq(const u8* bitmap);
	void update_fuzzed_quant(u32 seed, double fuzzed_quant);
	void update_fringe_score(u32 seed);
	u32 cull_queue(u32* seeds, u32 num);
	rh::unordered_set<u32> select_favored_seeds() const;
	void set_favored_seeds(const u32* seeds, u32 num);

	unique_ptr<TargetGrouper> grouper;
	void group();
	void assign_energy(u32 num_seeds, const u32* seeds, double* ret) const;

	u8 try_add_fringe(const Fringe& cand);
	vector<reach_t> try_del_fringe(const Fringe& cand);

	void remove_seed(u32 seed);

	friend void assign_energy_unite(u32 num_seeds, const u32* ss, double* ret);

private:
	struct FringeInfo
	{
		double quant;
		rh::unordered_set<u32> seeds;
		size_t idx;
		FringeInfo() : quant(0), idx(0) {}
	};

	pair<rh::unordered_map<u32, double>, double> assign_seed_no_ctx(
		const rh::unordered_map<reach_t, double>& block_weight,
		const rh::unordered_map<u32, u32>& seed_to_idx) const;
	pair<rh::unordered_map<u32, double>, double> assign_seed_ctx(
		const rh::unordered_map<reach_t, double>& block_weight,
		const rh::unordered_map<u32, u32>& seed_to_idx) const;
	inline pair<rh::unordered_map<u32, double>, double> assign_seed(
		const rh::unordered_map<reach_t, double>& block_weight,
		const rh::unordered_map<u32, u32>& seed_to_idx) const;
	void assign_seeds_covered(
		const rh::unordered_set<u32>& seeds, double total_weight,
		const rh::unordered_map<u32, u32>& seed_to_idx,
		rh::unordered_map<u32, double>& seed_weight, double& all_sum) const;
	void record_new_cvx_opt(
		const vector<pair<reach_t, rh::unordered_set<reach_t>>>& target_fringes,
		const rh::unordered_map<reach_t, double>& block_weight,
		const rh::unordered_map<u32, double>& seed_ratio,
		const vector<pair<u32, double>>& sol) const;

	void remove_freq(const F& f);
	bool remove_block(const F& f);
	pair<unique_ptr<double[]>, unique_ptr<double[]>> allocate_ratio(
		const rh::unordered_map<reach_t, FringeInfo>& fringe_info,
		const vector<reach_t>& vec_fringes) const;
};

unique_ptr<FringeBlocks<Fringe, Fringe>> path_fringes = nullptr;
unique_ptr<FringeBlocks<Fringe, reach_t>> path_pro_fringes = nullptr;
unique_ptr<FringeBlocks<Fringe, u8/*not used*/>> reached_targets = nullptr;

// Convert block index into distance for each target
vector<rh::unordered_map<reach_t, double>> bb_to_dists;

// Given set of blocks, we distribute target weight `total` to basic blocks,
// using distance to target `t`, returned by adding each weight value to `dst`.
void dist_block_ratio(
	const rh::unordered_set<reach_t>& blocks, reach_t t, double total,
	rh::unordered_map<reach_t, double>& dst)
{
	if (isinf(config.dist_k))
	{ // If `k` is infinity, we just uniformly distribute.
		for (reach_t b : blocks)
		{
			dst[b] += total / blocks.size();
		}
		return;
	}
	vector<pair<reach_t, double>> block_ratios; double sum = 0;
	for (reach_t b : blocks)
	{
		double w = 1.0 / (bb_to_dists[b].find(t)->second + config.dist_k);
		sum += w;
		block_ratios.emplace_back(b, w);
	}
	for (const auto& p : block_ratios)
	{
		dst[p.first] += total * p.second / sum;
	}
}

class AFLRunState
{
public:
	enum Mode : u8
	{
		kCoverage = 0, kFringe, kProFringe, kTarget, kUnite
	};
private:
	Mode mode;
	bool reset_exploit, init_cov;
	int cycle_count;
	u64 whole_count;
	double cov_quant, exploration_quant, exploitation_quant;
	void reset(Mode new_mode)
	{
		if (mode == kUnite)
		{ // Unite mode always resets to it self when there is any fringe update
			cycle_count = -1;
			assert(cov_quant == 0);
			return;
		}
		// we don't want to reset to a more explorative state;
		// we also don't want to reset to exploration mode in exploitation mode,
		// exploitation goes back to exploration only if certain amount of energy
		// is totally executed. e.i. see `cycle_end` when `mode == kTarget`.
		if (new_mode < mode)
			return;
		mode = new_mode;
		// set to -1 because we don't want to count current cycle
		cycle_count = -1;
		cov_quant = 0;
	}
	// 4. Solve favor high column(e.i. linear to number of seeds)
	// 5. Better Splice
	// 6. Better design for fringe? Keep some deleted fringe. (Might take time)

public:
	AFLRunState() : mode(kCoverage), reset_exploit(false), init_cov(true),
		cycle_count(-1), whole_count(0), cov_quant(0),
		exploration_quant(0), exploitation_quant(0) {}
	// Initialize cycle_count to -1 since cycle_end is called at start of cycle

	inline u64 get_whole_count() const
	{
		return whole_count;
	}

	bool cycle_end() // Return true if whole_count has increased
	{
		// For coverage mode,
		// we look quantum being executed instead of number of cycles
		if (init_cov)
		{
			assert(mode == kCoverage);
			++cycle_count;
			if (cov_quant >= config.init_cov_quant)
			{
				// After initial coverage fuzzing,
				// we switch to either state machine or unite assignment.
				if (config.unite_assign)
					mode = kUnite; // Start unite energy assignment mode
				else
					mode = kProFringe; // Start directed fuzzing
				cov_quant = 0; cycle_count = 0;
				init_cov = false;
			}
			return false;
		}
		if (mode == kUnite)
		{
			++cycle_count; // We never switch as long as we enter unite state
			return false; // TODO: whole_count for unite mode?
		}
		if (mode == kCoverage)
		{
			// we still need to count cycle to precent cycle to be always -1
			++cycle_count;
			if (cov_quant >= config.max_cycle_count * config.cycle_energy ||
				config.disable_mode[kCoverage])
			{ // When we cannot find anything new, start exploitation
				mode = kTarget;
				cov_quant = 0;
				cycle_count = 0;
			}
			return false;
		}
		assert(cov_quant == 0); // We should not have cov_quant in non-cov mode
		if (mode == kTarget)
		{
			bool ret = false;
			++cycle_count;
			// If we have already done more exploitation than exploration,
			// switch back to exploration again.
			if (exploitation_quant >= exploration_quant * config.exp_ratio ||
				reached_targets->fringes.empty() || // If no reached target, skip
				config.disable_mode[kTarget])
			{
				mode = kProFringe;
				cycle_count = 0;
				if (reset_exploit || config.uni_whole_cycle)
				{
					reset_exploit = false;
				}
				else
				{
					++whole_count; // Only inc when exploitation is not resetted
					ret = true;
				}
			}
			return ret;
		}
		assert(cycle_count < config.max_cycle_count);
		if (mode == kProFringe)
		{
			if (++cycle_count == config.max_cycle_count ||
				path_pro_fringes->fringes.empty() || // If no pro fringe, skip
				config.disable_mode[kProFringe])
			{
				mode = kFringe;
				cycle_count = 0;
			}
		}
		else
		{
			assert(mode == kFringe);
			if (++cycle_count == config.max_cycle_count ||
				path_fringes->fringes.empty() || // If no fringe, skip
				config.disable_mode[kFringe])
			{
				mode = kCoverage;
				cycle_count = 0;
			}
		}
		return false;
	}

	void reset(u8 r)
	{
		if (init_cov)
			return; // Don't reset at initial coverage based stage
		switch (r)
		{
			case 2:
				return reset(kProFringe);
			case 1:
				return reset(kFringe);
			case 0:
				return reset(kCoverage);
			default: abort();
		}
	}

	// Reset to exploitation state directly
	void exploit()
	{
		if (mode == kUnite)
		{ // Unite mode always resets to it self when there is any target update
			cycle_count = -1;
			assert(cov_quant == 0);
			return;
		}
		// If already in exploitation, we don't reset itself,
		// this is different from situation in explorative mode.
		if (init_cov || mode == kTarget)
			return;
		reset_exploit = true;
		mode = kTarget;
		cycle_count = -1;
		cov_quant = 0;
	}

	void add_quant(double quant)
	{
		Mode m = get_mode();
		// We don't need to use quant in unite mode
		if (m == kUnite)
			return;

		if (m == kTarget)
		{
			exploitation_quant += quant;
		}
		else
		{
			exploration_quant += quant;
			if (m == kCoverage)
				cov_quant += quant;
		}
	}

	inline Mode get_mode() const { return mode; }
	inline bool is_reset() const { return cycle_count == -1; }
	inline bool is_init_cov() const { return init_cov; }
	inline void reset_cov_quant() { cov_quant = 0; }
	inline bool is_end_cov() const
	{
		if (init_cov)
			return cov_quant >= config.init_cov_quant;
		if (mode == kCoverage)
			return config.disable_mode[kCoverage] ||
				cov_quant >= config.max_cycle_count * config.cycle_energy;
		return false;
	}
	inline void get_counts(int& cycle, u32& cov) const
	{
		cycle = cycle_count;
		cov = cov_quant;
	}
};

AFLRunState state;

template <typename F>
inline size_t to_bitmap_idx(const F& f);

template <>
inline size_t to_bitmap_idx<Fringe>(const Fringe& f)
{
	return CTX_IDX(f.block, f.context);
}

template <typename F>
inline F from_bitmap_idx(size_t idx);

template <>
inline Fringe from_bitmap_idx<Fringe>(size_t idx)
{
	return Fringe(idx / CTX_SIZE, idx % CTX_SIZE);
}

template <typename F>
inline reach_t to_fringe_block(const F& f);

template <>
inline reach_t to_fringe_block<Fringe>(const Fringe& f)
{
	return f.block;
}

template <>
inline reach_t to_fringe_block<reach_t>(const reach_t& f)
{
	return f;
}

// Add new fringe to the given target
template <typename F, typename D>
void FringeBlocks<F, D>::add_fringe(
	const F& f, reach_t t, rh::unordered_set<D>&& decisives)
{
	target_to_fringes[t].insert(f);
	block_to_fringes[to_fringe_block<F>(f)].insert(f);
	for (const D& dec : decisives)
		decisive_to_fringes[dec].insert(f);
	auto p = fringes.emplace(f, Info());
	p.first->second.decisives.emplace(t, std::move(decisives));
	if (p.second)
	{
		freq_idx.emplace(f, freq.size());
		freq.emplace_back(to_bitmap_idx<F>(f), 0);
	}
}

// Return true if the block is removed
template <typename F, typename D>
bool FringeBlocks<F, D>::remove_block(const F& f)
{
	// Remove fringe from `block_to_fringes`
	auto it2 = block_to_fringes.find(to_fringe_block<F>(f));
	it2->second.erase(f);
	if (it2->second.empty())
	{
		block_to_fringes.erase(it2);
		return true;
	}
	return false;
}

// Remove the element in frequency array
template <typename F, typename D>
void FringeBlocks<F, D>::remove_freq(const F& f)
{
	auto i = freq_idx.find(f);
	if (i != freq_idx.end())
	{
		assert(freq[i->second].first == to_bitmap_idx<F>(f));
		assert(i->second < freq.size());
		if (i->second + 1 != freq.size())
		{
			// Remove the fringe from `freq` array
			freq[i->second] = freq.back();
			freq.pop_back();

			// Update index value in `freq_idx` map
			size_t idx = freq[i->second].first;
			freq_idx.find(from_bitmap_idx<F>(idx))->second = i->second;
			freq_idx.erase(i);
		}
		else
		{ // Special case: remove last element in `freq` array
			freq.pop_back();
			freq_idx.erase(i);
		}
	}
}

void try_disable_seed(u32 s)
{
	if (reached_targets->seed_fringes.count(s) == 0 &&
		path_pro_fringes->seed_fringes.count(s) == 0 &&
		path_fringes->seed_fringes.count(s) == 0)
	{ // If the seed is not used by aflrun now, try to disable it
		disable_aflrun_extra(g->afl, s);
	}
}

// Remove the fringe in given set of targets, return true if `f.block` is removed
template <typename F, typename D>
bool FringeBlocks<F, D>::del_fringe(const F& f, const vector<reach_t>& ts)
{
	auto it = fringes.find(f);
	assert(it != fringes.end());

	// Remove the fringe in given set of targets
	for (reach_t t : ts)
	{
		it->second.decisives.erase(t);
		target_to_fringes[t].erase(f);
	}

	// If given fringe in all targets is removed, remove the fringe itself
	if (it->second.decisives.empty())
	{
		auto seeds = std::move(it->second.seeds);
		fringes.erase(it);
		// Remove the all seeds reaching the deleted fringe
		for (u32 seed : seeds)
		{
			auto it3 = seed_fringes.find(seed);
			it3->second.erase(f);
			if (it3->second.empty())
			{
				seed_fringes.erase(it3);
				try_disable_seed(seed);
			}
		}
		remove_freq(f);
		return remove_block(f);
	}
	return false;
}

// Remove the fringe in all targets, return true if `f.block` is removed
template <typename F, typename D>
bool FringeBlocks<F, D>::del_fringe(const F& f)
{
	auto it = fringes.find(f);

	for (const auto& td : it->second.decisives)
	{
		target_to_fringes[td.first].erase(f);
	}
	it->second.decisives.clear();

	auto seeds = std::move(it->second.seeds);
	fringes.erase(it);

	for (u32 seed : seeds)
	{
		auto it3 = seed_fringes.find(seed);
		it3->second.erase(f);
		if (it3->second.empty())
		{
			seed_fringes.erase(it3);
			try_disable_seed(seed);
		}
	}
	remove_freq(f);
	return remove_block(f);
}

template <typename F>
inline void log_fringe(ostream& out, const F& f);

// Given `trace_ctx` of a `seed`, check its coverage of fringe and add if necessary
template <typename F, typename D>
bool FringeBlocks<F, D>::fringe_coverage(const u8* bitmap, u32 seed,
	const rh::unordered_set<Fringe>* new_criticals,
	const rh::unordered_set<reach_t>* new_bits_targets)
{
	// fringe_coverage for each seed should only be called once
	assert(seed_fringes.find(seed) == seed_fringes.end());
	rh::unordered_set<F> sf;
	for (auto& p : fringes)
	{
		const F& f = p.first;

		// If new_criticals is NULL, we think no new critical is found;
		// otherwise, we consider coverage only if `f` is new critical.
		bool is_new_critical = new_criticals ?
			(new_criticals->count(f) != 0) : false;
		// If new_bits_targets is NULL, we consider coverage of every critical,
		// so in other word, there is no seed isolation, used for non-extra seeds;
		// otherwise, we consider coverage only if `f` is target with new bits.
		bool is_new_bits_targets = new_bits_targets ?
			(new_bits_targets->count(f.block) != 0) : true;

		// We try coverage if at least one of them is true.
		if ((is_new_critical || is_new_bits_targets) &&
			IS_SET(bitmap, to_bitmap_idx<F>(f)))
		{ // If covered, add the seed
			p.second.seeds.insert(seed);
			sf.insert(f);
		}
	}
	if (!sf.empty())
	{
		ofstream out(g->out_dir + "seeds.txt", ios::app);
		out << seed << " | ";
		for (const auto& f : sf)
		{
			log_fringe<F>(out, f); out << ' ';
		}
		out << endl;
		seed_fringes.emplace(seed, std::move(sf));
		return true;
	}
	else
	{
		return false;
	}
}

// Increase frequency of fringe according to given trace exerted by mutated input
template <typename F, typename D>
void FringeBlocks<F, D>::inc_freq(const u8* bitmap)
{
	for (auto& p : freq)
	{
		if (IS_SET(bitmap, p.first))
		{
			p.second++;
		}
	}
}

template <typename F, typename D>
void FringeBlocks<F, D>::update_fuzzed_quant(u32 seed, double fuzzed_quant)
{
	// When fuzzing norm fringe, seed fuzzed can have no fringe in pro fringe.
	auto it = seed_fringes.find(seed);
	if (it == seed_fringes.end())
		return;
	const auto& fs = it->second;
	for (const F& f : fs)
	{ // For each of its fringe, add `fuzzed_quant`
		fringes.find(f)->second.fuzzed_quant += fuzzed_quant;
	}
}

template <typename F, typename D>
void FringeBlocks<F, D>::update_fringe_score(u32 seed)
{
	// If seed does not touch any fringe, skip
	auto it = seed_fringes.find(seed);
	if (it == seed_fringes.end())
		return;
	u64 fav_factor = get_seed_fav_factor(g->afl, seed);
	for (const F& f : it->second)
	{
		Info& info = fringes.find(f)->second;
		if (info.has_top_rated && fav_factor > info.top_rated_factor)
			continue;

		// Update top-rated seed and factor when possible
		assert(info.seeds.find(seed) != info.seeds.end());
		info.top_rated_seed = seed;
		info.top_rated_factor = fav_factor;
		info.has_top_rated = true;
	}
}

vector<double> seed_quant;

random_device rd;
mt19937 gen(rd());
uniform_int_distribution<> distrib(0, 99);

template <typename F, typename D>
rh::unordered_set<u32> FringeBlocks<F, D>::select_favored_seeds() const
{
	// Seeds that are considered favored
	rh::unordered_set<u32> favored;

	// Record all visited fringes
	rh::unordered_set<F> temp_v;

	for (const auto& p : fringes)
	{ // For each unvisited fringe, we get top rated seed, if any
		if (p.second.has_top_rated && temp_v.find(p.first) == temp_v.end())
		{
			// The seed must be contained in initial seed set,
			// because disabled seeds cannot be considered top-rated.
			u32 seed = p.second.top_rated_seed;

			// We insert all fringes the seed cover into visited set
			const auto& fs = seed_fringes.find(seed)->second;
			temp_v.insert(fs.begin(), fs.end());
			assert(temp_v.find(p.first) != temp_v.end());

			// Add seed to favored set
			favored.insert(seed);
		}
	}

	return favored;
}

template <typename F, typename D>
void FringeBlocks<F, D>::set_favored_seeds(const u32* seeds, u32 num)
{
	auto favored = select_favored_seeds();
	favored_seeds.clear();
	for (u32 i = 0; i < num; ++i)
	{
		if (favored.count(seeds[i]) > 0 || get_seed_div_favored(g->afl, seeds[i]))
			favored_seeds.insert(seeds[i]);
	}
}

template <typename F, typename D>
u32 FringeBlocks<F, D>::cull_queue(u32* seeds, u32 num)
{
	// Set containing original seeds
	const rh::unordered_set<u32> seed_set(seeds, seeds + num);

	auto favored = select_favored_seeds();
	for (u32 seed : favored)
		assert(seed_set.find(seed) != seed_set.end());

	// Select seeds to fuzz in this cycle
	u32 idx = 0;
	favored_seeds.clear();
	for (u32 seed : seed_set)
	{
		if (favored.find(seed) != favored.end() ||
			get_seed_div_favored(g->afl, seed))
			// `cull_queue_div` should be called first
		{
			seeds[idx++] = seed;
			favored_seeds.insert(seed);
		}
		else if (aflrun_get_seed_quant(seed) > 0)
		{ // If the unfavored seed is fuzzed before
			if (distrib(gen) >= SKIP_NFAV_OLD_PROB)
				seeds[idx++] = seed;
		}
		else
		{
			if (distrib(gen) >= SKIP_NFAV_NEW_PROB)
				seeds[idx++] = seed;
		}
	}
	return idx;
}

u32 cull_queue_unite(u32* seeds, u32 num)
{
	// Set containing original seeds
	const rh::unordered_set<u32> seed_set(seeds, seeds + num);

	u32 idx = 0;
	for (u32 seed : seed_set)
	{ // Similar to `cull_queue` above
		if (path_fringes->favored_seeds.count(seed) > 0 ||
			path_pro_fringes->favored_seeds.count(seed) > 0 ||
			reached_targets->favored_seeds.count(seed) > 0 ||
			get_seed_cov_favored(g->afl, seed) == 2)
		{
			seeds[idx++] = seed;
		}
		else if (aflrun_get_seed_quant(seed) > 0)
		{
			if (distrib(gen) >= SKIP_NFAV_OLD_PROB)
				seeds[idx++] = seed;
		}
		else
		{
			if (distrib(gen) >= SKIP_NFAV_NEW_PROB)
				seeds[idx++] = seed;
		}
	}

	return idx;
}

template <typename T>
void write_vec(ostream& o, const vector<T>& v)
{
	o << '[';
	for (T e : v)
	{
		o << e << ", ";
	}
	o << "]";
}

template <typename T>
void write_arr(ostream& o, const T* arr, size_t size)
{
	o << '[';
	for (size_t i = 0; i < size; ++i)
	{
		o << arr[i] << ", ";
	}
	o << "]";
}

template <typename F, typename D>
pair<unique_ptr<double[]>, unique_ptr<double[]>>
	FringeBlocks<F, D>::allocate_ratio(
	const rh::unordered_map<reach_t, FringeInfo>& fringe_info,
	const vector<reach_t>& vec_fringes) const
{
	assert(fringe_info.size() == vec_fringes.size());
	size_t num_fringes = vec_fringes.size();
	struct Elem
	{
		reach_t target;
		rh::unordered_set<reach_t> fringes;
		Elem(reach_t target, rh::unordered_set<reach_t>&& fringes) :
			target(target), fringes(std::move(fringes)) {}
	};

	// We firstly get fringes of each active target
	vector<Elem> targets_info;
	for (reach_t t = 0; t < target_to_fringes.size(); ++t)
	{
		const auto& tf = target_to_fringes[t];

		// Skip targets without fringe
		if (tf.empty())
			continue;

		rh::unordered_set<reach_t> fringes;
		for (const F& f : tf)
		{
			fringes.insert(f.block);
		}
		targets_info.emplace_back(t, std::move(fringes));
	}

	// Allocate weight of each target to its fringes
	auto static_weights = make_unique<double[]>(num_fringes);
	auto ret = make_unique<double[]>(num_fringes);
	for (const Elem& e : targets_info)
	{
		rh::unordered_map<reach_t, double> res;
		dist_block_ratio(e.fringes, e.target, g->get_tw(e.target), res);
		for (const auto& fw : res)
		{
			static_weights[fringe_info.find(fw.first)->second.idx] += fw.second;
		}
	}

	double sum = 0;
	for (size_t i = 0; i < num_fringes; ++i)
	{
		double w = static_weights[i];
		ret[i] = w;
		sum += w;
	}
	for (size_t i = 0; i < num_fringes; ++i)
	{
		ret[i] /= sum;
	}
	return make_pair<>(std::move(ret), std::move(static_weights));
}

u32 num_active_seeds = 0;
void trim_new_cvx(
	rh::unordered_map<u32, double>& seed_weight, double& all_sum, double total)
{
	bool trimed;
	do
	{
		double total_after = total;
		vector<tuple<u32, double, double>> seed_weight_prev;
		seed_weight_prev.reserve(seed_weight.size());

		// Flatten the unordered map, also add `prev`,
		// and calculate total energy after the allocation.
		for (const auto& sw : seed_weight)
		{
			double prev = aflrun_get_seed_quant(sw.first);
			total_after += prev;
			seed_weight_prev.emplace_back(sw.first, sw.second, prev);
		}

		double sum = all_sum;
		trimed = false;
		for (const auto& swp : seed_weight_prev)
		{
			// If previous energy is already >= than desired energy calculated
			// from desired ratio, we will not allocate energy to it, so it can
			// be removed for optimization.
			if (get<2>(swp) >= total_after * get<1>(swp) / sum)
			{
				seed_weight.erase(get<0>(swp));
				all_sum -= get<1>(swp);
				trimed = true;
			}
		}

	// We recursively trim, until there is no trimming happens
	} while (trimed);
}

vector<pair<u32, double>> solve_new_cvx(
	const rh::unordered_map<u32, double>& seed_weight, double sum, double total)
{
	// Same as above
	double total_after = total;
	vector<tuple<u32, double, double>> seed_weight_prev;
	seed_weight_prev.reserve(seed_weight.size());
	for (const auto& sw : seed_weight)
	{
		double prev = aflrun_get_seed_quant(sw.first);
		total_after += prev;
		seed_weight_prev.emplace_back(sw.first, sw.second, prev);
	}

	vector<pair<u32, double>> ret;
	for (const auto& swp : seed_weight_prev)
	{ // After trimming, desired energy must be larger than previous energy
		double seed_energy = total_after * get<1>(swp) / sum - get<2>(swp);
		assert(seed_energy > 0);

		// TODO: potential precision problem?
		ret.emplace_back(get<0>(swp), seed_energy);
	}

	return ret;
}

template <typename F, typename D>
void FringeBlocks<F, D>::record_new_cvx_opt(
	const vector<pair<reach_t, rh::unordered_set<reach_t>>>& target_fringes,
	const rh::unordered_map<reach_t, double>& block_weight,
	const rh::unordered_map<u32, double>& seed_ratio,
	const vector<pair<u32, double>>& sol) const
{
	ofstream out(g->out_dir + "cvx/opt.py");
	if (!out.is_open())
		return;

	out << "import numpy as np" << endl;

	// Output normalized weights of targets
	double sum = 0;
	for (const auto& t : target_fringes)
		sum += g->get_tw(t.first);
	out << "target_weight = np.array([" << endl;
	out << "# target, ratio" << endl;
	for (const auto& t : target_fringes)
		out << "[\"" << g->reachable_names[t.first] <<
			"\", " << g->get_tw(t.first) / sum << "]," << endl;
	out << "])" << endl;

	// Output normalized weights of blocks
	sum = 0;
	for (const auto& bw : block_weight)
		sum += bw.second;
	out << "block_weight = np.array([" << endl;
	out << "# block, ctx_count, ratio" << endl;
	for (const auto& bw : block_weight)
		out << "[\"" << g->reachable_names[bw.first] <<
			"\", " << block_to_fringes.find(bw.first)->second.size() <<
			", " << bw.second / sum << "]," << endl;
	out << "])" << endl;

	out << "opt = np.array([" << endl;
	out << "# seed, prev, ratio, solution" << endl;

	rh::unordered_set<u32> non_zero_seeds;
	for (const auto& se : sol)
	{
		out << '[' << se.first << ", " << aflrun_get_seed_quant(se.first) <<
			", " << seed_ratio.find(se.first)->second << ", " <<
			se.second << "]," << endl;
		non_zero_seeds.insert(se.first);
	}
	for (const auto& sr : seed_ratio)
	{
		if (non_zero_seeds.count(sr.first) > 0)
			continue;
		out << '[' << sr.first << ", " << aflrun_get_seed_quant(sr.first) <<
			", " << sr.second << ", " << 0.0 << "]," << endl;
	}
	out << "])" << endl;
}

void record_new_cvx_opt_uni(
	const vector<pair<reach_t, array<double, 3>>>& target_type_weights,
	const array<rh::unordered_map<reach_t, double>, 3>& block_weights,
	const array<rh::unordered_map<u32, double>, 4>& seed_weights,
	const double* seed_sums, const rh::unordered_map<u32, double>& seed_ratio,
	const vector<pair<u32, double>>& sol)
{
	ofstream out(g->out_dir + "cvx/opt.py");
	if (!out.is_open())
		return;
	out << "import numpy as np" << endl;

	// Output normalized weights of targets for each type
	double sum = 0;
	for (const auto& ttw : target_type_weights)
		for (size_t i = 0; i < 3; ++i)
			sum += ttw.second[i];
	out << "target_weights = np.array([" << endl;
	out << "# target, N ratio, P ratio, T ratio" << endl;
	for (const auto& ttw : target_type_weights)
	{
		out << "[\"" << g->reachable_names[ttw.first] << "\"";
		for (size_t i = 0; i < 3; ++i)
			out << ", " << ttw.second[i] / sum;
		out << "]," << endl;
	}
	out << "])" << endl;

	// Output normalized weights of blocks for each mode
	function<size_t(u32)> ctx_count[3] = {
		[](u32 s) -> size_t
		{
			return path_fringes->block_to_fringes.find(s)->second.size();
		},
		[](u32 s) -> size_t
		{
			return path_pro_fringes->block_to_fringes.find(s)->second.size();
		},
		[](u32 s) -> size_t
		{
			return reached_targets->block_to_fringes.find(s)->second.size();
		},
	};
	const char* names = "NPT";
	for (size_t i = 0; i < 3; ++i)
	{
		sum = 0;
		for (const auto& btw : block_weights[i])
			sum += btw.second;
		out << "block_weight_" << names[i] << " = np.array([" << endl;
		out << "# block, ctx_count, ratio" << endl;
		for (const auto& btw : block_weights[i])
			out << "[\"" << g->reachable_names[btw.first] <<
				"\", " << ctx_count[i](btw.first) <<
				", " << btw.second / sum << "]," << endl;
		out << "])" << endl;
	}

	out << "opt = np.array([" << endl;
	out << "# seed, prev, ratio, solution, N, P, T, C" << endl;
	rh::unordered_set<u32> non_zero_seeds;
	double weight_sums[4] = {0,0,0,0}; double ratio_sum = 0;
	auto log_seed_weights =
	[&seed_weights, &out, &weight_sums](u32 seed)
	{
		for (size_t i = 0; i < 4; ++i)
		{
			auto it = seed_weights[i].find(seed);
			double val = it == seed_weights[i].end() ? 0.0 : it->second;
			out << ", " << val;
			weight_sums[i] += val;
		}
	};
	for (const auto& se : sol)
	{
		double ratio = seed_ratio.find(se.first)->second;
		ratio_sum += ratio;
		out << '[' << se.first << ", " << aflrun_get_seed_quant(se.first) <<
			", " << ratio << ", " << se.second;
		log_seed_weights(se.first);
		out << "]," << endl;
		non_zero_seeds.insert(se.first);
	}
	for (const auto& sr : seed_ratio)
	{
		if (non_zero_seeds.count(sr.first) > 0)
			continue;
		ratio_sum += sr.second;
		out << '[' << sr.first << ", " << aflrun_get_seed_quant(sr.first) <<
			", " << sr.second << ", " << 0.0;
		log_seed_weights(sr.first);
		out << "]," << endl;
	}
	out << "])" << endl;
	out << "# " << ratio_sum;
	for (size_t i = 0; i < 4; ++i)
	{
		out << ' ' << seed_sums[i] << "==" << weight_sums[i];
	}
	out << endl;
}

template <typename F, typename D>
void FringeBlocks<F, D>::assign_seeds_covered(
	const rh::unordered_set<u32>& seeds, double total_weight,
	const rh::unordered_map<u32, u32>& seed_to_idx,
	rh::unordered_map<u32, double>& seed_weight, double& all_sum) const
{
	// For all seeds that cover this context block,
	// we get their expected performance scores, and calculate their sum.
	vector<pair<u32, double>> seed_perf_score;
	double sum = 0;
	for (u32 s : seeds)
	{
		// Skip seeds not selected for fuzzing
		if (seed_to_idx.count(s) == 0)
			continue;
		double e_perf_score = get_seed_perf_score(g->afl, s) *
			(favored_seeds.find(s) == favored_seeds.end() ?
				(100 - SKIP_NFAV_OLD_PROB) / 100.0 : 1.0);
		// Skip non-positive seeds,
		// which is not quite possible but we do it anyway
		if (e_perf_score <= 0)
			continue;
		seed_perf_score.emplace_back(s, e_perf_score);
		sum += e_perf_score;
	}

	for (const auto& sps : seed_perf_score)
	{ // Allocate weight of seeds according to ratio of performance scores
		double w = total_weight * sps.second / sum;
		seed_weight[sps.first] += w;
		all_sum += w;
	}
}

rh::unordered_map<u32, double> assign_seeds_coverage(
	const u32* seeds, u32 num, double cov_sum)
{
	vector<pair<u32, double>> seed_perf_score;
	double sum = 0;
	for (u32 i = 0; i < num; ++i)
	{
		u8 level = get_seed_cov_favored(g->afl, seeds[i]);
		if (!config.extra_cov && level == 0) // Skip aflrun extra seeds
			continue;
		double e_perf_score = get_seed_perf_score(g->afl, seeds[i]) *
			(level == 2 ? 1.0 : (100 - SKIP_NFAV_OLD_PROB) / 100.0);
		if (e_perf_score <= 0)
			continue;
		seed_perf_score.emplace_back(seeds[i], e_perf_score);
		sum += e_perf_score;
	}

	rh::unordered_map<u32, double> ret;
	for (const auto& sps : seed_perf_score)
		ret.emplace(sps.first, cov_sum * sps.second / sum);
	return ret;
}

template <typename F, typename D>
pair<rh::unordered_map<u32, double>, double>
	FringeBlocks<F, D>::assign_seed_no_ctx(
	const rh::unordered_map<reach_t, double>& block_weight,
	const rh::unordered_map<u32, u32>& seed_to_idx) const
{
	// Here we assign energy from fringe to seed directly, without context pass.
	rh::unordered_map<u32, double> seed_weight;
	double all_sum = 0;
	for (const auto& bw : block_weight)
	{
		const auto& ctx_blocks = block_to_fringes.find(bw.first)->second;
		assert(!ctx_blocks.empty());
		rh::unordered_set<u32> seeds;
		for (const F& cb : ctx_blocks)
		{ // Collect all seeds that cover this fringe
			assert(cb.block == bw.first);
			const Info& info = fringes.find(cb)->second;
			seeds.insert(info.seeds.begin(), info.seeds.end());
		}

		assign_seeds_covered(
			seeds, bw.second, seed_to_idx, seed_weight, all_sum);
	}

	return make_pair(seed_weight, all_sum);
}

template <typename F, typename D>
pair<rh::unordered_map<u32, double>, double> FringeBlocks<F, D>::assign_seed_ctx(
	const rh::unordered_map<reach_t, double>& block_weight,
	const rh::unordered_map<u32, u32>& seed_to_idx) const
{
	// Map context block to weight being allocated from parent block
	rh::unordered_map<Fringe, double> ctx_block_weight;
	for (const auto& bw : block_weight)
	{
		const auto& ctx_blocks = block_to_fringes.find(bw.first)->second;
		assert(!ctx_blocks.empty());
		for (const F& cb : ctx_blocks)
		{ // Allocate weight of each block uniformly to its context blocks
			assert(cb.block == bw.first && ctx_block_weight.count(cb) == 0);
			ctx_block_weight.emplace(cb, bw.second / ctx_blocks.size());
		}
	}

	// Map seed to weight being allocated from context blocks it covers
	rh::unordered_map<u32, double> seed_weight;
	double all_sum = 0;
	for (const auto& cbw : ctx_block_weight)
	{
		const Info& info = fringes.find(cbw.first)->second;
		assign_seeds_covered(
			info.seeds, cbw.second, seed_to_idx, seed_weight, all_sum);
	}

	return make_pair(seed_weight, all_sum);
}

template <typename F, typename D>
pair<rh::unordered_map<u32, double>, double> FringeBlocks<F, D>::assign_seed(
	const rh::unordered_map<reach_t, double>& block_weight,
	const rh::unordered_map<u32, u32>& seed_to_idx) const
{
	if (config.assign_ctx)
		return assign_seed_ctx(block_weight, seed_to_idx);
	else
		return assign_seed_no_ctx(block_weight, seed_to_idx);
}

template <typename F, typename D>
void FringeBlocks<F, D>::assign_energy(
	u32 num_seeds, const u32* ss, double* ret) const
{
	// Map seed to index to the return array
	rh::unordered_map<u32, u32> seed_to_idx;
	for (u32 i = 0; i < num_seeds; ++i)
		seed_to_idx.emplace(ss[i], i);
	assert(seed_to_idx.size() == num_seeds);

	vector<pair<reach_t, rh::unordered_set<reach_t>>> target_fringes;

	for (reach_t t = 0; t < target_to_fringes.size(); ++t)
	{ // Iterate all targets with any fringes
		const auto& tf = target_to_fringes[t];
		if (tf.empty())
			continue;

		// Record all fringes a target has
		rh::unordered_set<reach_t> fringes;
		for (const F& f : tf)
			fringes.insert(f.block);
		target_fringes.emplace_back(t, std::move(fringes));
	}

	// Map fringe block to weight being allocated from targets
	rh::unordered_map<reach_t, double> block_weight;
	for (const auto& e : target_fringes)
	{
		dist_block_ratio(
			e.second, e.first, g->get_tw(e.first), block_weight);
	}

	rh::unordered_map<u32, double> seed_weight; double all_sum;
	tie(seed_weight, all_sum) = assign_seed(block_weight, seed_to_idx);

	// Original seed ratio, used for output only
	rh::unordered_map<u32, double> seed_ratio;
	for (const auto& sw : seed_weight)
		seed_ratio.emplace(sw.first, sw.second / all_sum);

	const double total = max<double>(
		num_active_seeds * config.linear_cycle_energy, config.cycle_energy);
	trim_new_cvx(seed_weight, all_sum, total);
	auto sol = solve_new_cvx(seed_weight, all_sum, total);

	fill(ret, ret + num_seeds, 0.0);
	for (const auto& se : sol)
		ret[seed_to_idx.find(se.first)->second] = se.second;

	record_new_cvx_opt(target_fringes, block_weight, seed_ratio, sol);
}

rh::unordered_set<reach_t> strip_ctx(const rh::unordered_set<Fringe>& from)
{
	// Record all blocks a target has
	rh::unordered_set<reach_t> blocks;
	for (const Fringe& f : from)
		blocks.insert(f.block);
	return blocks;
}

void sum_seed_weight(
	rh::unordered_map<u32, double>& seed_weight, double& all_sum,
	const rh::unordered_map<u32, double>& tmp_weight, double tmp_sum)
{
	all_sum += tmp_sum;
	for (const auto& sw : tmp_weight)
		seed_weight[sw.first] += sw.second;
}

void assign_energy_unite(u32 num_seeds, const u32* ss, double* ret)
{
	// Map seed to index to the return array
	rh::unordered_map<u32, u32> seed_to_idx;
	for (u32 i = 0; i < num_seeds; ++i)
		seed_to_idx.emplace(ss[i], i);
	assert(seed_to_idx.size() == num_seeds);

	constexpr size_t kNumTypes = 3;
	// [0]: ctx_fringes; [1]: pro_fringes; [2]: targets
	using FringeEach = array<rh::unordered_set<reach_t>, kNumTypes>;
	vector<pair<reach_t, FringeEach>> target_fringes;
	for (reach_t t = 0; t < g->num_targets; ++t)
	{ // For each target, we get its fringes from all 3 types, if any
		FringeEach tf;
		if (config.unite_ratio[1] > 0)
			tf[0] = strip_ctx(path_fringes->target_to_fringes[t]);
		if (config.unite_ratio[2] > 0)
			tf[1] = strip_ctx(path_pro_fringes->target_to_fringes[t]);
		if (config.unite_ratio[3] > 0)
			tf[2] = strip_ctx(reached_targets->target_to_fringes[t]);

		// If the target has no block in any of these, skip it
		if (tf[0].empty() && tf[1].empty() && tf[2].empty())
			continue;

		target_fringes.emplace_back(t, std::move(tf));
	}

	// Map target to weights of 3 types, whose sum should be target weight
	vector<pair<reach_t, array<double, kNumTypes>>> target_type_weights;
	for (const auto& e : target_fringes)
	{
		array<double, kNumTypes> type_weights; double sum = 0;
		for (size_t i = 0; i < kNumTypes; ++i)
		{
			double ratio = config.unite_ratio[i + 1];
			if (e.second[i].empty() || ratio == 0)
			{ // For each non-active type, we skip it by setting weight to zero.
				type_weights[i] = 0;
			}
			else
			{ // For each active type, we sum and record the ratio.
				sum += ratio;
				type_weights[i] = ratio;
			}
		}
		assert(sum > 0);

		// Assign `type_weights` from `tw` according to the ratio
		double tw = g->get_tw(e.first);
		for (size_t i = 0; i < kNumTypes; ++i)
		{
			type_weights[i] = tw * type_weights[i] / sum;
		}

		target_type_weights.emplace_back(e.first, std::move(type_weights));
	}
	assert(target_fringes.size() == target_type_weights.size());

	// Now we can allocate weight for each block
	array<rh::unordered_map<reach_t, double>, kNumTypes> block_weights;
	for (size_t i = 0; i < kNumTypes; ++i)
	{
		// For each type, we iterate its active targets,
		// each of which has a weight and a set of blocks;
		// we can imagine this to be allocation of
		// `target_weights` -> `block_weight` in non-unite modes.
		auto tf_it = target_fringes.begin();
		auto ttw_it = target_type_weights.begin();
		for (; tf_it != target_fringes.end(); ++tf_it, ++ttw_it)
		{
			assert(tf_it->first == ttw_it->first);
			double ttw = ttw_it->second[i];
			if (ttw == 0) // Skip non-active targets
				continue;
			dist_block_ratio(
				tf_it->second[i], tf_it->first, ttw, block_weights[i]);
		}
	}

	// Assign seed for each block_weights[i], and sum them together
	rh::unordered_map<u32, double> seed_weight; double all_sum = 0;
	array<rh::unordered_map<u32, double>, kNumTypes + 1> type_seed_weight;
	double type_sum[kNumTypes + 1];
	tie(type_seed_weight[0], type_sum[0]) =
		path_fringes->assign_seed(block_weights[0], seed_to_idx);
	sum_seed_weight(seed_weight, all_sum, type_seed_weight[0], type_sum[0]);
	tie(type_seed_weight[1], type_sum[1]) =
		path_pro_fringes->assign_seed(block_weights[1], seed_to_idx);
	sum_seed_weight(seed_weight, all_sum, type_seed_weight[1], type_sum[1]);
	tie(type_seed_weight[2], type_sum[2]) =
		reached_targets->assign_seed(block_weights[2], seed_to_idx);
	sum_seed_weight(seed_weight, all_sum, type_seed_weight[2], type_sum[2]);

	// Calculate total weight for coverage background according to ratios
	type_sum[3] = 0; size_t count = 0;
	for (size_t i = 0; i < kNumTypes; ++i)
	{
		if (type_sum[i] > 0)
		{
			double ratio = config.unite_ratio[i + 1]; assert(ratio > 0);
			type_sum[3] += type_sum[i] * config.unite_ratio[0] / ratio;
			++count;
		}
	}

	if (count == 0)
	{ // If no reachable block is covered, do coverage mode
		assert(all_sum == 0 && seed_weight.empty());
		all_sum = 1;
		seed_weight = assign_seeds_coverage(ss, num_seeds, all_sum);
	}
	else
	{
		type_sum[3] /= count; // Take the average

		if (type_sum[3] > 0)
		{
			type_seed_weight[3] =
				assign_seeds_coverage(ss, num_seeds, type_sum[3]);
			sum_seed_weight(
				seed_weight, all_sum, type_seed_weight[3], type_sum[3]);
		}
	}

	// Original seed ratio, used for output only
	rh::unordered_map<u32, double> seed_ratio;
	for (const auto& sw : seed_weight)
		seed_ratio.emplace(sw.first, sw.second / all_sum);

	// Finally we get the correct `seed_weight` just like before,
	// we solve it as the final energy assignment.
	const double total = max<double>(
		num_active_seeds * config.linear_cycle_energy, config.cycle_energy);
	trim_new_cvx(seed_weight, all_sum, total);
	auto sol = solve_new_cvx(seed_weight, all_sum, total);

	fill(ret, ret + num_seeds, 0.0);
	for (const auto& se : sol)
		ret[seed_to_idx.find(se.first)->second] = se.second;

	record_new_cvx_opt_uni(target_type_weights, block_weights,
		type_seed_weight, type_sum, seed_ratio, sol);
}

unique_ptr<AFLRunGraph> graph = nullptr;

rh::unordered_map<reach_t, double> bb_to_avg_dists;

rh::unordered_map<string, reach_t> name_to_id, fname_to_id;
vector<string> id_to_fname;

// Array of traces for each target
// e.g. (*all_exec_paths[id])[target].data()
vector<unique_ptr<reach_t[]>> all_exec_paths;

template <>
inline void log_fringe<Fringe>(ostream& out, const Fringe& f)
{
	if (f.block == g->num_reachables)
	{ // For printing cluster only
		assert(f.context == 0);
		out << "primary";
	}
	else
	{
		char hex_buf[4];
		snprintf(hex_buf, sizeof(hex_buf), "%.2X", f.context);
		out << g->reachable_names[f.block] << ',' << hex_buf;
	}
}

template <>
inline void log_fringe<reach_t>(ostream& out, const reach_t& f)
{
	out << g->reachable_names[f];
}

// template<typename F>
// F target_trace_to_fringe(const T* targets, size_t idx);

// template<>
// Fringe target_trace_to_fringe<Fringe, ctx_t>(
// 	const ctx_t* targets, size_t idx)
// {
// 	// Pseudo fringe representing primary map
// 	if (idx == 0)
// 		return Fringe(g->num_reachables, 0);
// 	else
// 	{
// 		const ctx_t* t = targets + (idx - 1);
// 		return Fringe(t->block, t->call_ctx);
// 	}
// }

// template<>
// reach_t target_trace_to_fringe<reach_t, reach_t>(
// 	const reach_t* targets, size_t idx)
// {
// 	return idx == 0 ? g->num_reachables : targets[idx - 1];
// }

struct ClusterPair
{
private:
	size_t fst; size_t snd;
public:
	inline size_t get_fst() const noexcept
	{
		return fst;
	}
	inline size_t get_snd() const noexcept
	{
		return snd;
	}
	bool operator==(const ClusterPair& rhs) const
	{
		return this->fst == rhs.fst && this->snd == rhs.snd;
	}
	explicit ClusterPair(size_t c1, size_t c2)
	{ // Make the pair order insensitive such that `fst <= snd` always holds
		assert(c1 != c2);
		if (c1 < c2)
		{
			fst = c1;
			snd = c2;
		}
		else
		{
			fst = c2;
			snd = c1;
		}
	}
};

template<typename F>
class Clusters
{
private:
	rh::unordered_map<F, size_t> target_to_idx;
	vector<rh::unordered_set<F>> clusters; // Reverse of `target_to_idx`
	vector<unique_ptr<u8[]>> cluster_maps;
	vector<unique_ptr<void*[]>> cluster_tops;

	// Each pair of the vector stores 64 `and` bit sequences corresponding to
	// each virgin map including the primary map, and first `u64` is a `or`
	// value of all values in the `vector`, so we don't need to consider 0 seqs.
	vector<pair<u64, unique_ptr<vector<u64>>>> and_bit_seqs;

	// Support count for single target or a pair of targets
	rh::unordered_map<ClusterPair, double> pair_supp_cnt;
	vector<double> supp_cnt;

	bool cluster_valid(size_t cluster) const
	{
		return cluster == 0 || cluster_maps[cluster] != nullptr;
	}

	// Merge cluster `src` to cluster `dst`;
	// after this function, `src` cluster is invalid.
	void merge_cluster(size_t src, size_t dst)
	{
		// `src` cannot be primary cluster, and cannot be invalid cluster
		assert(src != dst && cluster_maps[src] != nullptr && cluster_valid(dst));
		rh::unordered_set<F> src_cluster(std::move(clusters[src]));
		for (F t : src_cluster)
			target_to_idx.find(t)->second = dst;
		clusters[dst].insert(src_cluster.begin(), src_cluster.end());
		cluster_maps[src] = nullptr; cluster_tops[src] = nullptr;
		// We don't clean support counts with `src` here,
		// because they cannot be used again.
	}

	inline static bool supp_cnt_enough(double lhs, double both)
	{
		return config.single_supp_thr ?
			lhs >= config.supp_cnt_thr : both >= config.supp_cnt_thr;
	}

	// Try to merge clusters, if any; return true iff merge happens
	bool try_merge()
	{
		// Store each LHS->RHS to be merged and corresponding confidence value
		rh::unordered_map<size_t, pair<size_t, double>> to_merge;

		for (const auto& p : pair_supp_cnt)
		{ // Iterate each pair support count
			size_t fst = p.first.get_fst();
			size_t snd = p.first.get_snd();

			// Check if snd->fst reach merge threshold
			double snd_supp_cnt = supp_cnt[snd];
			if (supp_cnt_enough(snd_supp_cnt, p.second))
			{
				double conf = p.second / snd_supp_cnt;
				if (conf >= config.conf_thr)
				{ // If snd->fst reach merge threshold, merge snd into fst
					auto p2 = make_pair(fst, conf);
					auto p3 = to_merge.emplace(snd, p2);
					// If existing element has less confidence, replace
					if (!p3.second && p3.first->second.second < conf)
						p3.first->second = p2;
				}
			}

			// Note that we should not merge primary map to anything
			if (fst == 0) continue;

			// Check fst->snd, same as above
			double fst_supp_cnt = supp_cnt[fst];
			if (supp_cnt_enough(fst_supp_cnt, p.second))
			{
				double conf = p.second / fst_supp_cnt;
				if (conf >= config.conf_thr)
				{
					auto p2 = make_pair(snd, conf);
					auto p3 = to_merge.emplace(fst, p2);
					if (!p3.second && p3.first->second.second < conf)
						p3.first->second = p2;
				}
			}
		}

		if (to_merge.empty()) return false;

		// Todo: Merge may be optimized using Kosaraju's algorithm.
		for (const auto& p : to_merge)
		{
			size_t src = p.first;
			size_t dst = p.second.first;
			// We are going to merge src to dst, but dst can already be invalid,
			// so we need to walk to find a valid cluster to merge
			while (!cluster_valid(dst))
			{ // Walk through the graph until `dst` is valid
				dst = to_merge.find(dst)->second.first;
			}
			// If they finally become same cluster, we don't merge
			if (src != dst)
				merge_cluster(src, dst);
		}

		clean_supp_cnts();

		return true;
	}

public:

	// Index 0 prepresent primary map, which is not stored here.
	Clusters() : clusters(1), cluster_maps(1), cluster_tops(1), supp_cnt(1) {}

	void clean_supp_cnts()
	{
		vector<ClusterPair> to_remove;
		for (const auto& p : pair_supp_cnt)
		{
			if (!cluster_valid(p.first.get_fst()) ||
				!cluster_valid(p.first.get_snd()))
				to_remove.push_back(p.first);
		}
		for (const auto& p : to_remove)
		{
			pair_supp_cnt.erase(p);
		}
	}

	// Given a context-sensitive target, return corresponding cluster index;
	// this may also create a new cluster, for example, when target is new.
	size_t get_cluster(F target)
	{
		/*
		Currently `get_cluster` allocate each different target with a new cluster,
		but this is going to be changed when clustering algorithm is implemented.
		*/
		size_t num_clusters = cluster_maps.size();
		auto res = target_to_idx.emplace(target, num_clusters);
		if (res.second)
		{
			auto v = make_unique<u8[]>(g->map_size);
			fill(v.get(), v.get() + g->map_size, 255);
			cluster_maps.push_back(std::move(v));
			cluster_tops.push_back(make_unique<void*[]>(g->map_size));
			clusters.emplace_back(initializer_list<F>{target});
			supp_cnt.push_back(0);
			return num_clusters;
		}
		else
		{
			return res.first->second;
		}
	}
	// Return virgin map of given cluster, cluster id must < num of clusters
	u8* get_virgin_map(size_t cluster) const
	{
		return cluster_maps[cluster].get();
	}
	void** get_top_rated(size_t cluster) const
	{
		return cluster_tops[cluster].get();
	}
	const rh::unordered_set<F>& get_targets(size_t cluster) const
	{
		return clusters[cluster];
	}
	size_t size(void) const
	{
		return clusters.size();
	}
	size_t get_all_tops(void*** ret_tops, u8 mode) const
	{
		// Instead of get all top_rated maps,
		// we only get ones corresponding to fringe blocks of current state.
		const rh::unordered_map<reach_t, rh::unordered_set<Fringe>>* blocks;
		switch (mode)
		{
		case AFLRunState::kFringe:
			blocks = &path_fringes->block_to_fringes;
			break;
		case AFLRunState::kProFringe:
			blocks = &path_pro_fringes->block_to_fringes;
			break;
		case AFLRunState::kTarget:
			blocks = &reached_targets->block_to_fringes;
			break;
		default:
			abort();
		}
		size_t idx = 0;
		bo::dynamic_bitset<> visited_clusters(size());
		for (const auto& b : *blocks)
		{
			auto it = target_to_idx.find(b.first);
			if (it == target_to_idx.end() || visited_clusters[it->second] ||
				cluster_tops[it->second] == nullptr)
				continue;

			visited_clusters[it->second] = true;
			ret_tops[idx++] = cluster_tops[it->second].get();
		}
		return idx;
	}
	void add_bit_seq(u64 or_all, unique_ptr<vector<u64>>&& seq)
	{
		and_bit_seqs.emplace_back(or_all, std::move(seq));
	}
	void commit_bit_seqs(const size_t* clusters, size_t num)
	{
		if (and_bit_seqs.empty()) return;

		// Sequences representing all ones in bit arrays
		vector<vector<size_t>> sequences;

		for (const auto& seq : and_bit_seqs)
		{
			u64 or_all = seq.first;
			assert(seq.second->size() == num);
			for (size_t i = 0; or_all != 0; ++i, or_all >>= 1)
			{ // Iterate each bit of `or_all`, and process these `1` bits
				if ((or_all & 1) == 0)
					continue;

				vector<size_t> sequence;
				size_t j = 0; auto it = seq.second->begin();
				for (; it != seq.second->end(); ++it, ++j)
				{ // Iterate bit sequence `i`
					if (((*it) & (1uLL << i)) != 0uLL)
					{
						sequence.push_back(clusters[j]);
					}
				}
				assert(!sequence.empty()); // Sequence must have at least one `1`
				sequences.push_back(std::move(sequence));
			}
		}
		and_bit_seqs.clear();
		// If count using seed, we should deem each sequence as a factor count.
		double w_each = config.count_seed ? 1.0 / sequences.size() : 1.0;

		bool if_try = false;
		for (const auto& seq : sequences)
		{
			for (auto i = seq.begin(); i != seq.end(); ++i)
			{ // For each cluster, increment support count
				double cnt_after = (supp_cnt[*i] += w_each);
				if_try = if_try || cnt_after >= config.supp_cnt_thr;
				for (auto j = i + 1; j != seq.end(); ++j)
				{ // For each cluster pair, increment pair support count
					pair_supp_cnt[ClusterPair(*i, *j)] += w_each;
				}
			}
		}

		if (if_try)
		{ // Only try to merge if there is any support count >= threshold
			while (try_merge()) {}
		}

	}
	// Move `b` from its cluster to primary cluster,
	// if original cluster becomes empty, remove the cluster.
	void invalidate_div_block(F b)
	{
		// Find corresponding cluster
		auto it = target_to_idx.find(b);
		auto& cluster = clusters[it->second];
		assert(cluster.find(b) != cluster.end());

		// Move `b` to primary map
		cluster.erase(b);
		clusters.front().insert(b);

		if (cluster.empty())
		{ // If it is the last seed in the corpus, we remove the cluster
			cluster_maps[it->second] = nullptr;
			cluster_tops[it->second] = nullptr;
		}
		it->second = 0;
	}
	void remove_div_block(F b)
	{ // To remove a div block, we need delete corresponding `target_to_idx`.
		// If final cluster is also empty, we delete the cluster.

		// Find corresponding cluster
		auto it = target_to_idx.find(b);
		auto& cluster = clusters[it->second];
		assert(cluster.find(b) != cluster.end());

		cluster.erase(b);
		if (cluster.empty())
		{
			cluster_maps[it->second] = nullptr;
			cluster_tops[it->second] = nullptr;
		}
		target_to_idx.erase(it);
	}
	void print(ostream& out) const
	{
		out << "Clusters" << endl;
		size_t c = 0; auto it = clusters.begin();
		for (; it != clusters.end(); ++it, ++c)
		{
			const auto& cluster = *it;
			if (cluster.empty())
				continue;
			out << c << " | ";
			for (const F& t : cluster)
			{
				log_fringe<F>(out, t); out << ' ';
			}
			out << endl;
		}
		out << "Confidence Values" << endl;

		vector<ClusterPair> to_erase;
		for (const auto& p : pair_supp_cnt)
		{
			size_t fst = p.first.get_fst();
			size_t snd = p.first.get_snd();
			assert(cluster_valid(fst) && cluster_valid(snd));
			double fst_cnt = supp_cnt[fst];
			double snd_cnt = supp_cnt[snd];

			out << fst << "->" << snd << " | " << p.second << " / " <<
				fst_cnt << " = " << p.second / fst_cnt << endl;
			out << snd << "->" << fst << " | " << p.second << " / " <<
				snd_cnt << " = " << p.second / snd_cnt << endl;
		}
	}
};

#ifdef AFLRUN_CTX_DIV
Clusters<Fringe> clusters;
inline Fringe to_cluster_target(const ctx_t* t)
{
	return Fringe(t->block, t->call_ctx);
}
inline Fringe to_cluster_target(const Fringe& t)
{
	return t;
}
#else
Clusters<reach_t> clusters;
inline reach_t to_cluster_target(const ctx_t* t)
{
	return t->block;
}
inline reach_t to_cluster_target(const Fringe& t)
{
	return t.block;
}
#endif

// TODO: context sensitive diversity blocks
template <typename F>
struct DiversityBlocks
{
	// Map seed to currently active diversity blocks
	rh::unordered_map<u32, rh::unordered_set<F>> seed_blocks;

	// Map diversity block to seeds that cover it
	rh::unordered_map<F, rh::unordered_set<u32>> block_seeds;

	// Both unordered maps above must not contain any empty value

	u8* div_switch; // Shared Memory

	// Number of diversity block that reach threshold, targets not included;
	// Number of fringe diversity currently has,
	// including invalid ones, excluding targets.
	size_t num_invalid, num_fringes;

	explicit DiversityBlocks(u8* div_switch)
		: div_switch(div_switch), num_invalid(0), num_fringes(0) {}

	// For each new seed, update its coverage of active diversity blocks
	void div_coverage(const u8* bitmap, u32 seed,
		const rh::unordered_set<reach_t>* new_criticals = nullptr,
		const rh::unordered_set<reach_t>* new_bits_targets = nullptr);

	// TODO: add and delete diversity blocks when new fringe is added or deleted
	void switch_on(F f);
	void switch_off(F f);
	void remove_seed(u32 seed);

	void print(ostream& out) const;
};

template <>
void DiversityBlocks<reach_t>::div_coverage(const u8 *bitmap, u32 seed,
	const rh::unordered_set<reach_t>* new_criticals,
	const rh::unordered_set<reach_t>* new_bits_targets)
{ // Similar to `fringe_coverage`
	if (config.no_diversity)
		return;
	assert(seed_blocks.find(seed) == seed_blocks.end());
	rh::unordered_set<reach_t> blocks;
	vector<reach_t> to_invalidate;
	for (auto& b : block_seeds)
	{
		bool is_new_critical = new_criticals ?
			(new_criticals->count(b.first) != 0) : false;
		bool is_new_bits_targets = new_bits_targets ?
			(new_bits_targets->count(b.first) != 0) : true;

		assert(IS_SET(div_switch, b.first));
		if ((is_new_critical || is_new_bits_targets) && IS_SET(bitmap, b.first))
		{
			b.second.insert(seed);
			// We don't use `>=` to not invalidate already invalid blocks
			if (b.second.size() == config.div_seed_thr &&
				b.first >= g->num_targets)
			{ // If number of seeds reach threshold for fringe, invalidate it
				to_invalidate.push_back(b.first);
				++num_invalid;
			}
			blocks.insert(b.first);
		}
	}
	if (!blocks.empty())
		seed_blocks.emplace(seed, std::move(blocks));

	// For invalid diversity blocks, we only merge it to primary cluster,
	// so that it will not contribute to any new extra seeds.
	// We don't turn it off because we don't want to lose all previous seeds.
	if (!to_invalidate.empty())
	{
		for (reach_t b : to_invalidate)
			clusters.invalidate_div_block(b);
		clusters.clean_supp_cnts();
	}
}

template <>
void DiversityBlocks<reach_t>::switch_on(reach_t f)
{
	// If already switched on, this function does nothing
	if (!block_seeds.emplace(f, rh::unordered_set<u32>()).second)
		return;
	div_switch[f / 8] |= 1 << (f % 8);

	// This will be added very soon, so empty value does not matter
	if (f >= g->num_targets)
		++num_fringes;
}

template <>
void DiversityBlocks<reach_t>::switch_off(reach_t f)
{
	auto it = block_seeds.find(f);
	assert(f >= g->num_targets && IS_SET(div_switch, f));
	div_switch[f / 8] &= ~(1 << (f % 8));

	for (u32 s : it->second)
	{ // Delete the block in all seeds
		auto it2 = seed_blocks.find(s);
		it2->second.erase(f);
		if (it2->second.empty())
			seed_blocks.erase(it2);
	}
	if (it->second.size() >= config.div_seed_thr)
		--num_invalid;
	--num_fringes;
	block_seeds.erase(it);
	clusters.remove_div_block(f);
}

template <>
void DiversityBlocks<reach_t>::remove_seed(u32 seed)
{
	auto it = seed_blocks.find(seed);
	if (it == seed_blocks.end())
		return;
	assert(!it->second.empty());
	for (reach_t b : it->second)
	{
		auto& seeds = block_seeds.find(b)->second;
		seeds.erase(seed); assert(!seeds.empty());
	}
	seed_blocks.erase(it);
}

template<>
void DiversityBlocks<reach_t>::print(ostream& out) const
{
	out << "Diversity" << endl;
	size_t num_reached = 0, num_non_targets = 0;
	for (const auto& b : block_seeds)
	{
		bool target = b.first < g->num_targets;
		size_t s = b.second.size();
		bool reached = s >= config.div_seed_thr;
		if (!target)
		{
			++num_non_targets;
			if (reached) ++num_reached;
		}
		out << g->reachable_names[b.first] << " | " << s <<
			(target ? " T" : (reached ? " R" : "")) << endl;
	}
	assert(num_reached == num_invalid && num_fringes == num_non_targets);
}

unique_ptr<DiversityBlocks<reach_t>> div_blocks = nullptr;

using group_t = reach_t;
class TargetGrouper
{
public:
	friend void ::aflrun_init_groups(reach_t num_targets);
private:
	static rh::unordered_set<reach_t> all_targets;

	unique_ptr<group_t[]> target_to_group;
	vector<rh::unordered_set<reach_t>> groups;

	// some memory pool to save allocation time
	vector<reach_t> subgroups_;
	vector<reach_t> sizes_;
	vector<u8> covered_groups_;
	vector<group_t> covered_groups_arr_;
public:
	explicit TargetGrouper()
	{
		target_to_group = make_unique<group_t[]>(g->num_targets);
		fill(target_to_group.get(), target_to_group.get() + g->num_targets, 0);
		groups.emplace_back(all_targets);
		subgroups_.resize(g->num_targets);
		sizes_.resize(1);
		covered_groups_.resize(1);
		covered_groups_arr_.resize(1);
	}

	// Pre: targets must be unique
	template<typename D>
	void add_reachable(
		const rh::unordered_map<reach_t, rh::unordered_set<D>>& decs)
	{
		reach_t* subgroups = subgroups_.data();
		reach_t* sizes = sizes_.data();
		u8* covered_groups = covered_groups_.data();
		group_t* covered_groups_arr = covered_groups_arr_.data();
		const reach_t num_targets = g->num_targets;

		size_t group_size = groups.size();
		// Map each group index into all elements in `targets` belonging to it
		fill(sizes, sizes + group_size, 0);
		fill(covered_groups, covered_groups + group_size, 0);
		size_t num_covered_groups = 0;
		for (const auto& t : decs)
		{
			// Get group idx that the target belongs to
			group_t g = target_to_group[t.first];
			// Append the target to the corresponding subgroup
			subgroups[g * num_targets + sizes[g]++] = t.first;
			if (!covered_groups[g])
			{
				covered_groups[g] = 1;
				covered_groups_arr[num_covered_groups++] = g;
			}
		}

		// For subgroup that can cut any of existing group, we need to cut
		for (size_t i = 0; i < num_covered_groups; ++i)
		{
			group_t g = covered_groups_arr[i];
			size_t size = sizes[g];
			assert(0 < size);
			if (size < groups[g].size())
			{
				const reach_t* subgroup = subgroups + g * num_targets;
				group_t new_idx = groups.size();
				groups.emplace_back(subgroup, subgroup + size);
				for (size_t j = 0; j < size; ++j)
				{
					groups[g].erase(subgroup[j]);
					target_to_group[subgroup[j]] = new_idx;
				}
			}
		}

		group_size = groups.size();
		subgroups_.resize(group_size * num_targets);
		sizes_.resize(group_size);
		covered_groups_.resize(group_size);
		covered_groups_arr_.resize(group_size);
	}

	inline group_t to_group(reach_t target) const
	{
		return target_to_group[target];
	}

	inline const rh::unordered_set<reach_t>& to_targets(group_t group) const
	{
		return groups[group];
	}

	inline size_t size() const
	{
		return groups.size();
	}

	// Separate given set of targets according to current group
	template<typename D>
	vector<rh::unordered_set<reach_t>> separate(
		const rh::unordered_map<reach_t, rh::unordered_set<D>>& decs) const
	{
		rh::unordered_set<reach_t> targets;
		for (const auto& td : decs)
		{
			targets.insert(td.first);
		}
		vector<rh::unordered_set<reach_t>> ret;
		while (!targets.empty())
		{
			reach_t t = *targets.begin();
			rh::unordered_set<reach_t> group = to_targets(to_group(t));
#ifndef NDEBUG
			size_t prev_size = targets.size();
#endif
			for (reach_t e : group)
				targets.erase(e);
			// Check that all group elements removed are indeed in `targets`
			assert(targets.size() + group.size() == prev_size);

			ret.push_back(std::move(group));
		}
		return ret;
	}

	void slow_check() const
	{
		for (reach_t t = 0; t < g->num_targets; ++t)
		{
			group_t g = target_to_group[t];
			assert(groups.at(g).find(t) != groups.at(g).end());
			for (size_t i = 0; i < groups.size(); ++i)
			{
				if (i == g)
					continue;
				assert(groups[i].find(t) == groups[i].end());
			}
		}
	}
};

template <typename F, typename D>
void FringeBlocks<F, D>::group()
{
	grouper = make_unique<TargetGrouper>();
	// For each of fringe, we add associated targets to grouper
	for (const auto& f : fringes)
	{
		grouper->add_reachable<D>(f.second.decisives);
	}
}

rh::unordered_set<reach_t> TargetGrouper::all_targets;

} // namespace

size_t hash<Fringe>::operator()(const Fringe& p) const noexcept
{
	size_t seed = 0;
	bo::hash_combine(seed, p.block);
	bo::hash_combine(seed, p.context);
	return seed;
}

size_t hash<SeedFringes>::operator()(const SeedFringes& p) const noexcept
{
	const u8* ptr = p.bitmap.get();
	return bo::hash_range(ptr, ptr + p.bitmap_size);
}

size_t hash<pair<reach_t, reach_t>>::operator()(
	const pair<reach_t, reach_t>& p) const noexcept
{
	size_t seed = 0;
	bo::hash_combine(seed, p.first);
	bo::hash_combine(seed, p.second);
	return seed;
}

size_t hash<ClusterPair>::operator()(
	const ClusterPair& p) const noexcept
{
	size_t seed = 0;
	bo::hash_combine(seed, p.get_fst());
	bo::hash_combine(seed, p.get_snd());
	return seed;
}

/* ----- Functions called at initialization ----- */

void aflrun_init_groups(reach_t num_targets)
{
	for (reach_t t = 0; t < num_targets; ++t)
	{
		TargetGrouper::all_targets.insert(t);
	}
}

void aflrun_init_fringes(reach_t num_reachables, reach_t num_targets)
{
	path_fringes = make_unique<FringeBlocks<Fringe, Fringe>>(num_targets);
	path_pro_fringes = make_unique<FringeBlocks<Fringe, reach_t>>(num_targets);
	reached_targets = make_unique<FringeBlocks<Fringe, u8>>(num_targets);
}

void aflrun_init_globals(void* afl, reach_t num_targets, reach_t num_reachables,
		reach_t num_ftargets, reach_t num_freachables,
		u8* virgin_reachables, u8* virgin_freachables, u8* virgin_ctx,
		char** reachable_names, reach_t** reachable_to_targets,
		reach_t* reachable_to_size, const char* out_dir,
		const double* target_weights, u32 map_size, u8* div_switch,
		const char* cycle_time)
{
	assert(g == nullptr);
	g = make_unique<AFLRunGlobals>(num_targets, num_reachables,
		num_ftargets, num_freachables, virgin_reachables,
		virgin_freachables, virgin_ctx, reachable_names,
		reachable_to_targets, reachable_to_size, out_dir,
		target_weights, map_size, afl, get_cur_time(),
		cycle_time == NULL ? 0 : strtoull(cycle_time, NULL, 10));
	div_blocks = make_unique<DiversityBlocks<reach_t>>(div_switch);
}

void aflrun_load_freachables(const char* temp_path,
	reach_t* num_ftargets, reach_t* num_freachables)
{
	string temp(temp_path);
	if (temp.back() != '/')
		temp.push_back('/');
	ifstream fd(temp + "Freachable.txt"); assert(fd.is_open());
	string line;
	getline(fd, line);
	size_t idx = line.find(','); assert(idx != string::npos);
	*num_ftargets = strtoul(line.c_str(), NULL, 10);
	*num_freachables = strtoul(line.c_str() + idx + 1, NULL, 10);

	reach_t i = 0;
	while (getline(fd, line))
	{
		fname_to_id.emplace(line, i++);
		id_to_fname.push_back(std::move(line));
	}

	assert(i == *num_freachables && i == fname_to_id.size());
}

void aflrun_load_edges(const char* temp_path, reach_t num_reachables)
{
	string temp(temp_path);
	if (temp.back() != '/')
		temp.push_back('/');
	graph = make_unique<BasicBlockGraph>(
		(temp + "BBedges.txt").c_str(), num_reachables);

	ifstream fd(temp + "Chash.txt"); assert(fd.is_open());
	string line;
	while (getline(fd, line))
	{
		size_t idx1 = line.find(','); assert(idx1 != string::npos);
		size_t idx2 = line.find('|'); assert(idx2 != string::npos);
		auto call_edge = make_pair<reach_t, reach_t>(
			strtoul(line.c_str(), NULL, 10),
			strtoul(line.c_str() + idx1 + 1, NULL, 10));
		graph->call_hashes[call_edge].push_back(
			strtoul(line.c_str() + idx2 + 1, NULL, 10));
	}
}

void aflrun_load_dists(const char* dir, reach_t num_targets,
	reach_t num_reachables, char** reachable_names)
{
	bb_to_dists.resize(num_reachables);

	// Convert reachable name to id in O(1)
	for (reach_t i = 0; i < num_reachables; i++)
	{
		name_to_id.emplace(reachable_names[i], i);
	}

	string path(dir);
	if (path.back() != '/')
		path.push_back('/');
	path += "distance.cfg/";
	for (reach_t t = 0; t < num_targets; ++t)
	{
		ifstream cf(path + to_string(t) + ".txt"); assert(cf.is_open());
		string line;
		while (getline(cf, line))
		{
			// get name and dist
			size_t pos = line.find(","); assert(pos != string::npos);
			string bb_name = line.substr(0, pos);
			double bb_dis = atof(line.substr(pos + 1, line.length()).c_str());

			// update name and dist into global data structure
			assert(name_to_id.find(bb_name) != name_to_id.end());
			reach_t block = name_to_id.find(bb_name)->second;
			auto tmp = bb_to_dists[block].find(t);
			if (tmp == bb_to_dists[block].end())
			{
				bb_to_dists[block].emplace(t, bb_dis);
			}
			else if (tmp->second > bb_dis)
			{
				tmp->second = bb_dis; // we get minimum of all distances
			}
		}
		cf.close();
	}

	// calculate the average distance among all targets
	// TODO: calculate the average lazily
	rh::unordered_map<reach_t, double> dists;
	for (reach_t bb = 0; bb < num_reachables; ++bb)
	{
		double sum = 0.0; size_t count = 0;
		for (reach_t t = 0; t < num_targets; ++t)
		{
			auto d = bb_to_dists[bb].find(t);
			if (d != bb_to_dists[bb].end())
			{
				sum += d->second; ++count;
			}
		}
		assert(count > 0);
		bb_to_avg_dists.emplace(bb, sum / count);
	}
}

// The config is in form "xxx=aaa:yyy=bbb"
void aflrun_load_config(const char* config_str,
	u8* check_at_begin, u8* log_at_begin, u64* log_check_interval,
	double* trim_thr, double* queue_quant_thr, u32* min_num_exec)
{
	string s(config_str);
	try
	{
		while (true)
		{
			size_t idx = s.find(':');
			if (idx == string::npos)
			{
				config.load(s);
				break;
			}
			config.load(s.substr(0, idx));
			s = s.substr(idx + 1);
		}
		config.check();
	}
	catch (const string& e)
	{
		cerr << e << endl;
		abort();
	}
	*check_at_begin = config.check_at_begin;
	*log_at_begin = config.log_at_begin;
	*log_check_interval = config.log_check_interval;
	*trim_thr = config.trim_thr;
	*queue_quant_thr = config.queue_quant_thr;
	*min_num_exec = config.min_num_exec;
}

void aflrun_remove_seed(u32 seed)
{
	path_pro_fringes->remove_seed(seed);
	path_fringes->remove_seed(seed);
	reached_targets->remove_seed(seed);
	div_blocks->remove_seed(seed);
}

/* ----- Functions called for some time interval to log and check ----- */

#ifdef NDEBUG
void aflrun_check_state(void) {}
#else
namespace
{
template <typename F, typename D>
void check_state(const FringeBlocks<F, D>& fringes)
{
	for (reach_t t = 0; t < fringes.target_to_fringes.size(); ++t)
	{
		for (const F& f : fringes.target_to_fringes[t])
		{
			auto it = fringes.fringes.find(f);
			assert(it != fringes.fringes.end());
			auto it2 = it->second.decisives.find(t);
			assert(it2 != it->second.decisives.end());
			assert(!it->second.seeds.empty());
			for (u32 seed : it->second.seeds)
			{
				const auto& seed_fringes = fringes.seed_fringes.find(seed)->second;
				assert(seed_fringes.find(f) != seed_fringes.end());
			}
		}
	}
	for (const auto& fi : fringes.fringes)
	{
		assert(!fi.second.decisives.empty());
		for (const auto& td : fi.second.decisives)
		{
			const auto& fs = fringes.target_to_fringes.at(td.first);
			assert(fs.find(fi.first) != fs.end());
		}
	}
}
}
void aflrun_check_state(void)
{
	if (!config.check_fringe)
		return;
	check_state(*path_fringes);
	check_state(*path_pro_fringes);
	check_state(*reached_targets);
	for (reach_t t = 0; t < path_pro_fringes->target_to_fringes.size(); ++t)
	{
		for (const auto& f : path_pro_fringes->target_to_fringes[t])
		{
			assert(path_fringes->target_to_fringes[t].find(f) !=
				path_fringes->target_to_fringes[t].end());
		}
	}
}
#endif


namespace
{
string targets_info;

template <typename F, typename D>
void log_fringes(ofstream& out, const FringeBlocks<F, D>& fringes)
{
	out << "fringe | target group | decisives | seeds | freq" << endl;
	for (const auto& f : fringes.fringes)
	{
		auto res = fringes.grouper->separate(f.second.decisives);
		for (const rh::unordered_set<reach_t>& group : res)
		{
			log_fringe<F>(out, f.first);
			out << " |";
			rh::unordered_set<D> decisives;
			for (reach_t t : group)
			{
				out << ' ' << g->reachable_names[t];
				const auto& tmp = f.second.decisives.find(t)->second;
				decisives.insert(tmp.begin(), tmp.end());
			}
			out << " | ";
			for (const D& d : decisives)
			{
				log_fringe<D>(out, d); out << ' ';
			}
			out << '|';
			if (config.show_all_seeds)
			{
				for (u32 s : f.second.seeds)
				{
					out << ' ' << s;
				}
			}
			else if (f.second.has_top_rated)
			{
				out << ' ' << f.second.top_rated_seed;
			}
			out << " | " << f.second.fuzzed_quant << endl;
		}
	}
}
}

void aflrun_log_fringes(const char* path, u8 which)
{
	ofstream out(path);
	// When critical block is disabled, we don't need log.
	if (!out.is_open() || config.no_critical)
		return;

	path_fringes->group();
	path_pro_fringes->group();
	reached_targets->group();

	switch (which)
	{
	case 2: // print all paths towards all targets
		out << "context | target | seeds" << endl;
		for (const auto& f : reached_targets->fringes)
		{
			assert(f.first.block < g->num_targets);
			out << f.first.context << " | " <<
				g->reachable_names[f.first.block] << " |";
			if (config.show_all_seeds)
			{
				for (u32 s : f.second.seeds)
				{
					out << ' ' << s;
				}
			}
			else if (f.second.has_top_rated)
			{
				out << ' ' << f.second.top_rated_seed;
			}
			out << endl;
		}
		clusters.print(out);
		div_blocks->print(out);
		break;
	case 1:
		log_fringes(out, *path_pro_fringes);
		break;
	case 0:
		log_fringes(out, *path_fringes);
		break;
	default:
		abort();
	}
	if (which == 2)
		out << targets_info;
	out.close();
}

u64 aflrun_queue_cycle(void)
{
	if (g->cycle_time)
		return (get_cur_time() - g->init_time) / 1000 / g->cycle_time;
	else
		return state.get_whole_count();
}

void aflrun_get_state(int* cycle_count, u32* cov_quant,
	size_t* div_num_invalid, size_t* div_num_fringes)
{
	state.get_counts(*cycle_count, *cov_quant);
	*div_num_invalid = div_blocks->num_invalid;
	*div_num_fringes = div_blocks->num_fringes;
}

u8 aflrun_get_mode(void)
{
	return state.get_mode();
}

bool aflrun_is_uni(void)
{
	return state.get_mode() == AFLRunState::kUnite;
}

double aflrun_get_seed_quant(u32 seed)
{
	return seed < seed_quant.size() ? seed_quant[seed] : 0;
}

void aflrun_get_reached(reach_t* num_reached, reach_t* num_freached,
	reach_t* num_reached_targets, reach_t* num_freached_targets)
{
	*num_reached = g->num_reached;
	*num_freached = g->num_freached;
	*num_reached_targets = g->num_reached_targets;
	*num_freached_targets = g->num_freached_targets;
}

void aflrun_get_time(u64* last_reachable, u64* last_fringe,
	u64* last_pro_fringe, u64* last_target, u64* last_ctx_reachable,
	u64* last_ctx_fringe, u64* last_ctx_pro_fringe, u64* last_ctx_target)
{
	*last_reachable = update_time.last_reachable;
	*last_fringe = update_time.last_fringe;
	*last_pro_fringe = update_time.last_pro_fringe;
	*last_target = update_time.last_target;
	*last_ctx_reachable = update_time.last_ctx_reachable;
	*last_ctx_fringe = update_time.last_ctx_fringe;
	*last_ctx_pro_fringe = update_time.last_ctx_pro_fringe;
	*last_ctx_target = update_time.last_ctx_target;
}

/* ----- Functions called at begining of each cycle ----- */

namespace
{
void assign_energy_seed(u32 num_seeds, const u32* seeds, double* ret)
{
	switch (state.get_mode())
	{
	case AFLRunState::kFringe:
	{
		path_fringes->assign_energy(num_seeds, seeds, ret);
		return;
	}
	case AFLRunState::kProFringe:
	{
		path_pro_fringes->assign_energy(num_seeds, seeds, ret);
		return;
	}
	case AFLRunState::kTarget:
	{
		reached_targets->assign_energy(num_seeds, seeds, ret);
		return;
	}
	case AFLRunState::kUnite:
	{
		assign_energy_unite(num_seeds, seeds, ret);
		return;
	}
	default:
		abort();
	}
}
}

void aflrun_assign_energy(u32 num_seeds, const u32* seeds, double* ret)
{
	if (!config.seed_based_energy)
	{
		cerr << "Old energy assignment is no longer supported" << endl;
		abort();
	}
	assign_energy_seed(num_seeds, seeds, ret);
}

// Call this function at end of all cycles,
// including beginning of the first cycle or when state is reset
// (pseudo cycle end where `cycle_count` increment from -1 to 0).
// The function return the new mode
u8 aflrun_cycle_end(u8* whole_end)
{
	*whole_end = state.cycle_end();
	return state.get_mode();
}

/* ----- Functions called when new reachable block becomes non-virgin ----- */

namespace
{

// Perform vigin BFS from given block,
// return map from reached target to a set of blocks containing a path to it

template <typename D>
inline rh::unordered_set<D> trace_decisives(
	const rh::unordered_map<D, D>& parent, const D& start, const D& v)
{
	rh::unordered_set<D> decisives;

	// Get all blocks consisting of path towards the target
	D cur = v;
	do
	{
		decisives.insert(cur);
		cur = parent.find(cur)->second;
	} while (!(cur == start));

	return decisives;
}

template <typename D>
rh::unordered_map<reach_t, rh::unordered_set<D>> get_target_paths(D);

template <>
rh::unordered_map<reach_t, rh::unordered_set<reach_t>>
	get_target_paths<reach_t>(reach_t block)
{
	// https://en.wikipedia.org/wiki/Breadth-first_search#Pseudocode
	rh::unordered_map<reach_t, rh::unordered_set<reach_t>> ret;
	queue<reach_t> q; rh::unordered_map<reach_t, reach_t> parent;
	for (reach_t dst : graph->src_to_dst[block])
	{
		if (IS_SET(g->virgin_reachables, dst))
		{ // add all outgoing virgin vertexes to queue as initialization
			parent.emplace(dst, block);
			q.push(dst);
		}
	}
	while (!q.empty())
	{
		reach_t v = q.front(); q.pop();

		if (v < g->num_targets)
		{
			ret.emplace(v, trace_decisives<reach_t>(parent, block, v));
		}

		for (reach_t w : graph->src_to_dst[v])
		{
			if (!IS_SET(g->virgin_reachables, w))
				continue;
			if (parent.find(w) == parent.end())
			{
				parent.emplace(w, v);
				q.push(w);
			}
		}
	}
	return ret;
}

vector<u32> get_next_hashes(const Fringe& src, reach_t dst, bool& is_call)
{
	u32 ctx = src.context;
	reach_t block = src.block;
	auto p = make_pair<reach_t, reach_t>(std::move(block), std::move(dst));
	auto it = graph->call_hashes.find(p);

	vector<u32> next_hashes;
	// If it is a call edge with multiple hashes, calculate new ctx.
	// e.i. one block calls same function for multiple times
	if (it != graph->call_hashes.end())
	{
		for (u32 h : it->second)
		{
			next_hashes.push_back(ctx ^ h);
		}
		is_call = true;
	}
	else
	{
		next_hashes.push_back(ctx);
		is_call = false;
	}

	return next_hashes;
}

// This is a helper function for `get_target_paths<Fringe>` for optimization,
// because going through all possible states with contexts are too expensive.
bool all_targets_visited(reach_t block,
	const rh::unordered_map<reach_t, rh::unordered_set<Fringe>>& cur)
{
	size_t num_ts = g->reachable_to_size[block];

	// If number of reachable targets are larger than number of visited targets,
	// then there must be some targets reachable by `block` not visited yet;
	// this is just a quick path for slight optimization.
	if (num_ts > cur.size())
		return false;

	const reach_t* beg = g->reachable_to_targets[block];
	const reach_t* end = beg + num_ts;

	for (const reach_t* t = beg; t < end; ++t)
	{ // If there is a target rechable by `block` not yet visited by `cur`,
		// we should return false.
		if (cur.find(*t) == cur.end())
			return false;
	}

	// If all targets reachable by `block` already has a path,
	// we can then skip this block by not adding it to stack.
	return true;
}

// Basically same as above, except when doing BFS,
// we consider the context and regard same `dst` node with different contexts
// as different next possible states.
rh::unordered_map<reach_t, rh::unordered_set<Fringe>>
	get_target_paths_slow(const Fringe& block_ctx)
{
	rh::unordered_map<reach_t, rh::unordered_set<Fringe>> ret;
	queue<Fringe> q; rh::unordered_map<Fringe, Fringe> parent;
	reach_t block = block_ctx.block;
	bool dummy;

	// For given source state (e.i. block and context),
	// we iterate all possible next states and add them into queue.
	for (reach_t dst : graph->src_to_dst[block])
	{
		auto next_hashes = get_next_hashes(block_ctx, dst, dummy);
		for (u32 next_hash : next_hashes)
		{
			if (IS_SET(g->virgin_ctx, CTX_IDX(dst, next_hash)))
			{
				Fringe next(dst, next_hash);
				parent.emplace(next, block_ctx);
				q.push(next);
			}
		}
	}

	while (!q.empty())
	{
		Fringe v = q.front(); q.pop();

		// If we reached the target via BFS for the first time,
		// we trace and record paths to it, similar to above
		if (v.block < g->num_targets && ret.find(v.block) == ret.end())
		{
			ret.emplace(v.block, trace_decisives<Fringe>(parent, block_ctx, v));
		}

		// All possible next states are virgin (block, ctx) pairs
		for (reach_t w : graph->src_to_dst[v.block])
		{
			if (all_targets_visited(w, ret))
				continue;
			auto next_hashes = get_next_hashes(v, w, dummy);
			for (u32 next_hash : next_hashes)
			{
				if (!IS_SET(g->virgin_ctx, CTX_IDX(w, next_hash)))
					continue;
				Fringe next(w, next_hash);
				if (parent.find(next) == parent.end())
				{
					parent.emplace(next, v);
					q.push(next);
				}
			}
		}
	}

	return ret;
}

// The problem of a thorough BFS is that it can be too slow for big binaries,
// so we have another fast version that only BFS inside the function and
// entry block of each function it calls.
// The core idea is that as long as it reaches a entry block whose next context
// is virgin, it add all targets the block can reach into `decisives` with the
// partial trace reaching the entry block. The idea is that as long as we have
// entry block with virgin context, the stack trace before + this call site
// must not have been visited, thus any target it can reach can potentially
// have stack trace before + this call site + other call sites to reach target,
// which must also be not visited before. Thus it is okay to know there exists
// a context-sensitive path to these targets.
// However, such fast hack has 2 problems:
// 1. Cannot handle hash collision; 2. potentially problematic for recursion.
rh::unordered_map<reach_t, rh::unordered_set<Fringe>>
	get_target_paths_fast(const Fringe& block_ctx)
{
	rh::unordered_map<reach_t, rh::unordered_set<Fringe>> ret;
	queue<pair<Fringe, bool>> q; rh::unordered_map<Fringe, Fringe> parent;
	reach_t block = block_ctx.block;

	// Similar to the slow one,
	// except we also record whether `Fringe` is a call in the queue.

	for (reach_t dst : graph->src_to_dst[block])
	{
		bool is_call;
		auto next_hashes = get_next_hashes(block_ctx, dst, is_call);
		for (u32 next_hash : next_hashes)
		{
			if (IS_SET(g->virgin_ctx, CTX_IDX(dst, next_hash)))
			{
				Fringe next(dst, next_hash);
				parent.emplace(next, block_ctx);
				q.push(make_pair(std::move(next), std::move(is_call)));
			}
		}
	}

	while (!q.empty())
	{
		auto tmp = q.front(); q.pop();
		const Fringe& v = tmp.first;

		// We still need to check potential targets in the function
		if (!tmp.second &&
			v.block < g->num_targets && ret.find(v.block) == ret.end())
		{
			ret.emplace(v.block, trace_decisives<Fringe>(parent, block_ctx, v));
		}

		// If current virgin `Fringe` is visited from call edge,
		// then we get a trace from it, and assign to each target it can reach;
		// also we don't continue to visit its child blocks.
		if (tmp.second)
		{
			auto decisives = trace_decisives(parent, block_ctx, v);

			const reach_t* beg = g->reachable_to_targets[v.block];
			const reach_t* end = beg + g->reachable_to_size[v.block];
			for (const reach_t* t = beg + 1; t < end; ++t)
			{
				// If key `*t` already exists, `emplace` does nothing.
				ret.emplace(*t, decisives);
			}
			ret.emplace(*beg, std::move(decisives));
		}
		else
		{
			for (reach_t w : graph->src_to_dst[v.block])
			{
				bool is_call;
				auto next_hashes = get_next_hashes(v, w, is_call);
				for (u32 next_hash : next_hashes)
				{
					if (!IS_SET(g->virgin_ctx, CTX_IDX(w, next_hash)))
						continue;
					Fringe next(w, next_hash);
					if (parent.find(next) == parent.end())
					{
						parent.emplace(next, v);
						q.push(make_pair(std::move(next), std::move(is_call)));
					}
				}
			}
		}
	}

	return ret;
}

template <>
rh::unordered_map<reach_t, rh::unordered_set<Fringe>>
	get_target_paths<Fringe>(Fringe block_ctx)
{
	if (config.slow_ctx_bfs)
		return get_target_paths_slow(block_ctx);
	else
		return get_target_paths_fast(block_ctx);
}

/* ----- Functions called for each test case mutated and executed ----- */

template <typename D>
inline D to_decisive(const Fringe& f);
template <>
inline reach_t to_decisive<reach_t>(const Fringe& f)
{
	return f.block;
}
template <>
inline Fringe to_decisive<Fringe>(const Fringe& f)
{
	return f;
}

template <typename F, typename D>
u8 FringeBlocks<F, D>::try_add_fringe(const Fringe& cand)
{
	auto target_decisives = get_target_paths<D>(to_decisive<D>(cand));
	if (target_decisives.empty())
		return 0;
	for (auto& td : target_decisives)
	{
		this->add_fringe(cand, td.first, std::move(td.second));
	}
	return 1;
}

u8 try_add_fringe(const ctx_t& cand)
{
	reach_t block = cand.block;
	Fringe f_cand(block, cand.call_ctx);

	/* For the ablation study that removes the critical blocks,
	`path_pro_fringes` and `path_fringes` are both empty,
	and we put all covered blocks into reached_targets.
	Hope this hack does not cause any other problem. :) */
	if (config.no_critical)
	{
		const reach_t* beg = g->reachable_to_targets[block];
		const reach_t* end = beg + g->reachable_to_size[block];
		for (const reach_t* i = beg; i < end; ++i)
		{
			reached_targets->add_fringe(f_cand, *i, rh::unordered_set<u8>());
		}
		return 0;
	}

	u8 r2 = path_pro_fringes->try_add_fringe(f_cand);

#ifdef AFLRUN_CTX
	// We add criticals to into `path_fringes` only when context is enabled.
	u8 r1 = path_fringes->try_add_fringe(f_cand);
	assert(!r2 || r1); // r2 -> r1
#endif

	// If candidate is fringe reaching a target and it is not added yet, we add it
	if (block < g->num_targets)
	{
		reached_targets->add_fringe(f_cand, block, rh::unordered_set<u8>());
	}

#ifdef AFLRUN_CTX
	return r2 + r1;
#else
	// When context is not enabled, we return 2 when new critical is added.
	return r2 * 2;
#endif
}

// Return set of all blocks it removed
template <typename F, typename D>
vector<reach_t> FringeBlocks<F, D>::try_del_fringe(const Fringe& cand)
{
	vector<reach_t> ret;
	auto it = this->decisive_to_fringes.find(to_decisive<D>(cand));
	if (it == this->decisive_to_fringes.end())
		return ret;
	rh::unordered_set<Fringe> fringes_decided(std::move(it->second));
	this->decisive_to_fringes.erase(it);

	for (const Fringe& f : fringes_decided)
	{
		auto it2 = this->fringes.find(f);
		if (it2 == this->fringes.end())
			continue;

		// Re-evaluate the fringe to see if it can still reach any target
		auto target_decisives = get_target_paths<D>(to_decisive<D>(f));
		if (target_decisives.empty())
		{ // If not, delete the fringe
			if (this->del_fringe(f))
				ret.push_back(f.block);
		}
		else
		{ // Otherwise, update the fringe with:
			// 1. new targets(a subset of original targets) and 2. new decisives
			for (const auto& td : it2->second.decisives)
			{
				// If an old target is not covered by new set of targets
				if (target_decisives.find(td.first) == target_decisives.end())
				{
					this->target_to_fringes[td.first].erase(f);
				}
			}
			for (const auto& td : target_decisives)
			{
				for (const D& d : td.second)
				{
					this->decisive_to_fringes[d].insert(f);
				}
			}
			it2->second.decisives = std::move(target_decisives);
		}
	}
	return ret;
}

template <typename F, typename D>
void FringeBlocks<F, D>::remove_seed(u32 seed)
{
	auto it = seed_fringes.find(seed);
	// skip if seed does not exists
	if (it == seed_fringes.end())
		return;
	assert(!it->second.empty());
	for (const auto& f : it->second)
	{ // For all fringes, we need also to update its info about seeds
		auto& info = fringes.find(f)->second;

		// Because we only remove duplicate seed,
		// there must be another seed covering the fringe
		info.seeds.erase(seed); assert(!info.seeds.empty());

		if (info.has_top_rated && info.top_rated_seed == seed)
		{ // If top_rated_seed has been removed, we need to update it
			u32 best_seed = 0xdeadbeefu;
			u64 best_fav_factor = numeric_limits<u64>::max();
			for (u32 seed : info.seeds)
			{
				u64 fav_factor = get_seed_fav_factor(g->afl, seed);
				if (fav_factor <= best_fav_factor)
				{
					best_seed = seed;
					best_fav_factor = fav_factor;
				}
			}
			info.top_rated_seed = best_seed;
			info.top_rated_factor = best_fav_factor;
		}
	}
	seed_fringes.erase(it);
}

}

u8 aflrun_has_new_path(const u8* freached, const u8* reached, const u8* path,
	const ctx_t* new_paths, size_t len, u8 inc, u32 seed,
	const u8* new_bits, const size_t* cur_clusters, size_t num_clusters)
{
	u8 ret = 0;
	unique_ptr<rh::unordered_set<Fringe>> new_criticals;
	unique_ptr<rh::unordered_set<reach_t>> new_critical_blocks;
	if (len != 0)
	{
		// If there are `new_paths`, we update virgin bits.
		// Note that if there are new virgin bits, there must be `new_paths`,
		// so any newly reached virgin bits will not be missed.

		// update virgin bit for reachale functions
		for (reach_t i = 0; i < g->num_freachables; ++i)
		{
			if (IS_SET(g->virgin_freachables, i) && IS_SET(freached, i))
			{
				g->virgin_freachables[i / 8] &= 0xffu ^ (1u << (i % 8));
				g->num_freached++;
				if (i < g->num_ftargets)
					g->num_freached_targets++;
			}
		}

		rh::unordered_set<reach_t> new_blocks;
		for (reach_t i = 0; i < g->num_reachables; ++i)
		{
			// If the bit is virgin (e.i not reached before),
			// and this execution can reach such virgin bit
			if (IS_SET(g->virgin_reachables, i) && IS_SET(reached, i))
			{
				// we clear the virgin bit
				g->virgin_reachables[i / 8] &= 0xffu ^ (1u << (i % 8));
				g->num_reached++;
				new_blocks.insert(i);
				if (i < g->num_targets)
					g->num_reached_targets++;
			}
		}

		for (size_t i = 0; i < len; ++i)
		{
			const ctx_t& cand = new_paths[i];
			Fringe f_cand(cand.block, cand.call_ctx);
			auto del_norm = path_fringes->try_del_fringe(f_cand);
			auto del_pro = path_pro_fringes->try_del_fringe(f_cand);
			if (config.no_diversity)
				continue;
			if (config.div_level == 1) // Only pro-fringe
			{
				for (reach_t b : del_pro)
				{ // For all blocks removed from pro fringe
					assert(path_pro_fringes->block_to_fringes.count(b) == 0);
					if (b >= g->num_targets)
					{ // If it is not target, we switch it off
						div_blocks->switch_off(b);
					}
				}
				clusters.clean_supp_cnts();
			}
			else if (config.div_level == 2) // pro-fringe + norm-fringe
			{
				rh::unordered_set<reach_t> switched_off;
				for (reach_t b : del_pro)
				{
					assert(path_pro_fringes->block_to_fringes.count(b) == 0);
					if (b >= g->num_targets &&
						path_fringes->block_to_fringes.count(b) == 0)
					{ // If fringe is not pro, but still in norm, we still keep.
						div_blocks->switch_off(b);
						switched_off.insert(b);
					}
				}
				for (reach_t b : del_norm)
				{
					// If a block is deleted from norm fringe,
					// it cannot appear in pro fringe either.
					assert(path_pro_fringes->block_to_fringes.count(b) == 0);
					assert(path_fringes->block_to_fringes.count(b) == 0);
					if (b >= g->num_targets && switched_off.count(b) == 0)
					{
						div_blocks->switch_off(b);
					}
				}
				clusters.clean_supp_cnts();
			}
			// All fringes removed by `path_pro_fringes`
		}

		u8 cf = 0, ct = 0, f = 0, t = 0;
		new_criticals = make_unique<rh::unordered_set<Fringe>>();
		new_critical_blocks = make_unique<rh::unordered_set<reach_t>>();
		for (size_t i = 0; i < len; ++i)
		{
			reach_t block = new_paths[i].block;
			u8 r = try_add_fringe(new_paths[i]) + 1;

			// Update context-sensitive fringe and target
			cf = max(r, cf);
			if (block < g->num_targets)
				ct = 1;

			// It it is the first time a block is reached,
			// we update context-insensitive fringe and target.
			if (new_blocks.find(block) != new_blocks.end())
			{
				f = max(r, f);
				if (block < g->num_targets)
					t = 1;
			}

			if (r >= 2 || block < g->num_targets)
			{
				new_criticals->emplace(
					new_paths[i].block, new_paths[i].call_ctx);
				new_critical_blocks->insert(new_paths[i].block);
			}

			// When there is a new fringe or target, we activate its switch.
			if (block < g->num_targets || r > 3 - config.div_level)
			{ // Note this can happen multiple times for a block, 3 cases:
				// 1. If first time it is activated, then switch is turned on.
				// 2. If switch is already on, them nothing is done.
				// 3. If switch was turned off before, then turn on again.
					// Such case only occurs for r == 2. (e.i. context fringe)
				div_blocks->switch_on(block);
			}
		}
		if (config.reset_level == 1)
		{
			if (f > 0)
				state.reset(f - 1); // state.reset(cf - 1); TODO: config
			if (config.reset_target && t)
				state.exploit();
		} // TODO: reset_level == 2
		if (state.is_init_cov())
		{
			if (config.init_cov_reset == 1)
			{
				if (f > 0 || t)
					state.reset_cov_quant();
			}
			else if (config.init_cov_reset == 2)
			{
				if (cf > 0 || ct)
					state.reset_cov_quant();
			}
		}

		/*
		Given a execution trace exerted by a program,
		and try to see if there is something new;
		it returns information about if fringe is created,
		cf:
			1 for a new context-sensitive block is covered,
			2 for a new context-sensitive fringe is added,
			3 for a new context-sensitive pro fringe is added;
		ct:
			1 for new context-sensitive target is reached
		f:
			1 for a new reachable block is covered,
			2 for a new fringe is added for the first time,
			3 for a new pro fringe is added for the first time,
		t bit:
			1 for new context-insensitive target is reached
		*/

		if (f >= 1) update_time.last_reachable = get_cur_time();
		if (f >= 2) update_time.last_fringe = get_cur_time();
		if (f >= 3) update_time.last_pro_fringe = get_cur_time();

		if (t) update_time.last_target = get_cur_time();

		if (cf >= 1) update_time.last_ctx_reachable = get_cur_time();
		if (cf >= 2) update_time.last_ctx_fringe = get_cur_time();
		if (cf >= 3) update_time.last_ctx_pro_fringe = get_cur_time();

		if (ct) update_time.last_ctx_target = get_cur_time();

		ret = cf >= 2 || ct;
	}

	// TODO: Coverage for Seed Isolation

	bool has_cov = false;
	if (num_clusters == 0 || (new_bits && new_bits[0]))
	{ // If `num_clusters` is zero, or primary map has new bits,
		// then the seed is non-extra,
		// so we don't do seed isolation and consider all coverage.
		has_cov |= path_fringes->fringe_coverage(path, seed);
		has_cov |= path_pro_fringes->fringe_coverage(path, seed);
		has_cov |= reached_targets->fringe_coverage(path, seed);
		div_blocks->div_coverage(reached, seed);
	}
	else
	{
		rh::unordered_set<reach_t> new_bits_targets;
		if (new_bits)
		{ // If new_bits is not NULL, there is any virgin map update.
			for (size_t i = 1; i < num_clusters; ++i)
			{
				if (new_bits[i])
				{ // If there is any new bit, insert all blocks in the cluster.
					const auto& ts = clusters.get_targets(cur_clusters[i]);
					new_bits_targets.insert(ts.begin(), ts.end());
				}
			}
		}
		has_cov |= path_fringes->fringe_coverage(
			path, seed, new_criticals.get(), &new_bits_targets);
		has_cov |= path_pro_fringes->fringe_coverage(
			path, seed, new_criticals.get(), &new_bits_targets);
		has_cov |= reached_targets->fringe_coverage(
			path, seed, new_criticals.get(), &new_bits_targets);
		div_blocks->div_coverage(
			reached, seed, new_critical_blocks.get(), &new_bits_targets);
	}

	// Reset `cov_quant` to 0 in initial coverage if any new fringe coverage
	if (config.init_cov_reset == 3 && state.is_init_cov() && has_cov)
		state.reset_cov_quant();

	/*if (inc)
	{
		path_fringes->inc_freq(path);
		reached_targets->inc_freq(path);
	}*/

	return ret;
}

u8 aflrun_end_cycle()
{
	return state.is_reset() || state.is_end_cov();
}

void aflrun_update_fuzzed_quant(u32 id, double fuzzed_quant)
{
	path_fringes->update_fuzzed_quant(id, fuzzed_quant);
	path_pro_fringes->update_fuzzed_quant(id, fuzzed_quant);
	reached_targets->update_fuzzed_quant(id, fuzzed_quant);
	state.add_quant(fuzzed_quant);
	if (id >= seed_quant.size())
		seed_quant.resize(id + 1);
	seed_quant[id] += fuzzed_quant;
}

void aflrun_update_fringe_score(u32 seed)
{
	path_fringes->update_fringe_score(seed);
	path_pro_fringes->update_fringe_score(seed);
	reached_targets->update_fringe_score(seed);
}

void aflrun_set_favored_seeds(const u32* seeds, u32 num, u8 mode)
{
	switch (mode)
	{
	case AFLRunState::kFringe:
		return path_fringes->set_favored_seeds(seeds, num);
	case AFLRunState::kProFringe:
		return path_pro_fringes->set_favored_seeds(seeds, num);
	case AFLRunState::kTarget:
		return reached_targets->set_favored_seeds(seeds, num);
	default:
		abort();
	}
}

u32 aflrun_cull_queue(u32* seeds, u32 num)
{
	switch (state.get_mode())
	{
	case AFLRunState::kFringe:
		return path_fringes->cull_queue(seeds, num);
	case AFLRunState::kProFringe:
		return path_pro_fringes->cull_queue(seeds, num);
	case AFLRunState::kTarget:
		return reached_targets->cull_queue(seeds, num);
	case AFLRunState::kUnite:
		return cull_queue_unite(seeds, num);
	default:
		abort();
	}
}

// Note that the virgin maps returned can be inaccurate,
// which should not be used into `has_new_bits_mul`,
// instead use ones returned by `aflrun_get_seed_virgins`.
size_t aflrun_get_virgins(
	const ctx_t* targets, size_t num, u8** ret_maps, size_t* ret_clusters)
	// `ret_maps` and `ret_clusters` must have size at least `num`
{
	if (config.no_diversity)
		return 0;
	const ctx_t* t_end = targets + num;
	// The maximum potential number of clusters is current number of cluster
	// plus number of new context-sensitive targets, because each target
	// can only increase the number of clusters by one.
	bo::dynamic_bitset<> visited_clusters(clusters.size() + num);
	visited_clusters[0] = true; // always skip primary cluster

	size_t idx = 0;
	for (const ctx_t* t = targets; t < t_end; ++t)
	{
		// Note that even if binary is compiled with AFLRUN_CTX_DIV,
		// but fuzzer is not, it can still work correctly
		size_t cluster = clusters.get_cluster(to_cluster_target(t));
		if (visited_clusters[cluster])
			continue;
		visited_clusters[cluster] = true;

		ret_clusters[idx] = cluster;
		ret_maps[idx++] = clusters.get_virgin_map(cluster);
	}
	return idx;
}

// The maximum number of clusters of a seed is number of active diversity
// blocks it cover, assuming each diversity block can create one cluster,
// including primary cluster.
size_t aflrun_max_clusters(u32 seed)
{
	auto it = div_blocks->seed_blocks.find(seed);
	return 1 +
		(it == div_blocks->seed_blocks.end() ? 0 : it->second.size());
}

// Basically same as above, except div blocks are fetched from `div_blocks`
size_t aflrun_get_seed_virgins(u32 seed, u8** ret_maps, size_t* ret_clusters)
{
	if (config.no_diversity)
		return 0;
	auto it = div_blocks->seed_blocks.find(seed);
	if (it == div_blocks->seed_blocks.end())
		return 0;
	bo::dynamic_bitset<> visited_clusters(clusters.size() + it->second.size());
	visited_clusters[0] = true; // always skip primary cluster

	size_t idx = 0;
	for (auto t : it->second)
	{
		size_t cluster = clusters.get_cluster(t);
		if (visited_clusters[cluster])
			continue;
		visited_clusters[cluster] = true;

		ret_clusters[idx] = cluster;
		ret_maps[idx++] = clusters.get_virgin_map(cluster);
	}
	return idx;
}

size_t aflrun_get_seed_tops(u32 seed, void*** ret_tops)
{
	if (config.no_diversity)
		return 0;
	auto it = div_blocks->seed_blocks.find(seed);
	if (it == div_blocks->seed_blocks.end())
		return 0;
	bo::dynamic_bitset<> visited_clusters(clusters.size() + it->second.size());
	visited_clusters[0] = true; // always skip primary cluster

	size_t idx = 0;
	for (auto t : it->second)
	{
		size_t cluster = clusters.get_cluster(t);
		if (visited_clusters[cluster])
			continue;
		visited_clusters[cluster] = true;

		ret_tops[idx++] = clusters.get_top_rated(cluster);
	}
	return idx;
}

size_t aflrun_get_num_clusters(void)
{
	size_t size = clusters.size();
	size_t ret = 0;
	for (size_t i = 0; i < size; ++i)
	{
		if (clusters.get_top_rated(i)) ++ret;
	}
	return ret;
}

size_t aflrun_get_all_tops(void*** ret_tops, u8 mode)
{
	if (config.no_diversity)
		return 0;
	return clusters.get_all_tops(ret_tops, mode);
}

void aflrun_set_num_active_seeds(u32 n)
{
	num_active_seeds = n;
}

void discover_word_mul(u8 *new_bits,
	u64 *current, u64* const *virgins, size_t num, size_t idx, u8 modify)
{
	u64 or_all = 0;
	unique_ptr<vector<u64>> and_bit_seq(nullptr);

	for (size_t i = 0; i < num; ++i)
	{
		u64* virgin = virgins[i] + idx;

		u64 tmp = *current & *virgin;

		if (and_bit_seq != nullptr)
			and_bit_seq->push_back(tmp);

		if (tmp)
		{
			or_all |= tmp;

			// For the first time we touched a virgin map,
			// we create the sequence to store all `*current & *virgin` values.
			// This is a lazy approach so that we don't create the sequence
			// for most zero sequences.
			if (and_bit_seq == nullptr)
			{
				and_bit_seq = make_unique<vector<u64>>();
				and_bit_seq->reserve(num);
				// Since this is the first time we touch virgin bits,
				// all previous `*current & *virgin` values are zeros.
				for (size_t j = 0; j < i; ++j)
					and_bit_seq->push_back(0);
				and_bit_seq->push_back(tmp);
			}

			u8* ret = new_bits + i;
			if (likely(*ret < 2))
			{
				u8 *cur = (u8 *)current;
				u8 *vir = (u8 *)virgin;

				if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
					(cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
					(cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
					(cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
					*ret = 2;
				else
					*ret = 1;
			}
			if (modify)
				*virgin &= ~*current;
		}
	}

	if (modify && or_all != 0)
	{
		clusters.add_bit_seq(or_all, std::move(and_bit_seq));
	}
}

void aflrun_commit_bit_seqs(const size_t* cs, size_t num)
{
	clusters.commit_bit_seqs(cs, num);
}