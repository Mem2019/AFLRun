#ifndef _HAVE_AFL_RUN_H
#define _HAVE_AFL_RUN_H

#include "types.h"
#include "config.h"

#ifdef __cplusplus
extern "C"
{
#endif
	/* functions called at initialization */

	void aflrun_load_config(const char* config_str,
		u8* check_at_begin, u8* log_at_begin, u64* log_check_interval,
		double* trim_thr, double* queue_quant_thr, u32* min_num_exec);

	void aflrun_load_freachables(const char* temp_path,
		reach_t* num_ftargets, reach_t* num_freachables);
	void aflrun_load_edges(const char* bb_edges, reach_t num_reachables);
	void aflrun_load_dists(const char* dir, reach_t num_targets,
		reach_t num_reachables, char** reachable_names);

	void aflrun_init_fringes(
		reach_t num_reachables, reach_t num_targets);
	void aflrun_init_groups(reach_t num_targets);

	void aflrun_init_globals(void* afl,
		reach_t num_targets, reach_t num_reachables,
		reach_t num_ftargets, reach_t num_freachables,
		u8* virgin_reachables, u8* virgin_freachables, u8* virgin_ctx,
		char** reachable_names, reach_t** reachable_to_targets,
		reach_t* reachable_to_size, const char* out_dir,
		const double* target_weights, u32 map_size, u8* div_switch,
		const char* cycle_time);

	void aflrun_remove_seed(u32 seed);

	/* functions used to update fringe */

	// path-sensitive fringe, called for mutated input and new imported seed
	// One thing to note is that we don't consider seed that varies in coverage
	// among different runs, in which case we only use the coverage of the first
	// run (e.i. `common_fuzz_stuff` for mutated input and sync input or
	// first calibration for imported seed)
	u8 aflrun_has_new_path(const u8* freached, const u8* reached, const u8* path,
		const ctx_t* virgin_trace, size_t len, u8 inc, u32 seed,
		const u8* new_bits, const size_t* clusters, size_t num_clusters);
	u8 aflrun_end_cycle();
	void aflrun_update_fuzzed_quant(u32 id, double fuzzed_quant);

	/* functions for debugging and inspecting */

	void aflrun_check_state(void);
	void aflrun_log_fringes(const char* path, u8 prog);
	void aflrun_get_state(int* cycle_count, u32* cov_quant,
		size_t* div_num_invalid, size_t* div_num_fringes);
	u64 aflrun_queue_cycle(void);
	u8 aflrun_get_mode(void);
	bool aflrun_is_uni(void);
	void aflrun_get_reached(reach_t* num_reached, reach_t* num_freached,
		reach_t* num_reached_targets, reach_t* num_freached_targets);
	double aflrun_get_seed_quant(u32 seed);
	void aflrun_get_time(u64* last_reachable, u64* last_fringe,
		u64* last_pro_fringe, u64* last_target, u64* last_ctx_reachable,
		u64* last_ctx_fringe, u64* last_ctx_pro_fringe, u64* last_ctx_target);

	/* functions called at begining of each cycle to assign energy */

	// calculate energy for each seed
	void aflrun_assign_energy(u32 num_seeds, const u32* seeds, double* ret);
	void aflrun_set_num_active_seeds(u32 n);
	u8 aflrun_cycle_end(u8*);

	// update score and queue culling
	void aflrun_update_fringe_score(u32 seed);
	u32 aflrun_cull_queue(u32* seeds, u32 num);
	void aflrun_set_favored_seeds(const u32* seeds, u32 num, u8 mode);

	/* Functions for the second diversity idea */

	// Get virgin maps associated with given targets, result goes into `ret_maps`
	size_t aflrun_get_virgins(
		const ctx_t* targets, size_t num, u8** ret_maps, size_t* ret_clusters);
	size_t aflrun_max_clusters(u32 seed);
	size_t aflrun_get_seed_virgins(u32 seed, u8** ret_maps, size_t* ret_clusters);
	size_t aflrun_get_seed_tops(u32 seed, void*** ret_tops);
	size_t aflrun_get_num_clusters(void);
	size_t aflrun_get_all_tops(void*** ret_tops, u8 mode);

	// For target clustering
#ifdef WORD_SIZE_64
	void discover_word_mul(u8 *new_bits,
		u64 *current, u64* const *virgins, size_t num, size_t idx, u8 modify);
#else
	#error "Please use 64-bit to compile AFLRun"
#endif
	void aflrun_commit_bit_seqs(const size_t* clusters, size_t num);

	// AFL interfaces
	u64 get_seed_fav_factor(void* afl_void, u32 seed);
	double get_seed_perf_score(void* afl_void, u32 seed);
	bool get_seed_div_favored(void* afl_void, u32 seed);
	u8 get_seed_cov_favored(void* afl_void, u32 seed);
	void disable_aflrun_extra(void* afl_void, u32 seed);
	u64 get_cur_time(void);

#ifdef __cplusplus
}
#endif

#endif /* !_HAVE_AFL_RUN_H */