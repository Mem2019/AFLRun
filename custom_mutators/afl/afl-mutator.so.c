#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>
#include <stdbool.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

static s32 dev_urandom_fd = -1;
static u32 rand_cnt;

struct extra_data {
  u8* data;                           /* Dictionary token data            */
  u32 len;                            /* Dictionary token length          */
  u32 hit_cnt;                        /* Use count in the corpus          */
};

static struct extra_data* extras;     /* Extra tokens to fuzz with        */
static u32 extras_cnt;                /* Total number of tokens read      */

static struct extra_data* a_extras;   /* Automatically selected extras    */
static u32 a_extras_cnt;              /* Total number of tokens available */

static u8* fuzz_buf;
static u8** splice_bufs;
static u32* splice_buf_sizes;
static u32 num_splice_bufs = 0;
static u64 cycle_time;

/* Interesting values, as per config.h */

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

static u64 init_time;

static u8 no_splicing = 0;

/************ MOpt Starts ************/
static u64 limit_time_puppet = 0;
static u64 orig_hit_cnt_puppet = 0;
static u64 last_limit_time_start = 0;
static u64  tmp_pilot_time = 0;
static u64 total_pacemaker_time = 0;
static u64 total_puppet_find = 0;
static u64 temp_puppet_find = 0;
static u64 most_time_key = 0;
static u64 most_time_puppet = 0;
static u64 old_hit_count = 0;
static int SPLICE_CYCLES_puppet;
static int limit_time_sig = 0;
static int key_puppet = 0;
static int key_module = 0;
static double w_init = 0.9;
static double w_end = 0.3;
static double w_now;
static int g_now = 0;
static int g_max = 5000;
#define operator_num 18
#define swarm_num 5
#define period_core  500000
static u64 tmp_core_time = 0;
static int swarm_now = 0 ;
static double x_now[swarm_num][operator_num],
     L_best[swarm_num][operator_num],
     eff_best[swarm_num][operator_num],
     G_best[operator_num],
     v_now[swarm_num][operator_num],
       probability_now[swarm_num][operator_num],
     swarm_fitness[swarm_num];

static u64 stage_finds_puppet[swarm_num][operator_num],
			/* Patterns found per fuzz stage    */
            stage_finds_puppet_v2[swarm_num][operator_num],
            stage_cycles_puppet_v2[swarm_num][operator_num],
            stage_cycles_puppet_v3[swarm_num][operator_num],
            stage_cycles_puppet[swarm_num][operator_num],
      operator_finds_puppet[operator_num],
      core_operator_finds_puppet[operator_num],
      core_operator_finds_puppet_v2[operator_num],
      core_operator_cycles_puppet[operator_num],
      core_operator_cycles_puppet_v2[operator_num],
      core_operator_cycles_puppet_v3[operator_num];
	  /* Execs per fuzz stage             */


#define RAND_C (rand()%1000*0.001)
#define v_max 1
#define v_min 0.05
#define limit_time_bound 1.1
#define SPLICE_CYCLES_puppet_up 25
#define SPLICE_CYCLES_puppet_low 5
#define STAGE_RANDOMBYTE 12
#define STAGE_DELETEBYTE 13
#define STAGE_Clone75 14
#define STAGE_OverWrite75 15
#define STAGE_OverWriteExtra 16
#define STAGE_InsertExtra 17

#define period_pilot 50000
static double period_pilot_tmp = 5000.0;

static int key_lv = 0;

static int select_algorithm(int extras) {

  int i_puppet, j_puppet;
  //double total_puppet = 0.0;
  //srandom(time(NULL));

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);

  //double sele = ((double)(random()%10000)*0.0001);
  //SAYF("select : %f\n",sele);
  j_puppet = 0;
  int operator_number = operator_num;
  if (extras < 2) operator_number = operator_number - 2;
  double range_sele = (double)probability_now[swarm_now][operator_number - 1];
  double sele = ((double)(random() % 10000) * 0.0001 * range_sele);

  for (i_puppet = 0; i_puppet < operator_number; i_puppet++)
  {
      if (unlikely(i_puppet == 0))
      {
          if (sele < probability_now[swarm_now][i_puppet])
            break;
      }
      else
      {
          if (sele < probability_now[swarm_now][i_puppet])
          {
              j_puppet =1;
              break;
          }
      }
  }
  if ((j_puppet ==1 && sele < probability_now[swarm_now][i_puppet-1]) ||
      (i_puppet + 1 < operator_num &&
        sele > probability_now[swarm_now][i_puppet +  1]))
    FATAL("error select_algorithm");
  return i_puppet;
}

static void show_mopt_stats(void) {
  if (limit_time_sig == 1)
  {
    if (key_puppet == 0)
    {
      if (key_module == 0)
      {
        printf("%s", "MOpt-AFL (pilot_fuzzing)");
      }
      else if (key_module == 1)
      {
        printf("%s", "MOpt-AFL (core_fuzzing)");
      }
      else if (key_module == 2)
      {
        printf("%s", "MOpt-AFL (pso_updating)");
      }
    }
    else
    {
      if (key_module == 0)
      {
        printf("%s", "MOpt-AFL + pacemaker (pilot_fuzzing)");
      }
      else if (key_module == 1)
      {
        printf("%s", "MOpt-AFL + pacemaker (core_fuzzing)");
      }
      else if (key_module == 2)
      {
        printf("%s", "MOpt-AFL + pacemaker (pso_updating)");
      }
    }
  }
  else
  {
    printf("%s", "AFL");
  }
}

static void pso_updating(void) {

  g_now += 1;
  if (g_now > g_max) g_now = 0;
  w_now = (w_init - w_end)*(g_max - g_now) / (g_max)+w_end;
  int tmp_swarm, i, j;
  u64 temp_operator_finds_puppet = 0;
  for (i = 0; i < operator_num; i++)
  {
    operator_finds_puppet[i] = core_operator_finds_puppet[i];

    for (j = 0; j < swarm_num; j++)
    {
      operator_finds_puppet[i] =
        operator_finds_puppet[i] + stage_finds_puppet[j][i];
    }
    temp_operator_finds_puppet =
      temp_operator_finds_puppet + operator_finds_puppet[i];
  }

  for (i = 0; i < operator_num; i++)
  {
    if (operator_finds_puppet[i])
      G_best[i] = (double)((double)(operator_finds_puppet[i]) /
        (double)(temp_operator_finds_puppet));
  }

  for (tmp_swarm = 0; tmp_swarm < swarm_num; tmp_swarm++)
  {
    double x_temp = 0.0;
    for (i = 0; i < operator_num; i++)
    {
      probability_now[tmp_swarm][i] = 0.0;
      v_now[tmp_swarm][i] = w_now * v_now[tmp_swarm][i] +
        RAND_C * (L_best[tmp_swarm][i] - x_now[tmp_swarm][i]) +
        RAND_C * (G_best[i] - x_now[tmp_swarm][i]);
      x_now[tmp_swarm][i] += v_now[tmp_swarm][i];
      if (x_now[tmp_swarm][i] > v_max)
        x_now[tmp_swarm][i] = v_max;
      else if (x_now[tmp_swarm][i] < v_min)
        x_now[tmp_swarm][i] = v_min;
      x_temp += x_now[tmp_swarm][i];
    }

    for (i = 0; i < operator_num; i++)
    {
      x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / x_temp;
      if (likely(i != 0))
        probability_now[tmp_swarm][i] =
          probability_now[tmp_swarm][i - 1] + x_now[tmp_swarm][i];
      else
        probability_now[tmp_swarm][i] = x_now[tmp_swarm][i];
    }
    if (probability_now[tmp_swarm][operator_num - 1] < 0.99 ||
        probability_now[tmp_swarm][operator_num - 1] > 1.01)
        FATAL("ERROR probability");
  }
  swarm_now = 0;
  key_module = 0;
}


/* TODO:
static u8 fuzz_one(char** argv) {
  int key_val_lv = 0;
  if (limit_time_sig == 0)
    key_val_lv = normal_fuzz_one(argv);
  else
  {
    if (key_module == 0)
      key_val_lv = pilot_fuzzing(argv);
    else if (key_module == 1)
      key_val_lv = core_fuzzing(argv);
    else if (key_module == 2)
      pso_updating();
  }

  return key_val_lv;
}

TODO: add at initialization
  {    //default L
      limit_time_sig = 1;
      limit_time_puppet = 1;
      u64 limit_time_puppet2 = limit_time_puppet * 60 * 1000;
      if (limit_time_puppet2 < limit_time_puppet ) FATAL("limit_time overflow");
      limit_time_puppet = limit_time_puppet2;
      SAYF("default limit_time_puppet %llu\n",limit_time_puppet);
  }

srandom(time(NULL));

case 'V':{
 most_time_key = 1;
 if (sscanf(optarg, "%llu", &most_time_puppet) < 1 ||
  optarg[0] == '-') FATAL("Bad syntax used for -V");
 }
break;


        case 'L': {

            //if (limit_time_sig)  FATAL("Multiple -L options not supported");
            limit_time_sig = 1;

      if (sscanf(optarg, "%llu", &limit_time_puppet) < 1 ||
        optarg[0] == '-') FATAL("Bad syntax used for -L");

      u64 limit_time_puppet2 = limit_time_puppet * 60 * 1000;

      if (limit_time_puppet2 < limit_time_puppet ) FATAL("limit_time overflow");
        limit_time_puppet = limit_time_puppet2;

      SAYF("limit_time_puppet %llu\n",limit_time_puppet);

      if (limit_time_puppet == 0 )
          key_puppet = 1;


        }
        break;


{                //initialize swarms
                        int i;
                        int tmp_swarm = 0;
                        swarm_now = 0;

                        if (g_now > g_max) g_now = 0;
                                w_now = (w_init - w_end)*(g_max - g_now) / (g_max)+w_end;

                        for (tmp_swarm = 0; tmp_swarm < swarm_num; tmp_swarm++)
                        {
                                double total_puppet_temp = 0.0;
                                swarm_fitness[tmp_swarm] = 0.0;

                                for (i = 0; i < operator_num; i++)
                                {
                                        stage_finds_puppet[tmp_swarm][i] = 0;
                                        probability_now[tmp_swarm][i] = 0.0;
                                        x_now[tmp_swarm][i] = ((double)(random() % 7000)*0.0001 + 0.1);
                                        total_puppet_temp += x_now[tmp_swarm][i];
                                        v_now[tmp_swarm][i] = 0.1;
                                        L_best[tmp_swarm][i] = 0.5;
                                        G_best[i] = 0.5;
                                        eff_best[tmp_swarm][i] = 0.0;

                                }


                                for (i = 0; i < operator_num; i++) {
                                        stage_cycles_puppet_v2[tmp_swarm][i] = stage_cycles_puppet[tmp_swarm][i];
                                        stage_finds_puppet_v2[tmp_swarm][i] = stage_finds_puppet[tmp_swarm][i];
                                        x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / total_puppet_temp;
                                }

                                double x_temp = 0.0;

                                for (i = 0; i < operator_num; i++)
                                {
                                        probability_now[tmp_swarm][i] = 0.0;
                                        v_now[tmp_swarm][i] = w_now * v_now[tmp_swarm][i] + RAND_C * (L_best[tmp_swarm][i] - x_now[tmp_swarm][i]) + RAND_C * (G_best[i] - x_now[tmp_swarm][i]);

                                        x_now[tmp_swarm][i] += v_now[tmp_swarm][i];

                                        if (x_now[tmp_swarm][i] > v_max)
                                                x_now[tmp_swarm][i] = v_max;
                                        else if (x_now[tmp_swarm][i] < v_min)
                                                x_now[tmp_swarm][i] = v_min;

                                        x_temp += x_now[tmp_swarm][i];
                                }

                                for (i = 0; i < operator_num; i++)
                                {
                                        x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / x_temp;
                                        if (likely(i != 0))
                                                probability_now[tmp_swarm][i] = probability_now[tmp_swarm][i - 1] + x_now[tmp_swarm][i];
                                        else
                                                probability_now[tmp_swarm][i] = x_now[tmp_swarm][i];
                                }
                                if (probability_now[tmp_swarm][operator_num - 1] < 0.99 || probability_now[tmp_swarm][operator_num - 1] > 1.01)
                                    FATAL("ERROR probability");





                        }

                        for (i = 0; i < operator_num; i++)
                        {
                                core_operator_finds_puppet[i] = 0;
                                core_operator_finds_puppet_v2[i] = 0;
                                core_operator_cycles_puppet[i] = 0;
                                core_operator_cycles_puppet_v2[i] = 0;
                                core_operator_cycles_puppet_v3[i] = 0;
                        }

                  }

*/

/* TODO: fuzzing loop

    u64 cur_ms_lv = get_cur_time();
if(most_time_key ==1)
{
    if( most_time_puppet * 1000 <  cur_ms_lv  - start_time)
    break;
}

*/

/************ MOpt Ends ************/

static inline u32 UR(u32 limit) {

  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN((get_cur_time() - init_time) / 1000 / cycle_time + 1, 3);

  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default:

             if (UR(10)) {

               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;

             } else {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

             }

  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

}

/* Describe integer as memory size. */

static u8* DMS(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}

/* Helper function for load_extras. */

static int compare_extras_len(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;

  return e1->len - e2->len;
}

/* Read extras from a file, sort by size. */

static void load_extras_file(u8* fname, u32* min_len, u32* max_len,
                             u32 dict_level) {

  FILE* f;
  u8  buf[MAX_LINE];
  u8  *lptr;
  u32 cur_line = 0;

  f = fopen(fname, "r");

  if (!f) PFATAL("Unable to open '%s'", fname);

  while ((lptr = fgets(buf, MAX_LINE, f))) {

    u8 *rptr, *wptr;
    u32 klen = 0;

    cur_line++;

    /* Trim on left and right. */

    while (isspace(*lptr)) lptr++;

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr)) rptr--;
    rptr++;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#') continue;

    /* All other lines must end with '"', which we can consume. */

    rptr--;

    if (rptr < lptr || *rptr != '"')
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_') lptr++;

    /* If @number follows, parse that. */

    if (*lptr == '@') {

      lptr++;
      if (atoi(lptr) > dict_level) continue;
      while (isdigit(*lptr)) lptr++;

    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=') lptr++;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

    lptr++;

    if (!*lptr) FATAL("Empty keyword in line %u.", cur_line);

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
               sizeof(struct extra_data));

    wptr = extras[extras_cnt].data = ck_alloc(rptr - lptr);

    while (*lptr) {

      char* hexdigits = "0123456789abcdef";

      switch (*lptr) {

        case 1 ... 31:
        case 128 ... 255:
          FATAL("Non-printable characters in line %u.", cur_line);

        case '\\':

          lptr++;

          if (*lptr == '\\' || *lptr == '"') {
            *(wptr++) = *(lptr++);
            klen++;
            break;
          }

          if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
            FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

          *(wptr++) =
            ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
            (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

          lptr += 3;
          klen++;

          break;

        default:

          *(wptr++) = *(lptr++);
          klen++;

      }

    }

    extras[extras_cnt].len = klen;

    if (extras[extras_cnt].len > MAX_DICT_FILE)
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
            DMS(klen), DMS(MAX_DICT_FILE));

    if (*min_len > klen) *min_len = klen;
    if (*max_len < klen) *max_len = klen;

    extras_cnt++;

  }

  fclose(f);

}


/* Read extras from the extras directory and sort them by size. */

static void load_extras(u8* dir) {

  DIR* d;
  struct dirent* de;
  u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8* x;

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr(dir, '@'))) {

    *x = 0;
    dict_level = atoi(x + 1);

  }

  ACTF("Loading extra dict for AFL from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);

  if (!d) {

    if (errno == ENOTDIR) {
      load_extras_file(dir, &min_len, &max_len, dict_level);
      goto check_and_sort;
    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (x) FATAL("Dictionary levels not supported for directories.");

  while ((de = readdir(d))) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", dir, de->d_name);
    s32 fd;

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_DICT_FILE)
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_DICT_FILE));

    if (min_len > st.st_size) min_len = st.st_size;
    if (max_len < st.st_size) max_len = st.st_size;

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
               sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(st.st_size);
    extras[extras_cnt].len  = st.st_size;

    fd = open(fn, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", fn);

    ck_read(fd, extras[extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    extras_cnt++;

  }

  closedir(d);

check_and_sort:

  if (!extras_cnt) FATAL("No usable files in '%s'", dir);

  qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);

  OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt,
      DMS(min_len), DMS(max_len));

  if (max_len > 32)
    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          DMS(max_len));

  if (extras_cnt > MAX_DET_EXTRAS)
    WARNF("More than %u tokens - will use them probabilistically.",
          MAX_DET_EXTRAS);

}

// take *p_buf with size *p_len, return mutated buffer and size into them.
static void afl_havoc(u8** p_buf, s32* p_len, u32 max_seed_size) {

  s32 temp_len = *p_len;
  u8* out_buf = *p_buf; // Note this should be allocated from AFL heap API

  u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

  for (s32 i = 0; i < use_stacking; i++) {

    switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

      case 0:

        /* Flip a single bit somewhere. Spooky! */

        FLIP_BIT(out_buf, UR(temp_len << 3));
        break;

      case 1:

        /* Set byte to interesting value. */

        out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
        break;

      case 2:

        /* Set word to interesting value, randomly choosing endian. */

        if (temp_len < 2) break;

        if (UR(2)) {

          *(u16*)(out_buf + UR(temp_len - 1)) =
            interesting_16[UR(sizeof(interesting_16) >> 1)];

        } else {

          *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
            interesting_16[UR(sizeof(interesting_16) >> 1)]);

        }

        break;

      case 3:

        /* Set dword to interesting value, randomly choosing endian. */

        if (temp_len < 4) break;

        if (UR(2)) {

          *(u32*)(out_buf + UR(temp_len - 3)) =
            interesting_32[UR(sizeof(interesting_32) >> 2)];

        } else {

          *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
            interesting_32[UR(sizeof(interesting_32) >> 2)]);

        }

        break;

      case 4:

        /* Randomly subtract from byte. */

        out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
        break;

      case 5:

        /* Randomly add to byte. */

        out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
        break;

      case 6:

        /* Randomly subtract from word, random endian. */

        if (temp_len < 2) break;

        if (UR(2)) {

          u32 pos = UR(temp_len - 1);

          *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(temp_len - 1);
          u16 num = 1 + UR(ARITH_MAX);

          *(u16*)(out_buf + pos) =
            SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

        }

        break;

      case 7:

        /* Randomly add to word, random endian. */

        if (temp_len < 2) break;

        if (UR(2)) {

          u32 pos = UR(temp_len - 1);

          *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(temp_len - 1);
          u16 num = 1 + UR(ARITH_MAX);

          *(u16*)(out_buf + pos) =
            SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

        }

        break;

      case 8:

        /* Randomly subtract from dword, random endian. */

        if (temp_len < 4) break;

        if (UR(2)) {

          u32 pos = UR(temp_len - 3);

          *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(temp_len - 3);
          u32 num = 1 + UR(ARITH_MAX);

          *(u32*)(out_buf + pos) =
            SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

        }

        break;

      case 9:

        /* Randomly add to dword, random endian. */

        if (temp_len < 4) break;

        if (UR(2)) {

          u32 pos = UR(temp_len - 3);

          *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(temp_len - 3);
          u32 num = 1 + UR(ARITH_MAX);

          *(u32*)(out_buf + pos) =
            SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

        }

        break;

      case 10:

        /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */

        out_buf[UR(temp_len)] ^= 1 + UR(255);
        break;

      case 11 ... 12: {

          /* Delete bytes. We're making this a bit more likely
             than insertion (the next option) in hopes of keeping
             files reasonably small. */

          u32 del_from, del_len;

          if (temp_len < 2) break;

          /* Don't delete too much. */

          del_len = choose_block_len(temp_len - 1);

          del_from = UR(temp_len - del_len + 1);

          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;

          break;

        }

      case 13:

        if (temp_len + HAVOC_BLK_XL < max_seed_size) {

          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          u8  actually_clone = UR(4);
          u32 clone_from, clone_to, clone_len;
          u8* new_buf;

          if (actually_clone) {

            clone_len  = choose_block_len(temp_len);
            clone_from = UR(temp_len - clone_len + 1);

          } else {

            clone_len = choose_block_len(HAVOC_BLK_XL);
            clone_from = 0;

          }

          clone_to   = UR(temp_len);

          new_buf = ck_alloc_nozero(temp_len + clone_len);

          /* Head */

          memcpy(new_buf, out_buf, clone_to);

          /* Inserted part */

          if (actually_clone)
            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
          else
            memset(new_buf + clone_to,
                   UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

          /* Tail */
          memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                 temp_len - clone_to);

          ck_free(out_buf);
          out_buf = new_buf;
          temp_len += clone_len;

        }

        break;

      case 14: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          u32 copy_from, copy_to, copy_len;

          if (temp_len < 2) break;

          copy_len  = choose_block_len(temp_len - 1);

          copy_from = UR(temp_len - copy_len + 1);
          copy_to   = UR(temp_len - copy_len + 1);

          if (UR(4)) {

            if (copy_from != copy_to)
              memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          } else memset(out_buf + copy_to,
                        UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

          break;

        }

      /* Values 15 and 16 can be selected only if there are any extras
         present in the dictionaries. */

      case 15: {

          /* Overwrite bytes with an extra. */

          if (!extras_cnt || (a_extras_cnt && UR(2))) {

            /* No user-specified extras or odds in our favor. Let's use an
               auto-detected one. */

            u32 use_extra = UR(a_extras_cnt);
            u32 extra_len = a_extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = UR(temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {

            /* No auto extras or odds in our favor. Use the dictionary. */

            u32 use_extra = UR(extras_cnt);
            u32 extra_len = extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = UR(temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

          }

          break;

        }

      case 16: {

          u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
          u8* new_buf;

          /* Insert an extra. Do the same dice-rolling stuff as for the
             previous case. */

          if (!extras_cnt || (a_extras_cnt && UR(2))) {

            use_extra = UR(a_extras_cnt);
            extra_len = a_extras[use_extra].len;

            if (temp_len + extra_len >= max_seed_size) break;

            new_buf = ck_alloc_nozero(temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {

            use_extra = UR(extras_cnt);
            extra_len = extras[use_extra].len;

            if (temp_len + extra_len >= max_seed_size) break;

            new_buf = ck_alloc_nozero(temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

          }

          /* Tail */
          memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                 temp_len - insert_at);

          ck_free(out_buf);
          out_buf   = new_buf;
          temp_len += extra_len;

          break;

        }

    }

  }

  *p_buf = out_buf;
  *p_len = temp_len;

}

static void locate_diffs(
  const u8* ptr1, const u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) f_loc = pos;
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

static void generate_splice(
  u8 *in_buf, size_t len, u8 *add_buf, size_t add_buf_size) {

  if (likely(num_splice_bufs >= SPLICE_CYCLES))
    return;

  u8* new_buf = ck_alloc_nozero(add_buf_size);
  memcpy(new_buf, add_buf, add_buf_size);

  /* Find a suitable splicing location, somewhere between the first and
     the last differing byte. Bail out if the difference is just a single
     byte or so. */

  s32 f_diff, l_diff;
  locate_diffs(in_buf, new_buf, MIN(len, add_buf_size), &f_diff, &l_diff);

  if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {

    ck_free(new_buf);
    return;

  }

  /* Split somewhere between the first and last differing byte. */

  u32 split_at = f_diff + UR(l_diff - f_diff);

  /* Do the thing. */

  splice_buf_sizes[num_splice_bufs] = add_buf_size;
  memcpy(new_buf, in_buf, split_at);
  splice_bufs[num_splice_bufs++] = new_buf;

}

void *afl_custom_init(void* p, unsigned int s) {
  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");
  u8  *extras_dir = getenv("AFL_DICT"); // TODO: parse /proc/self/cmdline instead
  if (extras_dir) load_extras(extras_dir);
  splice_bufs = ck_alloc(SPLICE_CYCLES * sizeof(u8*));
  splice_buf_sizes = ck_alloc_nozero(SPLICE_CYCLES * sizeof(u32));
  const char* s_cycle_time = getenv("AFLRUN_CYCLE_TIME");
  cycle_time = (s_cycle_time == NULL) ? 600 : strtoull(s_cycle_time, NULL, 10);
  if (cycle_time == 0) cycle_time = 600;
  init_time = get_cur_time();
  no_splicing = getenv("NO_SPLICING") != NULL;
  return (void*)1;
}

void afl_custom_deinit(void* p) {
  close(dev_urandom_fd);
}

// Prepare all splice input buffers in this function
u32 afl_custom_fuzz_count(
  void *data, const u8 *in_buf, size_t len, u32 saved_max) {

  for (u32 i = 0; i < num_splice_bufs; ++i)
    ck_free(splice_bufs[i]);

  num_splice_bufs = 0;

  // AFLRun will ignore this anyway
  return saved_max;

}

size_t afl_custom_fuzz(void *data, u8 *buf, size_t buf_size, u8 **out_buf,
                        u8 *add_buf, size_t add_buf_size, size_t max_size) {

  u8* input_buf; s32 temp_len;

  if (!no_splicing)
    generate_splice(buf, buf_size, add_buf, add_buf_size);

  // Execute HAVOC and SPLICE interleavingly, with same expected ratio as AFL.
  // The bias exists but is negligible.
  if (buf_size <= 1 || num_splice_bufs == 0 ||
    UR(HAVOC_CYCLES + SPLICE_HAVOC * SPLICE_CYCLES) < HAVOC_CYCLES) {
    // HAVOC

    input_buf = buf;
    temp_len = buf_size;

  } else {

    u32 idx = UR(num_splice_bufs);
    input_buf = splice_bufs[idx];
    temp_len = splice_buf_sizes[idx];

  }

  fuzz_buf = ck_realloc(fuzz_buf, temp_len);
  memcpy(fuzz_buf, input_buf, temp_len);
  afl_havoc(&fuzz_buf, &temp_len, max_size);
  *out_buf = fuzz_buf;
  return temp_len;

}