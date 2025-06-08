/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#endif

#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define SHIFTS 47

typedef struct murmur64a_tmp
{
  u64 password_buf[32];
  u32 byte_length;

} murmur64a_tmp_t;

KERNEL_FQ void m95000_init (KERN_ATTR_TMPS (murmur64a_tmp_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 in[64];

  for (int i = 0; i < 64; i++)
  {
    in[i] = pws[gid].i[i];
  }

  u32 password_length = pws[gid].pw_len;

  u64 out[32];
  for(int i = 0; i < 32; i++)
  {
    out[i] = 0;
  }

  PRIVATE_AS u8 *in_ptr  = (PRIVATE_AS u8 *) in;
  PRIVATE_AS u8 *out_ptr = (PRIVATE_AS u8 *) out;

  for(int i = 0; i < password_length; i++)
  {
    out_ptr[i] = in_ptr[i];
  }

  for(int i = 0; i < 32; i++)
  {
    tmps[gid].password_buf[i] = out[i];
  }
  tmps[gid].byte_length = password_length;
}

KERNEL_FQ void m95000_loop (KERN_ATTR_TMPS (murmur64a_tmp_t))
{

}

KERNEL_FQ void m95000_comp (KERN_ATTR_TMPS (murmur64a_tmp_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 seed = 0;
  #define mix 0xc6a4a7935bd1e995

  u64 hash = seed ^ ((u64)tmps[gid].byte_length * mix);

  const u32 blocks = tmps[gid].byte_length / 8;
  if (tmps[gid].byte_length >= 8) {
    for (u32 i = 0; i < blocks; i++) {
      const u64 tmp = tmps[gid].password_buf[i] * mix;
      hash = (hash ^ (tmp ^ (tmp >> SHIFTS)) * mix) * mix;
    }
  }

  if (tmps[gid].byte_length % 8 > 0) {
    const u64 tmp = tmps[gid].password_buf[blocks];
    hash ^= tmp;
    hash = hash * mix;
  }

  hash = hash ^ (hash >> SHIFTS);
  hash = hash * mix;
  hash = hash ^ (hash >> SHIFTS);

  const u32 r0 = l32_from_64(hash);
  const u32 r1 = h32_from_64(hash);
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

// 0074616368736168
// 0074000000000000
// 