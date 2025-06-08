/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

DECLSPEC u64x MurmurHash (const u64x seed, PRIVATE_AS const u32x *w, const u32 pw_len)
{
  u64x hash = seed;

  #define M 0xc6a4a7935bd1e995
  #define R 47

  hash ^= ((u64)pw_len) * M;
  const u32 blocks = pw_len / 8;

  if (pw_len >= 8) {
    for (u32 i = 0; i < blocks * 2; i++) {
      const u64x tmp = ((((u64)w[2 * i + 1]) << 32) | w[2 * i]) * M;
      hash = (hash ^ ((tmp ^ (tmp >> R)) * M)) * M;
    }
  }

  if (pw_len % 8 > 0) {
    const u64x tmp = (((u64)w[2 * blocks + 1]) << 32) | w[2 * blocks];
    hash ^= tmp;
    hash = hash * M;
  }

  hash = hash ^ (hash >> R);
  hash = hash * M;
  hash = hash ^ (hash >> R);

  #undef M
  #undef R

  return hash;
}

KERNEL_FQ void m95000_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[64];

  const u32 pw_len = pws[gid].pw_len;

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * main
   */

   /**
   * seed
   */

  const u64x seed = salt_bufs[SALT_POS_HOST].salt_buf[0];

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    const u64x hash = MurmurHash (seed, w, pw_len);

    const u32x r0 = l32_from_64 (hash);
    const u32x r1 = h32_from_64 (hash);
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m95000_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[64];

  const u32 pw_len = pws[gid].pw_len & 63;

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * main
   */

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * seed
   */

  const u64x seed = salt_bufs[SALT_POS_HOST].salt_buf[0];

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    const u64x hash = MurmurHash (seed, w, pw_len);

    const u32x r0 = l32_from_64(hash);
    const u32x r1 = h32_from_64(hash);
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
