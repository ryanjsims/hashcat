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
  u64 prefix_hash;

} murmur64a_tmp_t;

KERNEL_FQ void m95001_init (KERN_ATTR_TMPS (murmur64a_tmp_t))
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

  if (password_length < 8 || password_length % 2 || password_length > 70)
  {
    //printf("WARNING: password must be of even length >= 8 and <= 70\n");
    tmps[gid].prefix_hash = 0x0;
    return;
  }

  u32 salt_idx = (password_length / 2) - 4;

  tmps[gid].prefix_hash = (u64)salt_bufs[SALT_POS_HOST].salt_buf[ salt_idx * 2] | (((u64)salt_bufs[SALT_POS_HOST].salt_buf[ salt_idx * 2 + 1]) << 32);
}

KERNEL_FQ void m95001_loop (KERN_ATTR_TMPS (murmur64a_tmp_t))
{

}

KERNEL_FQ void m95001_comp (KERN_ATTR_TMPS (murmur64a_tmp_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 mix = 0xc6a4a7935bd1e995;

  u64 hash = tmps[gid].prefix_hash;
  

  int i;
  // printf("\n");
  // printf("prefix hash = %08x%08x\n", h32_from_64(hash), l32_from_64(hash));
  for (i = 0; tmps[gid].byte_length - i >= 8; i += 8)
  {
    u64 key = tmps[gid].password_buf[i / 8];

    key *= mix;
    key ^= key >> SHIFTS;
    key *= mix;

    hash ^= key;
    hash *= mix;

    // printf("i = % 3d  hash = %08x%08x  key = %08x%08x\n", i, h32_from_64(hash), l32_from_64(hash), h32_from_64(key), l32_from_64(key));
  }

  if (tmps[gid].byte_length - i > 0) {
    GLOBAL_AS const u8 *password_bytes = ((GLOBAL_AS const u8 *) tmps[gid].password_buf) + i;
    for (int j = tmps[gid].byte_length - i - 1; j >= 0; j--)
    {
      hash ^= (u64)password_bytes[j] << (8 * j);
      // printf("j = % 3d  hash = %08x%08x\n", j, h32_from_64(hash), l32_from_64(hash));
    }
    hash *= mix;
    // printf("i = % 3d  hash = %08x%08x\n", i, h32_from_64(hash), l32_from_64(hash));
  }

  hash ^= hash >> SHIFTS;

  hash *= mix;
  hash ^= hash >> SHIFTS;


  const u32 r0 = l32_from_64(hash);
  const u32 r1 = h32_from_64(hash);
  const u32 r2 = 0;
  const u32 r3 = 0;
  // printf("hash = %08x%08x\n", r1, r0);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}