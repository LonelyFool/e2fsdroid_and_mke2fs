#!/bin/bash
cd libcutils
clang -fPIC -std=c++17 -I../include -c config_utils.cpp canned_fs_config.cpp iosched_policy.cpp load_file.cpp native_handle.cpp record_stream.cpp threads.cpp ashmem-host.cpp fs_config.cpp trace-host.cpp fs.cpp hashmap.cpp multiuser.cpp str_parms.cpp
clang -I../include -c strlcpy.c
ar rcs libcutils.a *.o

cd ../liblog
clang -fPIC -std=c++17 -fPIC -I../include -DLIBLOG_LOG_TAG=1006 -c log_event_list.cpp log_event_write.cpp logger_name.cpp logger_read.cpp logger_write.cpp logprint.cpp properties.cpp event_tag_map.cpp
ar rcs liblog.a *.o

cd ../base
clang -fPIC -std=c++17 -I../include -DPAGE_SIZE=4096 -c abi_compatibility.cpp chrono_utils.cpp cmsg.cpp file.cpp liblog_symbols.cpp logging.cpp mapped_file.cpp parsebool.cpp parsenetaddress.cpp process.cpp properties.cpp stringprintf.cpp strings.cpp threads.cpp test_utils.cpp errors_unix.cpp
ar rcs libbase.a *.o

if [ "$HOSTTYPE" = arm ] || [ "$HOSTTYPE" = aarch64 ];then
  cd ../zlib
  if [ "$HOSTTYPE" = aarch64 ];then
    CFLAGS="-DARMV8_OS_LINUX -O3 -DADLER32_SIMD_NEON -DCRC32_ARMV8_CRC32 -DINFLATE_CHUNK_READ_64LE"
  elif [ "$HOSTTYPE" = arm ];then
    CFLAGS="-DARMV8_OS_LINUX -O3"
  elif [ "$HOSTTYPE" = i686 ];then
    CFLAGS="-DX86_NOT_WINDOWS -mssse3 -mpclmul -DCRC32_SIMD_SSE42_PCLMUL"
    sources="crc_folding.c fill_window_sse.c"
  elif [ "$HOSTTYPE" = x86_64 ];then
    CFLAGS="-DX86_NOT_WINDOWS -mssse3 -mpclmul -DCRC32_SIMD_SSE42_PCLMUL -DINFLATE_CHUNK_READ_64LE"
    sources="crc_folding.c fill_window_sse.c"
  fi
  clang -fPIC -I. "$CFLAGS" -c adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c zutil.c adler32_simd.c cpu_features.c crc32_simd.c ${sources}
  ar rcs libz.a *.o
fi

cd ../libsparse
clang -fPIC -std=c++17 -I../include -I../zlib -c backed_block.cpp output_file.cpp sparse.cpp sparse_crc32.cpp sparse_err.cpp sparse_read.cpp
ar rcs libsparse.a *.o

cd ../crypto
if [ "$HOSTTYPE" = aarch64 ];then
  sources="linux-aarch64/crypto/chacha/chacha-armv8.S linux-aarch64/crypto/fipsmodule/aesv8-armx64.S linux-aarch64/crypto/fipsmodule/armv8-mont.S linux-aarch64/crypto/fipsmodule/ghash-neon-armv8.S linux-aarch64/crypto/fipsmodule/ghashv8-armx64.S linux-aarch64/crypto/fipsmodule/sha1-armv8.S linux-aarch64/crypto/fipsmodule/sha256-armv8.S linux-aarch64/crypto/fipsmodule/sha512-armv8.S linux-aarch64/crypto/fipsmodule/vpaes-armv8.S linux-aarch64/crypto/test/trampoline-armv8.S"
elif [ "$HOSTTYPE" = arm ];then
  sources="linux-arm/crypto/chacha/chacha-armv4.S linux-arm/crypto/fipsmodule/aesv8-armx32.S linux-arm/crypto/fipsmodule/armv4-mont.S linux-arm/crypto/fipsmodule/bsaes-armv7.S linux-arm/crypto/fipsmodule/ghash-armv4.S linux-arm/crypto/fipsmodule/ghashv8-armx32.S linux-arm/crypto/fipsmodule/sha1-armv4-large.S linux-arm/crypto/fipsmodule/sha256-armv4.S linux-arm/crypto/fipsmodule/sha512-armv4.S linux-arm/crypto/fipsmodule/vpaes-armv7.S linux-arm/crypto/test/trampoline-armv4.S src/crypto/curve25519/asm/x25519-asm-arm.S src/crypto/poly1305/poly1305_arm_asm.S"
elif [ "$HOSTTYPE" = i686 ];then
  sources="linux-x86/crypto/chacha/chacha-x86.S linux-x86/crypto/fipsmodule/aesni-x86.S linux-x86/crypto/fipsmodule/bn-586.S linux-x86/crypto/fipsmodule/co-586.S linux-x86/crypto/fipsmodule/ghash-ssse3-x86.S linux-x86/crypto/fipsmodule/ghash-x86.S linux-x86/crypto/fipsmodule/md5-586.S linux-x86/crypto/fipsmodule/sha1-586.S linux-x86/crypto/fipsmodule/sha256-586.S linux-x86/crypto/fipsmodule/sha512-586.S linux-x86/crypto/fipsmodule/vpaes-x86.S linux-x86/crypto/fipsmodule/x86-mont.S linux-x86/crypto/test/trampoline-x86.S"
elif [ "$HOSTTYPE" = x86_64 ];then
  sources="linux-x86_64/crypto/chacha/chacha-x86_64.S linux-x86_64/crypto/cipher_extra/aes128gcmsiv-x86_64.S linux-x86_64/crypto/cipher_extra/chacha20_poly1305_x86_64.S linux-x86_64/crypto/fipsmodule/aesni-gcm-x86_64.S linux-x86_64/crypto/fipsmodule/aesni-x86_64.S linux-x86_64/crypto/fipsmodule/ghash-ssse3-x86_64.S linux-x86_64/crypto/fipsmodule/ghash-x86_64.S linux-x86_64/crypto/fipsmodule/md5-x86_64.S linux-x86_64/crypto/fipsmodule/p256-x86_64-asm.S linux-x86_64/crypto/fipsmodule/p256_beeu-x86_64-asm.S linux-x86_64/crypto/fipsmodule/rdrand-x86_64.S linux-x86_64/crypto/fipsmodule/rsaz-avx2.S linux-x86_64/crypto/fipsmodule/sha1-x86_64.S linux-x86_64/crypto/fipsmodule/sha256-x86_64.S linux-x86_64/crypto/fipsmodule/sha512-x86_64.S linux-x86_64/crypto/fipsmodule/vpaes-x86_64.S linux-x86_64/crypto/fipsmodule/x86_64-mont.S linux-x86_64/crypto/fipsmodule/x86_64-mont5.S linux-x86_64/crypto/test/trampoline-x86_64.S src/crypto/hrss/asm/poly_rq_mul.S"
fi

clang -fPIC -I. -I../include -c err_data.c\
  src/crypto/asn1/a_bitstr.c\
  src/crypto/asn1/a_bool.c\
  src/crypto/asn1/a_d2i_fp.c\
  src/crypto/asn1/a_dup.c\
  src/crypto/asn1/a_enum.c\
  src/crypto/asn1/a_gentm.c\
  src/crypto/asn1/a_i2d_fp.c\
  src/crypto/asn1/a_int.c\
  src/crypto/asn1/a_mbstr.c\
  src/crypto/asn1/a_object.c\
  src/crypto/asn1/a_octet.c\
  src/crypto/asn1/a_print.c\
  src/crypto/asn1/a_strnid.c\
  src/crypto/asn1/a_time.c\
  src/crypto/asn1/a_type.c\
  src/crypto/asn1/a_utctm.c\
  src/crypto/asn1/a_utf8.c\
  src/crypto/asn1/asn1_lib.c\
  src/crypto/asn1/asn1_par.c\
  src/crypto/asn1/asn_pack.c\
  src/crypto/asn1/f_enum.c\
  src/crypto/asn1/f_int.c\
  src/crypto/asn1/f_string.c\
  src/crypto/asn1/tasn_dec.c\
  src/crypto/asn1/tasn_enc.c\
  src/crypto/asn1/tasn_fre.c\
  src/crypto/asn1/tasn_new.c\
  src/crypto/asn1/tasn_typ.c\
  src/crypto/asn1/tasn_utl.c\
  src/crypto/asn1/time_support.c\
  src/crypto/base64/base64.c\
  src/crypto/bio/bio.c\
  src/crypto/bio/bio_mem.c\
  src/crypto/bio/connect.c\
  src/crypto/bio/fd.c\
  src/crypto/bio/file.c\
  src/crypto/bio/hexdump.c\
  src/crypto/bio/pair.c\
  src/crypto/bio/printf.c\
  src/crypto/bio/socket.c\
  src/crypto/bio/socket_helper.c\
  src/crypto/bn_extra/bn_asn1.c\
  src/crypto/bn_extra/convert.c\
  src/crypto/buf/buf.c\
  src/crypto/bytestring/asn1_compat.c\
  src/crypto/bytestring/ber.c\
  src/crypto/bytestring/cbb.c\
  src/crypto/bytestring/cbs.c\
  src/crypto/bytestring/unicode.c\
  src/crypto/chacha/chacha.c\
  src/crypto/cipher_extra/cipher_extra.c\
  src/crypto/cipher_extra/derive_key.c\
  src/crypto/cipher_extra/e_aesccm.c\
  src/crypto/cipher_extra/e_aesctrhmac.c\
  src/crypto/cipher_extra/e_aesgcmsiv.c\
  src/crypto/cipher_extra/e_chacha20poly1305.c\
  src/crypto/cipher_extra/e_null.c\
  src/crypto/cipher_extra/e_rc2.c\
  src/crypto/cipher_extra/e_rc4.c\
  src/crypto/cipher_extra/e_tls.c\
  src/crypto/cipher_extra/tls_cbc.c\
  src/crypto/cmac/cmac.c\
  src/crypto/conf/conf.c\
  src/crypto/cpu-aarch64-fuchsia.c\
  src/crypto/cpu-aarch64-linux.c\
  src/crypto/cpu-arm-linux.c\
  src/crypto/cpu-arm.c\
  src/crypto/cpu-intel.c\
  src/crypto/cpu-ppc64le.c\
  src/crypto/crypto.c\
  src/crypto/curve25519/spake25519.c\
  src/crypto/dh/check.c\
  src/crypto/dh/dh.c\
  src/crypto/dh/dh_asn1.c\
  src/crypto/dh/params.c\
  src/crypto/digest_extra/digest_extra.c\
  src/crypto/dsa/dsa.c\
  src/crypto/dsa/dsa_asn1.c\
  src/crypto/ec_extra/ec_asn1.c\
  src/crypto/ec_extra/ec_derive.c\
  src/crypto/ecdh_extra/ecdh_extra.c\
  src/crypto/ecdsa_extra/ecdsa_asn1.c\
  src/crypto/engine/engine.c\
  src/crypto/err/err.c\
  src/crypto/evp/digestsign.c\
  src/crypto/evp/evp.c\
  src/crypto/evp/evp_asn1.c\
  src/crypto/evp/evp_ctx.c\
  src/crypto/evp/p_dsa_asn1.c\
  src/crypto/evp/p_ec.c\
  src/crypto/evp/p_ec_asn1.c\
  src/crypto/evp/p_ed25519.c\
  src/crypto/evp/p_ed25519_asn1.c\
  src/crypto/evp/p_rsa.c\
  src/crypto/evp/p_rsa_asn1.c\
  src/crypto/evp/p_x25519.c\
  src/crypto/evp/p_x25519_asn1.c\
  src/crypto/evp/pbkdf.c\
  src/crypto/evp/print.c\
  src/crypto/evp/scrypt.c\
  src/crypto/evp/sign.c\
  src/crypto/ex_data.c\
  src/crypto/fipsmodule/bcm.c\
  src/crypto/fipsmodule/fips_shared_support.c\
  src/crypto/fipsmodule/is_fips.c\
  src/crypto/hkdf/hkdf.c\
  src/crypto/hrss/hrss.c\
  src/crypto/lhash/lhash.c\
  src/crypto/mem.c\
  src/crypto/obj/obj.c\
  src/crypto/obj/obj_xref.c\
  src/crypto/pem/pem_all.c\
  src/crypto/pem/pem_info.c\
  src/crypto/pem/pem_lib.c\
  src/crypto/pem/pem_oth.c\
  src/crypto/pem/pem_pk8.c\
  src/crypto/pem/pem_pkey.c\
  src/crypto/pem/pem_x509.c\
  src/crypto/pem/pem_xaux.c\
  src/crypto/pkcs7/pkcs7.c\
  src/crypto/pkcs7/pkcs7_x509.c\
  src/crypto/pkcs8/p5_pbev2.c\
  src/crypto/pkcs8/pkcs8.c\
  src/crypto/pkcs8/pkcs8_x509.c\
  src/crypto/poly1305/poly1305.c\
  src/crypto/poly1305/poly1305_arm.c\
  src/crypto/poly1305/poly1305_vec.c\
  src/crypto/pool/pool.c\
  src/crypto/rand_extra/deterministic.c\
  src/crypto/rand_extra/forkunsafe.c\
  src/crypto/rand_extra/fuchsia.c\
  src/crypto/rand_extra/rand_extra.c\
  src/crypto/rand_extra/windows.c\
  src/crypto/rc4/rc4.c\
  src/crypto/refcount_c11.c\
  src/crypto/refcount_lock.c\
  src/crypto/rsa_extra/rsa_asn1.c\
  src/crypto/rsa_extra/rsa_print.c\
  src/crypto/siphash/siphash.c\
  src/crypto/stack/stack.c\
  src/crypto/thread.c\
  src/crypto/thread_none.c\
  src/crypto/thread_pthread.c\
  src/crypto/thread_win.c\
  src/crypto/x509/a_digest.c\
  src/crypto/x509/a_sign.c\
  src/crypto/x509/a_strex.c\
  src/crypto/x509/a_verify.c\
  src/crypto/x509/algorithm.c\
  src/crypto/x509/asn1_gen.c\
  src/crypto/x509/by_dir.c\
  src/crypto/x509/by_file.c\
  src/crypto/x509/i2d_pr.c\
  src/crypto/x509/rsa_pss.c\
  src/crypto/x509/t_crl.c\
  src/crypto/x509/t_req.c\
  src/crypto/x509/t_x509.c\
  src/crypto/x509/t_x509a.c\
  src/crypto/x509/x509.c\
  src/crypto/x509/x509_att.c\
  src/crypto/x509/x509_cmp.c\
  src/crypto/x509/x509_d2.c\
  src/crypto/x509/x509_def.c\
  src/crypto/x509/x509_ext.c\
  src/crypto/x509/x509_lu.c\
  src/crypto/x509/x509_obj.c\
  src/crypto/x509/x509_r2x.c\
  src/crypto/x509/x509_req.c\
  src/crypto/x509/x509_set.c\
  src/crypto/x509/x509_trs.c\
  src/crypto/x509/x509_txt.c\
  src/crypto/x509/x509_v3.c\
  src/crypto/x509/x509_vfy.c\
  src/crypto/x509/x509_vpm.c\
  src/crypto/x509/x509cset.c\
  src/crypto/x509/x509name.c\
  src/crypto/x509/x509rset.c\
  src/crypto/x509/x509spki.c\
  src/crypto/x509/x_algor.c\
  src/crypto/x509/x_all.c\
  src/crypto/x509/x_attrib.c\
  src/crypto/x509/x_crl.c\
  src/crypto/x509/x_exten.c\
  src/crypto/x509/x_info.c\
  src/crypto/x509/x_name.c\
  src/crypto/x509/x_pkey.c\
  src/crypto/x509/x_pubkey.c\
  src/crypto/x509/x_req.c\
  src/crypto/x509/x_sig.c\
  src/crypto/x509/x_spki.c\
  src/crypto/x509/x_val.c\
  src/crypto/x509/x_x509.c\
  src/crypto/x509/x_x509a.c\
  src/crypto/x509v3/pcy_cache.c\
  src/crypto/x509v3/pcy_data.c\
  src/crypto/x509v3/pcy_lib.c\
  src/crypto/x509v3/pcy_map.c\
  src/crypto/x509v3/pcy_node.c\
  src/crypto/x509v3/pcy_tree.c\
  src/crypto/x509v3/v3_akey.c\
  src/crypto/x509v3/v3_akeya.c\
  src/crypto/x509v3/v3_alt.c\
  src/crypto/x509v3/v3_bcons.c\
  src/crypto/x509v3/v3_bitst.c\
  src/crypto/x509v3/v3_conf.c\
  src/crypto/x509v3/v3_cpols.c\
  src/crypto/x509v3/v3_crld.c\
  src/crypto/x509v3/v3_enum.c\
  src/crypto/x509v3/v3_extku.c\
  src/crypto/x509v3/v3_genn.c\
  src/crypto/x509v3/v3_ia5.c\
  src/crypto/x509v3/v3_info.c\
  src/crypto/x509v3/v3_int.c\
  src/crypto/x509v3/v3_lib.c\
  src/crypto/x509v3/v3_ncons.c\
  src/crypto/x509v3/v3_ocsp.c\
  src/crypto/x509v3/v3_pci.c\
  src/crypto/x509v3/v3_pcia.c\
  src/crypto/x509v3/v3_pcons.c\
  src/crypto/x509v3/v3_pku.c\
  src/crypto/x509v3/v3_pmaps.c\
  src/crypto/x509v3/v3_prn.c\
  src/crypto/x509v3/v3_purp.c\
  src/crypto/x509v3/v3_skey.c\
  src/crypto/x509v3/v3_sxnet.c\
  src/crypto/x509v3/v3_utl.c\
  src/third_party/fiat/curve25519.c\
  ${sources}
ar rcs libcrypto.a *.o

#clang -std=c++17 -I../include -c config_utils.cpp canned_fs_config.cpp iosched_policy.cpp load_file.cpp native_handle.cpp record_stream.cpp threads.cpp ashmem-host.cpp fs_config.cpp trace-host.cpp fs.cpp hashmap.cpp multiuser.cpp str_parms.cpp arch-arm64/android_memset.S qtaguid.cpp
#clang -I../include -c strlcpy.c

cd ../libselinux
clang -I../include -I../pcre/include -c -DNO_PERSISTENTLY_STORED_PATTERNS -DDISABLE_SETRANS -DDISABLE_BOOL -D_GNU_SOURCE -DNO_MEDIA_BACKEND -DNO_X_BACKEND -DNO_DB_BACKEND -DUSE_PCRE2 -DBUILD_HOST -c src/label_file.c src/regex.c src/android/android_host.c src/avc.c src/avc_internal.c src/avc_sidtab.c src/compute_av.c src/compute_create.c src/compute_member.c src/context.c src/deny_unknown.c src/enabled.c src/fgetfilecon.c src/getenforce.c src/getfilecon.c src/get_initial_context.c src/init.c src/lgetfilecon.c src/load_policy.c src/lsetfilecon.c src/mapping.c src/procattr.c src/reject_unknown.c src/setenforce.c src/setexecfilecon.c src/setfilecon.c src/stringrep.c src/booleans.c src/callbacks.c src/freecon.c src/label_backends_android.c src/label.c src/label_support.c src/matchpathcon.c src/setrans_client.c src/sha1.c
ar rcs libselinux.a *.o

cd ../pcre
clang -Iinclude -Iinclude_internal -DHAVE_CONFIG_H -c dist2/src/pcre2_auto_possess.c dist2/src/pcre2_compile.c dist2/src/pcre2_config.c dist2/src/pcre2_context.c dist2/src/pcre2_convert.c dist2/src/pcre2_dfa_match.c dist2/src/pcre2_error.c dist2/src/pcre2_extuni.c dist2/src/pcre2_find_bracket.c dist2/src/pcre2_maketables.c dist2/src/pcre2_match.c dist2/src/pcre2_match_data.c dist2/src/pcre2_jit_compile.c dist2/src/pcre2_newline.c dist2/src/pcre2_ord2utf.c dist2/src/pcre2_pattern_info.c dist2/src/pcre2_script_run.c dist2/src/pcre2_serialize.c dist2/src/pcre2_string_utils.c dist2/src/pcre2_study.c dist2/src/pcre2_substitute.c dist2/src/pcre2_substring.c dist2/src/pcre2_tables.c dist2/src/pcre2_ucd.c dist2/src/pcre2_valid_utf.c dist2/src/pcre2_xclass.c dist2/src/pcre2_chartables.c
ar rcs libpcre2.a *.o

cd ../e2fsprogs/lib/et
clang -fPIC -I.. -c error_message.c et_name.c init_et.c com_err.c com_right.c
ar rcs libext2_com_err.a *.o

cd ../support
clang -fPIC -I.. -c dict.c mkquota.c parse_qtype.c plausible.c profile.c profile_helpers.c prof_err.c quotaio.c quotaio_tree.c quotaio_v2.c
ar rcs libext2_quota.a *.o

cd ../ext2fs
clang -fPIC -I.. -I/2/include -c ext2_err.c alloc.c alloc_sb.c alloc_stats.c alloc_tables.c atexit.c badblocks.c bb_inode.c bitmaps.c bitops.c blkmap64_ba.c blkmap64_rb.c blknum.c block.c bmap.c check_desc.c crc16.c crc32c.c csum.c closefs.c dblist.c dblist_dir.c digest_encode.c dirblock.c dirhash.c dir_iterate.c dupfs.c expanddir.c ext_attr.c extent.c fallocate.c fileio.c finddev.c flushb.c freefs.c gen_bitmap.c gen_bitmap64.c get_num_dirs.c get_pathname.c getsize.c getsectsize.c hashmap.c i_block.c icount.c imager.c ind_block.c initialize.c inline.c inline_data.c inode.c io_manager.c ismounted.c link.c llseek.c lookup.c mmp.c mkdir.c mkjournal.c namei.c native.c newdir.c nls_utf8.c openfs.c progress.c punch.c qcow2.c rbtree.c read_bb.c read_bb_file.c res_gdt.c rw_bitmaps.c sha256.c sha512.c swapfs.c symlink.c undo_io.c unix_io.c sparse_io.c unlink.c valid_blk.c version.c
ar rcs libext2fs.a *.o

cd ../blkid
clang -fPIC -I.. -c cache.c dev.c devname.c devno.c getsize.c llseek.c probe.c read.c resolve.c save.c tag.c version.c
ar rcs libext2_blkid.a *.o

cd ../uuid
clang -fPIC -I. -I.. -c clear.c compare.c copy.c gen_uuid.c isnull.c pack.c parse.c unpack.c unparse.c uuid_time.c
ar rcs libext2_uuid.a *.o

cd ../e2p
clang -I. -I.. -c encoding.c feature.c fgetflags.c fsetflags.c fgetproject.c fsetproject.c fgetversion.c fsetversion.c getflags.c getversion.c hashstr.c iod.c ljs.c ls.c mntopts.c parse_num.c pe.c pf.c ps.c setflags.c setversion.c uuid.c ostype.c percent.c
ar rcs libext2_e2p.a *.o

cd ../../misc
clang -fPIC -I. -I../lib -c create_inode.c
ar rcs libext2_misc.a *.o

clang -static -I../lib -o mke2fs mke2fs.c util.c mk_hugefiles.c default_profile.c libext2_misc.a ../lib/support/libext2_quota.a ../lib/ext2fs/libext2fs.a ../lib/blkid/libext2_blkid.a ../lib/uuid/libext2_uuid.a ../lib/et/libext2_com_err.a ../lib/e2p/libext2_e2p.a ../../libsparse/libsparse.a ../../base/libbase.a ../../liblog/liblog.a ../../zlib/libz.a -lpthread -lstdc++

cd ../contrib/android
clang -static -I../../lib -I../../lib/ext2fs -I../../misc -I../../../include -o e2fsdroid e2fsdroid.c block_range.c fsmap.c block_list.c base_fs.c perms.c basefs_allocator.c ../../misc/libext2_misc.a ../../lib/support/libext2_quota.a ../../lib/ext2fs/libext2fs.a ../../lib/blkid/libext2_blkid.a ../../lib/uuid/libext2_uuid.a ../../lib/et/libext2_com_err.a ../../../libsparse/libsparse.a ../../../zlib/libz.a ../../../libcutils/libcutils.a ../../../base/libbase.a ../../../libselinux/libselinux.a ../../../pcre/libpcre2.a ../../../crypto/libcrypto.a ../../../liblog/liblog.a -lpthread -lc -lstdc++
