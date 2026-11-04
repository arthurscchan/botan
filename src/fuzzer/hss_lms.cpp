/*
* Fuzzer for HSS/LMS (RFC 8554) signature verification
*
* Attack surface: signature verification against an attacker supplied
* public key, signature and message. The input is split as
*
*    u16be key_len | u16be sig_len | key | signature | message
*
* Allocations are bounded by the input (the driver caps it at
* max_fuzzer_input_size) and by LMS parameter validation on the key.
*/

#include "fuzzers.h"

#include <botan/asn1_obj.h>
#include <botan/exceptn.h>
#include <botan/hss_lms.h>
#include <botan/pk_options.h>
#include <botan/pubkey.h>

void fuzz(std::span<const uint8_t> in) {
   static constexpr size_t header_len = 4;

   if(in.size() < header_len) {
      return;
   }

   const size_t key_len = (static_cast<size_t>(in[0]) << 8) | in[1];
   const size_t sig_len = (static_cast<size_t>(in[2]) << 8) | in[3];

   const size_t rest_len = in.size() - header_len;

   if(key_len == 0 || sig_len == 0 || key_len + sig_len > rest_len) {
      return;
   }

   const auto key_bytes = in.subspan(header_len, key_len);
   const auto sig_bytes = in.subspan(header_len + key_len, sig_len);
   const auto msg_bytes = in.subspan(header_len + key_len + sig_len);

   try {
      const Botan::HSS_LMS_PublicKey key(Botan::AlgorithmIdentifier(), key_bytes);

      Botan::PK_Verifier verifier(key, Botan::PK_Signature_Options());
      verifier.verify_message(msg_bytes, sig_bytes);
   } catch(const Botan::Exception&) {}
}
