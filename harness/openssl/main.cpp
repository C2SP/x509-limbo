#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/opensslv.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include "date.hpp"
#include "json.hpp"

#ifdef OPENSSL_VERSION_STR
#define HARNESS_OPENSSL_VERSION_STR OPENSSL_VERSION_STR
#elif defined(SHLIB_VERSION_NUMBER)
#define HARNESS_OPENSSL_VERSION_STR SHLIB_VERSION_NUMBER
#else
#error "unsupported OpenSSL version: " #OPENSSL_VERSION
#endif

using json = nlohmann::json;

static void SK_X509_free(stack_st_X509 *ptr)
{
  // NOTE: This also frees each member of the `STACK_OF(X509)`.
  sk_X509_pop_free(ptr, X509_free);
}

using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), decltype(&SK_X509_free)>;
using X509_STORE_ptr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509_STORE_CTX_ptr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

[[noreturn]] void barf(const std::string &msg)
{
  std::cerr << "Internal error: " << msg << std::endl;
  std::exit(1);
}

std::map<std::string, int> create_eku_map()
{
  std::map<std::string, int> m;
  m["anyExtendedKeyUsage"] = X509_PURPOSE_ANY;
  m["serverAuth"] = X509_PURPOSE_SSL_SERVER;
  m["clientAuth"] = X509_PURPOSE_SSL_CLIENT;
  return m;
}

X509_ptr pem_to_x509(const std::string &pem)
{
  X509 *cert = nullptr;
  BIO_ptr cert_bio(BIO_new_mem_buf(pem.data(), pem.length()), BIO_free);

  if (!PEM_read_bio_X509(cert_bio.get(), &cert, 0, NULL))
  {
    barf("failed to parse cert");
  }

  return X509_ptr(cert, X509_free);
}

STACK_OF_X509_ptr x509_stack(const json &certs)
{
  if (!certs.is_array())
  {
    barf("unexpected type: expected an array of certs");
  }

  auto *stack = sk_X509_new_reserve(nullptr, certs.size());
  for (auto &cert : certs)
  {
    auto cert_pem = cert.template get<std::string>();
    auto cert_x509 = pem_to_x509(cert_pem);
    // NOTE: Our `STACK_OF_X509_ptr` takes ownership here,
    // since on destruction it uses `sk_X509_pop_free` instead
    // of `sk_X509_free`.
    sk_X509_push(stack, cert_x509.release());
  }

  return STACK_OF_X509_ptr(stack, SK_X509_free);
}

json skip(const std::string &id, const std::string &reason)
{
  json result;

  std::cerr << "SKIP: id=" << id << " reason=" << reason << std::endl;

  result["id"] = id;
  result["actual_result"] = "SKIPPED";
  result["context"] = reason;

  return result;
}

json evaluate_testcase(const json &testcase)
{
  auto id = testcase["id"].template get<std::string>();
  std::cerr << "Evaluating case: " << id << std::endl;

  if (testcase["validation_kind"] != "SERVER")
  {
    return skip(id, "non-SERVER testcases not supported yet");
  }

  if (!testcase["signature_algorithms"].array().empty())
  {
    return skip(id, "signature_algorithms not supported yet");
  }

  if (!testcase["key_usage"].array().empty())
  {
    return skip(id, "key_usage not supported yet");
  }

  if (!testcase["expected_peer_names"].array().empty())
  {
    return skip(id, "expected_peer_names not supported yet");
  }

  X509_STORE_ptr store(X509_STORE_new(), X509_STORE_free);
  X509_STORE_set_flags(store.get(), X509_V_FLAG_X509_STRICT);
  // NOTE(ww): This flag is terribly named; it tells OpenSSL to
  // treat intermediate certificates in the root store as trust anchors,
  // which they already are (by virtue of being in the trust store).
  // This isn't the default for backwards compatibility reasons,
  // but it's consistent with how just about every other path building
  // implementation works.
  X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);
  for (auto &cert : testcase["trusted_certs"])
  {
    auto cert_pem = cert.template get<std::string>();
    auto cert_x509 = pem_to_x509(cert_pem);
    // TODO(ww): Ownership is murky here, but appears to work;
    // probably because X509_STORE_add_cert does its own up-ref.
    X509_STORE_add_cert(store.get(), cert_x509.get());
  }

  auto untrusted = x509_stack(testcase["untrusted_intermediates"]);
  auto peer_pem = testcase["peer_certificate"].template get<std::string>();
  auto peer = pem_to_x509(peer_pem);
  X509_STORE_CTX_ptr ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
  X509_STORE_CTX_init(ctx.get(), store.get(), peer.get(), untrusted.get());

  if (testcase["validation_time"].is_string())
  {
    std::istringstream ss(testcase["validation_time"].template get<std::string>());
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp;
    ss >> date::parse("%FT%T%Z", tp);

    if (ss.fail())
    {
      barf("couldn't parse RFC 3339 time from testcase?");
    }

    auto tm = std::chrono::system_clock::to_time_t(tp);
    X509_STORE_CTX_set_time(ctx.get(), 0, tm);
  }
  else
  {
    X509_STORE_set_flags(store.get(), X509_V_FLAG_NO_CHECK_TIME);
  }

  auto param = X509_STORE_CTX_get0_param(ctx.get());

  // The default authentication level is 1, which corresponds to 80 bits
  // of security. Level 2 corresponds to 112 bits and includes RSA 2048,
  // which brings the validation logic very slightly closer to the Web PKI.
  X509_VERIFY_PARAM_set_auth_level(param, 2);

  if (testcase["expected_peer_name"].is_object())
  {
    auto peer_name = testcase["expected_peer_name"]["value"].template get<std::string>();
    auto peer_kind = testcase["expected_peer_name"]["kind"].template get<std::string>();

    if (peer_kind == "RFC822")
    {
      X509_VERIFY_PARAM_set1_email(param, peer_name.data(), peer_name.length());
    }
    else if (peer_kind == "DNS")
    {
      X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
      X509_VERIFY_PARAM_set1_host(param, peer_name.data(), peer_name.length());
    }
    else if (peer_kind == "IP")
    {
      X509_VERIFY_PARAM_set1_ip_asc(param, peer_name.c_str());
    }
    else
    {
      barf("unexpected peer kind: " + peer_kind);
    }
  }

  if (testcase["extended_key_usage"].is_array())
  {
    if (testcase["extended_key_usage"].size() > 1)
    {
      return skip(id, "multiple extended key usage values not yet supported");
    }
    const auto eku_name_to_id = create_eku_map();
    for (auto &eku : testcase["extended_key_usage"])
    {
      const auto expected_eku_name = eku.template get<std::string>();
      if (eku_name_to_id.count(expected_eku_name) == 0)
      {
        return skip(id, "extended key usage value not yet supported: " + expected_eku_name);
      }
      const auto expected_eku_id = eku_name_to_id.at(expected_eku_name);
      X509_STORE_CTX_set_purpose(ctx.get(), expected_eku_id);
    }
  }

  auto max_chain_depth_obj = testcase["max_chain_depth"];
  if (!max_chain_depth_obj.is_null())
  {
    auto max_chain_depth = max_chain_depth_obj.template get<int64_t>();
    X509_VERIFY_PARAM_set_depth(param, max_chain_depth);
  }

  auto should_pass = testcase["expected_result"] == "SUCCESS";
  auto does_pass = X509_verify_cert(ctx.get());
  if (should_pass ^ does_pass)
  {
    std::cerr << "\tFAIL " << does_pass << "/" << should_pass << std::endl;
  }
  else
  {
    std::cerr << "\tPASS" << std::endl;
  }

  return {
      {"id", id},
      {"actual_result", does_pass ? "SUCCESS" : "FAILURE"},
      // NOTE: default-constructed json{} is null.
      {"context", does_pass ? json{} : X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get()))},
  };
}

int main()
{
  json limbo = json::parse(std::cin);

  json results;
  for (auto &testcase : limbo["testcases"])
  {
    results.emplace_back(evaluate_testcase(testcase));
  }

  json limbo_result = {
      {"version", 1},
      {"harness", std::string("openssl-") + HARNESS_OPENSSL_VERSION_STR},
      {"results", std::move(results)},
  };
  std::cout << std::setw(2) << limbo_result << std::endl;

  return 0;
}
