#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include "date.hpp"
#include "json.hpp"

#define LIMBO_JSON "../../limbo.json"

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

[[noreturn]] void barf(const char *msg)
{
    std::cerr << "Internal error: " << msg << std::endl;
    std::exit(1);
}

X509_ptr pem_to_x509(std::string &pem)
{
    X509 *cert = nullptr;
    BIO_ptr cert_bio(BIO_new_mem_buf(pem.data(), pem.length()), BIO_free);

    if (!PEM_read_bio_X509(cert_bio.get(), &cert, 0, NULL))
    {
        barf("failed to parse cert");
    }

    return X509_ptr(cert, X509_free);
}

STACK_OF_X509_ptr x509_stack(json &certs)
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

void evaluate_testcase(json &testcase)
{
    auto id = testcase["id"].template get<std::string>();
    std::cerr << "Evaluating case: " << id << std::endl;

    X509_STORE_ptr store(X509_STORE_new(), X509_STORE_free);
    X509_STORE_set_flags(store.get(), X509_V_FLAG_X509_STRICT);
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
        date::sys_seconds tp;
        ss >> date::parse("%FT%T%Ez", tp);

        if (ss.fail())
        {
            barf("couldn't parse RFC 3339 time from testcase?");
        }

        auto tm = std::chrono::system_clock::to_time_t(tp);
        X509_STORE_CTX_set_time(ctx.get(), 0, tm);
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
}

int main()
{
    std::ifstream f(LIMBO_JSON);
    json data = json::parse(f);

    for (auto &testcase : data["testcases"])
    {
        evaluate_testcase(testcase);
    }

    return 0;
}
