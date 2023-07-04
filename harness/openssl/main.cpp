#include <cstdlib>
#include <fstream>
#include <iostream>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include "json.hpp"

#define LIMBO_JSON "../../limbo.json"

using json = nlohmann::json;

static void SK_X509_free(stack_st_X509 *ptr)
{
    sk_X509_free(ptr);
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

    auto *subject = X509_get_subject_name(cert);
    auto *subject_str = X509_NAME_oneline(subject, nullptr, 0);
    std::cerr << "SUBJECT: " << subject_str << std::endl;

    auto *issuer = X509_get_issuer_name(cert);
    auto *issuer_str = X509_NAME_oneline(issuer, nullptr, 0);
    std::cerr << "ISSUER: " << issuer_str << std::endl;

    return X509_ptr(cert, X509_free);
}

STACK_OF_X509_ptr x509_stack(json &certs)
{
    if (!certs.is_array())
    {
        barf("unexpected type: expected an array of certs");
    }

    STACK_OF_X509_ptr stack(sk_X509_new_reserve(nullptr, certs.size()), SK_X509_free);
    for (auto &cert : certs)
    {
        auto cert_pem = cert.template get<std::string>();
        auto cert_x509 = pem_to_x509(cert_pem);
        sk_X509_push(stack.get(), cert_x509.get());
    }

    return stack;
}

void evaluate_testcase(json &testcase)
{
    auto id = testcase["id"].template get<std::string>();
    std::cerr << "Evaluating case: " << id << std::endl;

    auto peer_pem = testcase["peer_certificate"].template get<std::string>();
    auto peer = pem_to_x509(peer_pem);

    X509_STORE_ptr store(X509_STORE_new(), X509_STORE_free);
    X509_STORE_set_flags(store.get(), X509_V_FLAG_X509_STRICT);
    // for (auto &cert : testcase["trusted_certs"])
    // {
    //     auto cert_pem = cert.template get<std::string>();
    //     auto cert_x509 = pem_to_x509(cert_pem);
    //     X509_STORE_add_cert(store.get(), cert_x509.get());
    // }
    // X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);

    X509_STORE_CTX_ptr ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);

    auto untrusted = x509_stack(testcase["untrusted_intermediates"]);
    std::cerr << "# untrusted: " << sk_X509_num(untrusted.get()) << std::endl;
    X509_STORE_CTX_init(ctx.get(), store.get(), peer.get(), untrusted.get());

    X509_STORE_CTX_set_time(ctx.get(), 0, 0);

    auto trusted = x509_stack(testcase["trusted_certs"]);
    std::cerr << "# trusted: " << sk_X509_num(trusted.get()) << std::endl;
    X509_STORE_CTX_set0_trusted_stack(ctx.get(), trusted.get());

    auto status = X509_verify_cert(ctx.get());
    if (status)
    {
        std::cerr << "\tPASS" << std::endl;
    }
    else
    {
        std::cerr << "\tFAIL: " << status << std::endl;
        std::cerr << "\t" << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get())) << std::endl;
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
