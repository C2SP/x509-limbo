#include <iostream>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pki/verify.h>

#include <date/date.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

[[noreturn]] void barf(const std::string &msg)
{
    std::cerr << "Internal error: " << msg << std::endl;
    std::exit(1);
}

// TODO: This can almost certainly be done with sane libpki APIs instead.
std::string pem_to_der(const std::string &pem)
{
    BIO_ptr cert_bio(BIO_new_mem_buf(pem.data(), pem.length()), BIO_free);

    X509 *raw_cert = nullptr;
    if (!PEM_read_bio_X509(cert_bio.get(), &raw_cert, 0, NULL))
    {
        barf("failed to parse cert");
    }
    auto cert = X509_ptr(raw_cert, X509_free);

    int len;
    unsigned char *der = NULL;
    len = i2d_X509(cert.get(), &der);
    if (len < 0)
    {
        barf("failed to DER-encode cert");
    }

    auto der_str = std::string(reinterpret_cast<char *>(der), len);
    OPENSSL_free(der);

    return der_str;
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

json fail(const std::string &id, const std::string &reason)
{
    json result;

    std::cerr << "FAIL: id=" << id << " reason=" << reason << std::endl;

    result["id"] = id;
    result["actual_result"] = "FAILURE";
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

    // All verify options will get mashed into this object.
    auto verify_options = bssl::CertificateVerifyOptions{};

    std::string trusted_certs;
    for (auto &cert : testcase["trusted_certs"])
    {
        auto cert_pem = cert.template get<std::string>();
        auto cert_der = pem_to_der(cert_pem);
        trusted_certs.append(cert_der);
    }
    std::string diagnostic;

    auto trust_store = bssl::VerifyTrustStore::FromDER(trusted_certs, &diagnostic);
    if (trust_store == nullptr)
    {
        return fail(id, "invalid trust store: " + diagnostic);
    }

    verify_options.trust_store = trust_store.get();

    std::vector<std::string> intermediate_certs;
    for (auto &cert : testcase["untrusted_intermediates"])
    {
        auto cert_pem = cert.template get<std::string>();
        auto cert_der = pem_to_der(cert_pem);
        intermediate_certs.emplace_back(std::move(cert_der));
    }

    // TODO: Probably a less silly way to go from vec<str> to vec<str_view>.
    std::vector<std::string_view> intermediate_certs_view(intermediate_certs.begin(), intermediate_certs.end());
    auto intermediate_pool = bssl::CertPool::FromCerts(intermediate_certs_view, &diagnostic);
    if (intermediate_pool == nullptr)
    {
        return fail(id, "invalid intermediates: " + diagnostic);
    }

    verify_options.extra_intermediates = intermediate_pool.get();

    auto peer_pem = testcase["peer_certificate"].template get<std::string>();
    auto peer_der = pem_to_der(peer_pem);

    verify_options.leaf_cert = peer_der;

    if (testcase["validation_time"].is_string())
    {
        std::istringstream ss(testcase["validation_time"].template get<std::string>());
        std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp;
        ss >> date::parse("%FT%T%Z", tp);

        if (ss.fail())
        {
            barf("couldn't parse RFC 3339 time from testcase?");
        }

        // NOTE: `time_since_epoch` is not guaranteed to use the UNIX epoch until C++20,
        // but in practice the UNIX epoch is universal. This is probably slightly
        // more robust than doing `to_time_t` and hoping `time_t` is a sufficiently
        // wide integral type that's also UTC-aware.
        auto time = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
        verify_options.time = time;
    }
    else
    {
        // Use the current time.
        verify_options.time = std::nullopt;
    }

    if (testcase["max_chain_depth"].is_number_integer())
    {
        auto max_chain_depth = testcase["max_chain_depth"].template get<uint32_t>();
        verify_options.max_path_building_depth = max_chain_depth;
    }

    // CA/B says the minimum RSA modulus should be 2048.
    verify_options.min_rsa_modulus_length = 2048;

    // TODO: What max does Chrome use here? This one is picked arbitrarily as a conservative choice.
    verify_options.max_iteration_count = 1024 * 1024;

    // TODO: Difference between `SERVER_AUTH_STRICT_LEAF` and `SERVER_AUTH_STRICT`?
    verify_options.key_purpose = bssl::CertificateVerifyOptions::KeyPurpose::SERVER_AUTH_STRICT_LEAF;

    return skip(id, "temporary");
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
        {"harness", "boringssl-head"},
        {"results", std::move(results)},
    };
    std::cout << std::setw(2) << limbo_result << std::endl;

    return 0;
}
