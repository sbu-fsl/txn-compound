/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief Encrypt and decrypt data
 */

#include "secnfs.h"
#include <iostream>

#include <cryptopp/filters.h>
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CTR_Mode;

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

#include <assert.h>

namespace secnfs {

SecureProxy::SecureProxy(const std::string &name, RSA::PrivateKey &private_key)
        : name_(name), key_(private_key) { }

};
