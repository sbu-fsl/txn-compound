/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @author Ming Chen <v.mingchen@gmail.com>
 */

#include "secnfs_lib.h"
#include <iostream>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/filters.h>
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StringStore;


#include <cryptopp/rsa.h>
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include <google/protobuf/io/coded_stream.h>
using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;

#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::ArrayOutputStream;

namespace secnfs {

RSAKeyPair::RSAKeyPair(bool create) {
        if (create) {
                AutoSeededRandomPool rnd;
                pri_.GenerateRandomWithKeySize(rnd, RSAKeyLength);
                pub_.Initialize(pri_.GetModulus(), pri_.GetPublicExponent());
        }
}

RSAKeyPair::RSAKeyPair(const std::string &pub, const std::string &pri) {
        DecodeKey(&pub_, pub);
        DecodeKey(&pri_, pri);
}


bool RSAKeyPair::operator==(const RSAKeyPair &other) const {
        return IsSamePrivateKey(pri_, other.pri_) &&
                IsSamePublicKey(pub_, other.pub_);
}


bool RSAKeyPair::operator!=(const RSAKeyPair &other) const {
        return !(*this == other);
}


bool RSAKeyPair::Verify() const {
        // TODO implement this
        return true;
}


void EncodeKey(const RSAFunction& key, std::string *result) {
        key.DEREncode(StringSink(*result).Ref());
}


void DecodeKey(RSAFunction *key, const std::string &code) {
        key->BERDecode(StringStore(code).Ref());
}


void RSAEncrypt(const RSA::PublicKey &pub_key, const std::string &plain,
                std::string *cipher) {
        AutoSeededRandomPool prng;
        RSAES_OAEP_SHA_Encryptor e(pub_key);
        StringSource ss(plain, true,
                new PK_EncryptorFilter(prng, e,
                        new StringSink(*cipher)));
}


void RSADecrypt(const RSA::PrivateKey &pri_key, const std::string &cipher,
                std::string *recovered) {
        AutoSeededRandomPool prng;
        RSAES_OAEP_SHA_Decryptor d(pri_key);
        StringSource ss(cipher, true,
                new PK_DecryptorFilter(prng, d,
                        new StringSink(*recovered)));
}


bool EncodeMessage(const google::protobuf::Message &msg, void **buf,
                   uint32_t *buf_size, uint32_t align) {
        uint32_t msg_size = msg.ByteSize();

        *buf_size = ((msg_size + sizeof(msg_size) + align - 1) / align) * align;
        *buf = malloc(*buf_size);

        assert(*buf);

        ArrayOutputStream aos(*buf, *buf_size);
        CodedOutputStream cos(&aos);
        cos.WriteLittleEndian32(msg_size);

        return msg.SerializeToCodedStream(&cos);
}


bool DecodeMessage(google::protobuf::Message *msg, void *buf,
                   uint32_t buf_size, uint32_t *msg_size) {
        ArrayInputStream ais(buf, buf_size);
        CodedInputStream cis(&ais);

        if (!cis.ReadLittleEndian32(msg_size)) {
                return false;
        }

        if (buf_size < *msg_size + 4) {
                return false;
        }

        cis.PushLimit(*msg_size);
        return msg->ParseFromCodedStream(&cis);
}

BlockMap::BlockMap() {
        // initialize mutex, same as FSAL/fsal_commonlib.c
        pthread_mutexattr_t attrs;
        pthread_mutexattr_init(&attrs);
#if defined(__linux__)
        pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_ADAPTIVE_NP);
#endif
        pthread_mutex_init(&mutex_, &attrs);
}


BlockMap::~BlockMap() {
        pthread_mutex_destroy(&mutex_);
}


static bool cmp_offset(const Range &a, const uint64_t &b) {
        return a.offset() < b;
}


/* try to insert a segment
 * if overlapping with existing segments, only insert leading
 * non-overlapping part.
 * return inserted length. 0 indicates no space to insert.
 */
uint64_t BlockMap::try_insert(uint64_t offset, uint64_t length) {
        assert(length > 0);
        deque<Range>::iterator pos, prev;
        Range seg;

        seg.set_offset(offset);
        seg.set_length(length);

        MutexLock lock(mutex_);
        if (segs_.empty()) {
                segs_.push_back(seg);
                return length;
        }

        pos = std::lower_bound(segs_.begin(), segs_.end(), offset, cmp_offset);

        if (pos > segs_.begin()) {
                prev = pos - 1;
                if (prev->offset() + prev->length() > offset)
                        return 0;
        }

        if (pos != segs_.end()) {
                /* pos points to next segment of our seg if inserted */
                if (pos->offset() == offset)
                        return 0;
                if (offset + length > pos->offset()) {
                        length = pos->offset() - offset;
                        seg.set_length(length);
                }
        }

        pos = segs_.insert(pos, seg);
        assert(valid(pos));

        return length;
}


// reverse operation of try_insert (assume inserted previously)
void BlockMap::remove_match(uint64_t offset, uint64_t length) {
        deque<Range>::iterator pos;

        MutexLock lock(mutex_);
        pos = std::lower_bound(segs_.begin(), segs_.end(), offset, cmp_offset);

        assert(pos != segs_.end());
        assert(pos->length() == length);

        segs_.erase(pos);
}


// push back without search (assume no overlap)
void BlockMap::push_back(uint64_t offset, uint64_t length) {
        Range seg;

        seg.set_offset(offset);
        seg.set_length(length);

        MutexLock lock(mutex_);
        segs_.push_back(seg);
        assert(valid(--segs_.end()));
}


// remove segments that overlap with [offset, offset + length)
// may cut existing segment if partially overlapping
// return number of affected holes
size_t BlockMap::remove_overlap(uint64_t offset, uint64_t length)
{
        deque<Range>::iterator pos;
        size_t affected = 0;

        if (!length)
                return affected;

        MutexLock lock(mutex_);
        if (segs_.empty())
                return affected;
        pos = std::lower_bound(segs_.begin(), segs_.end(), offset, cmp_offset);

        // should check previous segment whose offset is smaller
        // but length may be large
        if (pos != segs_.begin())
                pos--;

        uint64_t right = offset + length;
        uint64_t pos_right;
        while (pos != segs_.end() && pos->offset() < right) {
                pos_right = pos->offset() + pos->length();
                // segment above is located at pos
                //   -------     -->
                // -----------        ----------
                if (pos->offset() >= offset && pos_right <= right) {
                        pos = segs_.erase(pos);
                        affected++;
                        continue;
                }
                // --------      -->   ---
                //   ---------            ---------
                if (pos->offset() < offset && pos_right > offset &&
                                pos_right <= right) {
                        pos->set_length(offset - pos->offset());
                        pos++;
                        affected++;
                        continue;
                }
                // -----------    --> ---     ---
                //    -----
                if (pos->offset() < offset && pos_right > right) {
                        pos->set_length(offset - pos->offset());
                        Range new_seg;
                        new_seg.set_offset(right);
                        new_seg.set_length(pos_right - right);
                        segs_.insert(++pos, new_seg);
                        affected++;
                        break;
                }
                //     --------  -->            ---
                // ---------           ---------
                if (pos_right > right) {
                        pos->set_offset(right);
                        pos->set_length(pos_right - right);
                        affected++;
                        break;
                }
                pos++;
        }

        return affected;
}


// find segment that contains the offset or after the offset
void BlockMap::find_next(uint64_t offset,
                         uint64_t *nxt_offset, uint64_t *nxt_length)
{
        deque<Range>::iterator it, prev;

        *nxt_offset = 0;
        *nxt_length = 0;

        MutexLock lock(mutex_);
        if (segs_.empty())
                return;

        it = std::lower_bound(segs_.begin(), segs_.end(), offset, cmp_offset);
        if (it != segs_.begin()) {
                prev = it - 1;
                if (offset < prev->offset() + prev->length()) {
                        *nxt_offset = prev->offset();
                        *nxt_length = prev->length();
                        return;
                }
        }
        if (it != segs_.end()) {
                *nxt_offset = it->offset();
                *nxt_length = it->length();
        }
}


// return false if overlap
bool BlockMap::valid(deque<Range>::iterator pos) {
        deque<Range>::iterator prev, next;

        if (pos != segs_.begin()) {
                prev = pos - 1;
                if (prev->offset() + prev->length() > pos->offset())
                        return false;
        }
        if (pos != segs_.end() - 1) {
                next = pos + 1;
                if (pos->offset() + pos->length() > next->offset())
                        return false;
        }

        return true;
}


void BlockMap::print() {
        deque<Range>::iterator it;
        MutexLock lock(mutex_);

        std::cout << "Segments(" << segs_.size() << "):" << std::endl;
        for (it = segs_.begin(); it < segs_.end(); ++it)
                std::cout << it - segs_.begin()
                          << ": " << it->offset()
                          << " ("  << it->length() << ")"
                          << std::endl;

        std::cout << std::endl;
}


};
