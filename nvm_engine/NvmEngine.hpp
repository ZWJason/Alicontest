//
//  NvmEngine.hpp
//  tair_contest
//
//  Created by 翟文杰 on 2020/10/10.
//
#pragma once

#define LOCAL_VERSION
//#define PRINT_LOG
#define LINUX_PLATFORM
//#define PMEM_VERSION

//#define CACHE_ALIGN_VERSION
#include<sys/mman.h>　
#include<sys/types.h>　
#include<string.h>
#include<stdio.h>　
#include<unistd.h>
#include<fcntl.h>

#include <iostream>
#include <map>
#include <vector>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <algorithm>
#include <list>
#include <array>
#include <condition_variable>
#include <thread>
#include <future>
#include <queue>



#define ALIGN(LEN,TYPE) ((LEN+TYPE-1)&(~(TYPE-1)))    // TYPE = n^2

#ifdef LOCAL_VERSION
#include "../include/db.hpp"
constexpr uint64_t PMEM_MAX_SIZE = uint64_t(16* 1024) * 1024 * 1024;
#else
#include "../include/db.hpp"

constexpr uint64_t PMEM_MAX_SIZE = uint64_t(64) * 1024 * 1024 * 1024;
#endif // LOCAL_VERSION

#ifdef LINUX_PLATFORM
#include <pthread.h>
#include <sys/mman.h>
#endif // LINUX_PLATFORM

inline uint32_t key_hash_engine(const char* data);
inline uint64_t bucketID_hash_engine(const char* data);
inline uint32_t fletcher32(const uint16_t* data, size_t len);

namespace Tuple {

    constexpr uint64_t TUPLE_KEY_SIZE = 16;
    constexpr uint64_t TUPLE_VAL_MAX_SIZE = 1024;
    constexpr uint64_t TUPLE_VAL_MIN_SIZE = 80;
    struct TupleInfo {
        uint32_t check_num = 0;
        uint16_t max_val_len = 0;
        uint16_t real_val_len = 0;
    };
    struct TupleData {
        TupleData() = default;
        TupleData(const Slice& key, const Slice& value) {
            memcpy(this->key_, key.data(), TUPLE_KEY_SIZE);
            memcpy(this->value_, value.data(), value.size());
        }
        TupleData(const char* key, const char* value, size_t val_len) {
            memcpy(this->key_, key, TUPLE_KEY_SIZE);
            memcpy(this->value_, value, val_len);
        }
        char key_[TUPLE_KEY_SIZE];
        char value_[TUPLE_VAL_MAX_SIZE];
    };

    class Tuple {
    public:
        Tuple() = default;

        Tuple(const Slice& key, const Slice& value) :data_(key, value)
        {
            this->info_.real_val_len = value.size();

#ifdef CACHE_ALIGN_VERSION
            // .tuple_len() >= 256
            size_t len = TUPLE_KEY_SIZE+sizeof(TupleInfo)+ALIGN(this->info_.real_val_len,2);
            if(len>=256){
                this->info_.max_val_len = ALIGN(this->info_.real_val_len,2);
            }
            else{
                this->info_.max_val_len = 256-len + ALIGN(this->info_.real_val_len,2);
            }
#else
            this->info_.max_val_len = ALIGN(this->info_.real_val_len, 2);
#endif
            this->info_.check_num = fletcher32((uint16_t*)&(this->data_), ALIGN(this->info_.real_val_len,2) + TUPLE_KEY_SIZE);
        }

        Tuple(const char* key, const char* value, size_t val_len) :data_(key, value, val_len) {
            this->info_.real_val_len = val_len;
#ifdef CACHE_ALIGN_VERSION
            // .tuple_len() >= 256
            size_t len = TUPLE_KEY_SIZE+sizeof(TupleInfo)+ALIGN(this->info_.real_val_len,2);
            if(len>=256){
                this->info_.max_val_len = ALIGN(this->info_.real_val_len,2);
            }
            else{
                this->info_.max_val_len = 256-len + ALIGN(this->info_.real_val_len,2);
            }
#else
            this->info_.max_val_len = ALIGN(this->info_.real_val_len, 2);
#endif
            this->info_.check_num = fletcher32((uint16_t*)&(this->data_), ALIGN(this->info_.real_val_len,2) + TUPLE_KEY_SIZE);
        }

        size_t size() const noexcept {
            return sizeof(TupleInfo) + TUPLE_KEY_SIZE + this->info_.max_val_len;    //
        }

        void write_back(char* pmem_tuple_address) {
#ifdef PMEM_VERSION
            pmem_memcpy_persist(pmem_tuple_address, this, this->size());
#else
            memcpy(pmem_tuple_address, this, this->size());
#endif // LOCAL_VERSION
        }

        void value_to_string(std::string* value) {
            value->assign(this->data_.value_, this->info_.real_val_len);
        }

        int is_valid() {
            if (this->info_.max_val_len > 0) {
                return this->info_.real_val_len > 0 ? 1 : 0;
            }
            return -1;
        }

        void set_invalid() {
            this->info_.real_val_len = 0;
        }

        int data_check() {
            uint32_t checknum = fletcher32((uint16_t*)&(this->data_), ALIGN(this->info_.real_val_len,2) + TUPLE_KEY_SIZE);
            return checknum == this->info_.check_num ? 0 : -1;
        }

        char* key() {
            return this->data_.key_;
        }

        char* value() {
            return this->data_.value_;
        }

        char* data() {
            return (char*)&(this->data_);
        }

        bool is_equal(const char* key)
        {
            uint64_t* left = (uint64_t*)this->data_.key_;
            uint64_t* right = (uint64_t*)key;
            return left[0] == right[0] && left[1] == right[1];
        }

        size_t value_len() {
            return this->info_.real_val_len;
        }

        size_t data_len() {
            return TUPLE_KEY_SIZE + this->info_.max_val_len;
        }

        size_t tuple_len() {
            return sizeof(TupleInfo) + TUPLE_KEY_SIZE + this->info_.max_val_len;
        }

    protected:
        uint32_t fletcher32(const uint16_t* data, size_t len) {
            uint32_t c0, c1;
            //len = (len + 1) & ~1;      /* Round up len to words */

            /* We similarly solve for n > 0 and n * (n+1) / 2 * (2^16-1) < (2^32-1) here. */
            /* On modern computers, using a 64-bit c0/c1 could allow a group size of 23726746. */
            for (c0 = c1 = 0; len > 0; ) {
                size_t blocklen = len;
                if (blocklen > 360 * 2) {
                    blocklen = 360 * 2;
                }
                len -= blocklen;
                do {
                    c0 = c0 + *data++;
                    c1 = c1 + c0;
                } while ((blocklen -= 2));
                c0 = c0 % 65535;
                c1 = c1 % 65535;
            }
            return (c1 << 16 | c0);
        }

    private:
        TupleInfo info_;
        TupleData data_;
    };
}

namespace HashIndex {
    struct Node {
        void set_val(uint64_t pmem_offset);
        uint64_t get_val();
        int is_equal(const char* tuple_key, uint32_t node_key, char* pmem_address_base);
        int is_equal(Node& right);
        
        
        char val[8] = { 0,0,0,0,0,0,0,0 };
        uint32_t nkey = UINT32_MAX;    // node_key,若此值相等，则检测val对应的Tuple.key值是否相似
        // [node_key,tuple.key] 构成唯一键
    };
    constexpr uint64_t HASH_INIT_SIZE = 299999;
    class Hash {
    public:
        void init(char* pmem_base_address);
        char* insert(const char* tuple_key, const char* tuple_pmem_address, uint32_t node_key);
        Node* find(const char* tuple_key, uint32_t node_key);
    protected:
        uint32_t hash_node_key(uint32_t node_key, uint32_t mask);
        char* insert(const char* tuple_key, const char* tuple_pmem_address, uint32_t node_key, uint32_t mask);
        void expand_insert(Node& node, uint32_t mask, Node* nodes);
        void expand();
    private:
        Node* nodes_ = nullptr;
        size_t cur_size_ = 0;
        size_t max_size_ = 0;
        const double expand_factor_ = 1.3;
        const double expand_flag_ = 0.95;
        size_t expand_limit_size_ = 0;    // 当cur_size大于该值时调用expand()
        char* pmem_base_address_ = nullptr;
    };

}

namespace Manager {
    struct PageInfo {
        // [1,n]
        uint32_t bucket_id = 0;
        uint32_t page_id = 0;
    };
    constexpr uint64_t PMEM_PAGE_SIZE = uint64_t(4) * 1024 * 1024;
    constexpr uint64_t PMEM_PAGE_DATA_SIZE = PMEM_PAGE_SIZE - sizeof(PageInfo);
    struct Page {
        void clear();
        PageInfo info;
        char data[PMEM_PAGE_DATA_SIZE];
    };
    struct PageHeader    // dram
    {
        void clear();
        Tuple::Tuple* alloc_tuple(uint16_t tuple_len);

        Page* page = nullptr;
        PageInfo pinfo;
        size_t cur_data_offset = 0;
        size_t block_nums = 0;    // 记录当前page空tuple数量
        size_t level = 0;
        size_t gpid = 0;    // [0,N-1] , global page id,existed and not edited it again in total life (Manager V2)
        std::vector<uint32_t> del_pos;
    };

    struct Page2PHeader {
        PageHeader pheader;
    };

    constexpr uint64_t PMEM_PAGE_NUM = PMEM_MAX_SIZE / PMEM_PAGE_SIZE;
    static Page2PHeader* global_page_header_register = nullptr;
    constexpr uint64_t GLOBA_PAGE_WARNING = 32;

    constexpr uint64_t LEVEL_SIZE = 8;
    constexpr uint64_t BUCKET_LEVEL_RANGE = 1024/LEVEL_SIZE;
    constexpr uint64_t PAGE_LEVEL_RANGE = PMEM_MAX_SIZE/PMEM_PAGE_SIZE/LEVEL_SIZE;
    //
    class ManagerV2{
    public:
        Page* alloc_free_page(size_t bid);
        void recycle_free_page(Page* page,size_t gpid);

        Page* alloc_mem_buf_page();
        void recycle_mem_page(Page* page);

        size_t size() const noexcept;

        std::atomic<uint64_t> size_{0};
        std::mutex muts_[LEVEL_SIZE];
        std::array<std::vector<Page*>,LEVEL_SIZE> pages_;

        std::vector<Page*> mem_buf_pages_;
        std::mutex mem_buf_mut_;
    };

}

namespace GargabeCollector {

    using Level = std::unordered_map<Manager::Page*, Manager::PageHeader*>;

    constexpr uint64_t PAGE_MAX_LEVEL = 16;
    constexpr uint64_t PER_LEVEL_PAGE_SIZE = Manager::PMEM_PAGE_SIZE / PAGE_MAX_LEVEL;//4kb/16
    class GargabeCollector {
    public:
        void init();
        void page_register(Manager::PageHeader* pheader);
        void page_register(Manager::PageHeader* pheader, size_t level);
        void page_advance(Manager::PageHeader* pheader, size_t old_level);
        size_t size();
        Manager::PageHeader* get_page();
        Level* levels_ = nullptr;
        std::mutex* mut_ = nullptr;
    };
}


namespace Bucket {

    static std::atomic<uint64_t> tuple_block_counter{ 0 };
    static std::atomic<uint64_t> page_merge_counter{ 0 };

    constexpr uint64_t BUCKET_MAX_SIZE = (1 << 10);
    constexpr uint64_t BUCKET_MASK = BUCKET_MAX_SIZE - 1;
    class Bucket {
    public:
        void init(char* pmem_base_address, Manager::ManagerV2* manager, GargabeCollector::GargabeCollector* gc, uint32_t id);
        Status push(const char* key, const char* value, uint16_t val_len, uint32_t hash_node_key);
        Status find(const char* key, std::string* value, uint32_t hash_node_key);
        void recovery(Manager::Page* page);
        bool defragmentation(Manager::PageHeader* pheader);
    protected:
        void push_tuple_block(char* tuple_address, uint16_t tuple_len);
        Tuple::Tuple *pmem_tuple_alloc(const size_t &alloc_len);
        char *pmem_alloc(const size_t &alloc_len);
    private:
        Manager::Page* wanted_page_ = nullptr;
        HashIndex::Hash hash;
        char* pmem_base_address_ = nullptr;
        
        std::vector<Manager::PageHeader*> pages_;
        
        Manager::PageHeader* cur_page = nullptr;
        uint32_t ID = 0;

        Manager::ManagerV2 *manager_ = nullptr;

        uint32_t cur_page_id = 1;

        GargabeCollector::GargabeCollector* gc_ = nullptr;

        std::atomic<size_t> insert_counter{0};  // 记录已申请pmem内存但未写入索引的数据量
        std::mutex pmem_tuple_alloc_mut_;   //顶层锁

#ifdef LINUX_PLATFORM
        pthread_rwlock_t hash_rwlock_;
#else
        std::mutex hash_mut_;
#endif
    };

}

class NvmEngine :DB {
public:
    static Status CreateOrOpen(const std::string& name, DB** dbptr, FILE* log_file = nullptr);

    NvmEngine(const std::string& name, FILE* log_file);
    Status Get(const Slice& key, std::string* value) override;
    Status Set(const Slice& key, const Slice& value) override;

    ~NvmEngine() override;

private:
    char* mem_ptr_ = nullptr;
    size_t mapped_len_ = 0;
    int is_pmem_ = 0;

    Bucket::Bucket* buckets_ = nullptr;
    FILE* log_file_ = nullptr;

    Manager::ManagerV2* manager_ = nullptr;

    GargabeCollector::GargabeCollector* gc_ = nullptr;

#ifdef PRINT_LOG
    uint64_t race_counter = 0;
    time_t time_counter;
    uint64_t insert_data_counter_ = 0;
    uint64_t write_len = 0;
#endif // PRINT_LOG
};
