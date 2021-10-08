#ifndef PASSPORT_UTIL_HPP
#define PASSPORT_UTIL_HPP

#include <string>
#include <vector>

#if __cplusplus >= 201603L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201603L)
#   define NODEMSPASSPORT_NODISCARD [[nodiscard]]
#   define PASSPORT_UNUSED [[maybe_unused]]
#else
#   define NODEMSPASSPORT_NODISCARD
#   define PASSPORT_UNUSED
#endif

#undef max

namespace nodeMsPassport {
    using byte = unsigned char;
    namespace util {
        /**
		 * zallocator struct
		 * Source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
		 * with additions from: https://stackoverflow.com/a/53207813
		 */
        template<typename T>
        struct zallocator {
        public:
            typedef T value_type;
            typedef value_type *pointer;
            typedef const value_type *const_pointer;
            typedef value_type &reference;
            typedef const value_type &const_reference;
            typedef std::size_t size_type;
            typedef std::ptrdiff_t difference_type;

            constexpr zallocator() noexcept = default;

            template<class U>
            constexpr zallocator(const zallocator<U> &other) noexcept {}

            pointer address(reference v) const { return &v; }

            const_pointer address(const_reference v) const { return &v; }

            pointer allocate(size_type n, const void *hint = 0) {
                if (n > std::numeric_limits<size_type>::max() / sizeof(T))
                    throw std::bad_alloc();
                return static_cast<pointer>(::operator new(n * sizeof(value_type)));
            }

            void deallocate(pointer p, size_type n) {
                std::fill_n((volatile char *) p, n * sizeof(T), 0);
                ::operator delete(p);
            }

            [[nodiscard]] size_type max_size() const {
                return std::numeric_limits<size_type>::max() / sizeof(T);
            }

            template<typename U>
            struct rebind {
                typedef zallocator<U> other;
            };

            void construct(pointer ptr, const T &val) {
                new (static_cast<T *>(ptr)) T(val);
            }

            void destroy(pointer ptr) {
                static_cast<T *>(ptr)->~T();
            }

            template<typename U>
            friend bool operator==(const zallocator<T> &a, const zallocator<U> &b) {
                return true;
            }

            template<typename U>
            friend bool operator!=(const zallocator<T> &a, const zallocator<U> &b) {
                return false;
            }

#if __cpluplus >= 201103L
            template<typename U, typename... Args>
            void construct(U *ptr, Args &&...args) {
                ::new (static_cast<void *>(ptr)) U(std::forward<Args>(args)...);
            }

            template<typename U>
            void destroy(U *ptr) {
                ptr->~U();
            }
#endif
        };

        template<class T>
        using basic_secure_vector = std::vector<T, zallocator<T>>;
        using basic_secure_wstring = std::basic_string<wchar_t, std::char_traits<wchar_t>, zallocator<wchar_t>>;
    }// namespace util

    template<typename T>
    class secure_vector : public util::basic_secure_vector<T> {
    public:
        using util::basic_secure_vector<T>::basic_secure_vector;

        secure_vector() : util::basic_secure_vector<T>() {}

        secure_vector(const std::vector<T> &vec) : util::basic_secure_vector<T>(vec.begin(), vec.end()) {}

        NODEMSPASSPORT_NODISCARD std::vector<T> to_vector() const {
            return std::vector<T>(this->begin(), this->end());
        }
    };

    class secure_wstring : public util::basic_secure_wstring {
    public:
        using util::basic_secure_wstring::basic_secure_wstring;

        secure_wstring() : util::basic_secure_wstring() {}

        secure_wstring(const std::wstring &str) : util::basic_secure_wstring(str.begin(), str.end()) {}

        secure_wstring(const std::string &str) : util::basic_secure_wstring(str.size() + 1, L' ') {
            size_t outSize;

            errno_t err = mbstowcs_s(&outSize, (wchar_t *) this->data(), this->size(), str.c_str(), str.size());
            if (err) perror("Error creating wide string");
            this->resize(outSize);
        }

        secure_wstring(const secure_vector<unsigned char> &data) : util::basic_secure_wstring(
                                                                           data.size() / sizeof(wchar_t),
                                                                           L' ') {
            bool ok = memcpy_s((wchar_t *) this->data(), this->size() * sizeof(wchar_t), data.data(), data.size()) == 0;
            if (!ok) this->resize(0);
        }

        NODEMSPASSPORT_NODISCARD std::wstring to_wstring() const {
            return std::wstring(this->begin(), this->end());
        }

        NODEMSPASSPORT_NODISCARD secure_vector<unsigned char> getBytes() const {
            secure_vector<unsigned char> tmp;
            tmp.resize(this->size() * sizeof(wchar_t));

            bool ok = memcpy_s(tmp.data(), tmp.size(), this->c_str(), this->size() * sizeof(wchar_t)) == 0;
            if (!ok) tmp.resize(0);

            return tmp;
        }

        NODEMSPASSPORT_NODISCARD inline std::string to_string() const {
            std::string out(this->size() + 1, ' ');
            size_t outSize;

            errno_t err = wcstombs_s(&outSize, (char *) out.data(), out.size(), this->c_str(), this->size());
            if (err) perror("Error creating string");
            out.resize(outSize);

            return out;
        }
    };
}

#endif //PASSPORT_UTIL_HPP