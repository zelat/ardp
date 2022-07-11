//
// Created by tanchao on 2022/7/11.
//

#ifndef BASE_UTIL_SINGLETION_H_
#define BASE_UTIL_SINGLETION_H_

#include <memory>

namespace base {
    template<typename T>
    class Singleton {
    public:
        static T &instance();
        /**
         * Singletons should not be cloneable.
         */
        Singleton(const Singleton &) = delete;
        /**
         * Singletons should not be assignable.
         */
        Singleton &operator=(const Singleton) = delete;
    protected:
        Singleton() {}
    };
    /**
     * This is the static method that controls the access to the singleton
     * instance. On the first run, it creates a singleton object and places it
     * into the static field. On subsequent runs, it returns the client existing
     * object stored in the static field.
     */
    template<typename T>
    T &Singleton<T>::instance() {
        static const std::unique_ptr<T> instance{new T{}};
        return *instance;
    }
} // namespace base

#endif // BASE_UTIL_SINGLETION_H_
