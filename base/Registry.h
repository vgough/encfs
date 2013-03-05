#ifndef REGISTRY_H
#define REGISTRY_H

#include <list>
#include <map>
#include <string>

namespace encfs {

template <typename T>
class Registry
{
public:
  typedef T *(*FactoryFn)();
  struct Data {
    FactoryFn constructor;
    typename T::Properties properties;
  };

  void Register(const char *name,  FactoryFn fn,
                typename T::Properties properties)
  {
    Data d;
    d.constructor = fn;
    d.properties = properties;
    data[name] = d;
  }

  T* Create(const char *name)
  {
    auto it = data.find(name);
    if (it == data.end())
      return NULL;
    return (*it->second.constructor)();
  }

  T* CreateForMatch(const std::string &description)
  {
    for (auto &it : data) {
      auto name = it.second.properties.toString();
      if (!name.compare(0, description.size(), description))
        return (*it.second.constructor)();
    }
    return NULL;
  }

  std::list<std::string> GetAll() const {
    std::list<std::string> result;
    for (auto &it : data) {
      result.push_back(it.first);
    }
    return result;
  }

  const typename T::Properties *GetProperties(const char *name) const {
    auto it = data.find(name);
    if (it == data.end())
      return NULL;
    return &(it->second.properties);
  }
  
  const typename T::Properties *GetPropertiesForMatch(
      const std::string &description) const {
    for (auto &it : data) {
      auto name = it.second.properties.toString();
      if (!name.compare(0, description.size(), description))
        return &(it.second.properties);
    }
    return NULL;
  }


private:
  std::map<std::string, Data> data;
};

template <typename T, typename BASE>
class Registrar
{
public:
  Registrar(const char *name)
  {
    BASE::GetRegistry().Register(name,
                                 Registrar<T, BASE>::Construct,
                                 T::GetProperties());
  }

  static BASE *Construct() {
    return new T();
  }
};

#define DECLARE_REGISTERABLE_TYPE(TYPE) \
    static Registry<TYPE>& GetRegistry()

#define DEFINE_REGISTERABLE_TYPE(TYPE) \
    Registry<TYPE>& TYPE::GetRegistry() { \
      static Registry<TYPE> registry; \
      return registry; \
    }

#define REGISTER_CLASS(DERIVED, BASE) \
    static Registrar<DERIVED, BASE> registrar_ ## DERIVED ## _ ## BASE (#DERIVED)

}  // namespace encfs

#endif // REGISTRY_H
