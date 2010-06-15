#ifndef BOOST_VERSIONING_INCL
#define BOOST_VERSIONING_INCL

// This header stores workaround code for dealing with incompatible changes
// made to boost archive/serialization classes.


#if (BOOST_VERSION <= 104100)
// Easy case, boost archive serial numbers are sizeof(int)
BOOST_CLASS_VERSION(EncFSConfig, V6SubVersion)
#else
// starting with boost 1.42, serial numbers change to 8-bit.  However to make
// things tricker, the internal comparison is more like 16bit, which makes
// writing backward compatible code very tricky.

// We make a partial specialization of the iserializer class to remove the
// version number checking which would otherwise cause boost::serialization to
// throw an exception if it came across a version that was greater then what
// we specify in BOOST_CLASS_VERSION below.  Without this, manual editing
// of the file is needed before boost will allow us to read it.

// See bug http://code.google.com/p/encfs/issues/detail?id=60

BOOST_CLASS_VERSION(EncFSConfig, 20)


namespace boost {
namespace archive {
namespace detail {


// Specialize iserializer class in order to get rid of version check
template<class Archive>
class iserializer<Archive, EncFSConfig> : public basic_iserializer
{
private:
    virtual void destroy(/*const*/ void *address) const {
        boost::serialization::access::destroy(static_cast<EncFSConfig *>(address));
    }
protected:
    explicit iserializer() :
        basic_iserializer(
            boost::serialization::singleton<
                BOOST_DEDUCED_TYPENAME 
                boost::serialization::type_info_implementation<EncFSConfig>::type
            >::get_const_instance()
        )
    {}
public:
    virtual BOOST_DLLEXPORT void load_object_data(
        basic_iarchive & ar,
        void *x, 
        const unsigned int file_version
    ) const BOOST_USED;
    virtual bool class_info() const {
        return boost::serialization::implementation_level<EncFSConfig>::value 
            >= boost::serialization::object_class_info;
    }
    virtual bool tracking(const unsigned int /* flags */) const {
        return boost::serialization::tracking_level<EncFSConfig>::value 
                == boost::serialization::track_always
            || ( boost::serialization::tracking_level<EncFSConfig>::value 
                == boost::serialization::track_selectively
                && serialized_as_pointer());
    }
    virtual version_type version() const {
        return version_type(::boost::serialization::version<EncFSConfig>::value);
    }
    virtual bool is_polymorphic() const {
        return boost::is_polymorphic<EncFSConfig>::value;
    }
    virtual ~iserializer(){};
};

template<class Archive>
BOOST_DLLEXPORT void iserializer<Archive, EncFSConfig>::load_object_data(
    basic_iarchive & ar,
    void *x, 
    const unsigned int file_version
) const {
    boost::serialization::serialize_adl(
        boost::serialization::smart_cast_reference<Archive &>(ar),
        * static_cast<EncFSConfig *>(x), 
        file_version
    );
}

}
}
}

#endif



#endif // BOOST_VERSIONING_INCL
