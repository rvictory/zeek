// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <vector>
#include <string>
#include <iosfwd>

#include <sys/types.h>

// Forward declaration, for helper functions that convert (sub)string vectors
// to and from policy-level representations.
//
ZEEK_FORWARD_DECLARE_NAMESPACED(VectorVal, zeek);

namespace zeek {

typedef u_char* byte_vec;

class String {
public:
	typedef std::vector<String*> Vec;
	typedef Vec::iterator VecIt;
	typedef Vec::const_iterator VecCIt;

	typedef std::vector<const String*> CVec;
	typedef Vec::iterator CVecIt;
	typedef Vec::const_iterator CVecCIt;

	// IdxVecs are vectors of indices of characters in a string.
	typedef std::vector<int> IdxVec;
	typedef IdxVec::iterator IdxVecIt;
	typedef IdxVec::const_iterator IdxVecCIt;

	// Constructors creating internal copies of the data passed in.
	String(const u_char* str, int arg_n, bool add_NUL);
	explicit String(const char* str);
	explicit String(const std::string& str);
	String(const String& bs);

	// Constructor that takes owernship of the vector passed in.
	String(bool arg_final_NUL, byte_vec str, int arg_n);

	String();
	~String()	{ Reset(); }

	const String& operator=(const String& bs);
	bool operator==(const String& bs) const;
	bool operator<(const String& bs) const;

	byte_vec Bytes() const	{ return b; }
	int Len() const	{ return n; }

	// Releases the string's current contents, if any, and
	// adopts the byte vector of given length.  The string will
	// manage the memory occupied by the string afterwards.
	//
	void Adopt(byte_vec bytes, int len);

	// Various flavors of methods that release the string's
	// current contents, if any, and then set the string's
	// contents to a copy of the string given by the arguments.
	//
	void Set(const u_char* str, int len, bool add_NUL=true);
	void Set(const char* str);
	void Set(const std::string& str);
	void Set(const String &str);

	void SetUseFreeToDelete(int use_it)
		{ use_free_to_delete = use_it; }

	const char* CheckString() const;

	enum render_style {
		ESC_NONE = 0,
		ESC_ESC  = (1 << 1),	// '\' -> "\\"
		ESC_QUOT = (1 << 2),	// '"' -> "\"", ''' -> "\'"
		ESC_HEX  = (1 << 3),	// Not in [32, 126]? -> "\xXX"
		ESC_DOT  = (1 << 4),	// Not in [32, 126]? -> "."

		// For serialization: '<string len> <string>'
		ESC_SER  = (1 << 7),
	};

	static constexpr int EXPANDED_STRING =	// the original style
		ESC_HEX;

	static constexpr int BRO_STRING_LITERAL =	// as in a Bro string literal
		ESC_ESC | ESC_QUOT | ESC_HEX;

	// Renders a string into a newly allocated character array that
	// you have to delete[].  You can combine the render styles given
	// above to achieve the representation you desire.  If you pass a
	// pointer to an integer as the final argument, you'll receive the
	// entire length of the resulting char* in it.
	//
	// Note that you need to delete[] the resulting string.
	//
	char* Render(int format = EXPANDED_STRING, int* len = nullptr) const;

	// Similar to the above, but useful for output streams.
	// Also more useful for debugging purposes since no deallocation
	// is required on your part here.
	//
	std::ostream& Render(std::ostream& os, int format = ESC_SER) const;

	// Reads a string from an input stream.  Unless you use a render
	// style combination that uses ESC_SER, note that the streams
	// will consider whitespace as a field delimiter.
	//
	std::istream& Read(std::istream& is, int format = ESC_SER);

	// XXX Fix redundancy: strings.bif implements both to_lower
	// XXX and to_upper; the latter doesn't use String::ToUpper().
	void ToUpper();

	unsigned int MemoryAllocation() const;

	// Returns new string containing the substring of this string,
	// starting at @start >= 0 for going up to @length elements,
	// A negative @length means "until end of string".  Other invalid
	// values result in a return value of 0.
	//
	String* GetSubstring(int start, int length) const;

	// Returns the start index of s in this string, counting from 0.
	// If s is not found, -1 is returned.
	//
	int FindSubstring(const String* s) const;

	// Splits the string into substrings, taking all the indices in
	// the given vector as cutting points.  The vector does not need
	// to be sorted, and can have multiple entries.  Out-of-bounds
	// indices are ignored.  All returned strings are newly allocated.
	//
	Vec* Split(const IdxVec& indices) const;

	// Helper functions for vectors:
	static zeek::VectorVal* VecToPolicy(Vec* vec);
	static Vec* VecFromPolicy(zeek::VectorVal* vec);
	static char* VecToString(const Vec* vec);

protected:
	void Reset();

	byte_vec b;
	int n;
	bool final_NUL;	// whether we have added a final NUL
	bool use_free_to_delete;	// free() vs. operator delete
};

// A comparison class that sorts pointers to String's according to
// the length of the pointed-to strings. Sort order can be specified
// through the constructor.
//
class StringLenCmp {
public:
	explicit StringLenCmp(bool increasing = true) { _increasing = increasing; }
	bool operator()(String*const& bst1, String*const& bst2);

 private:
	unsigned int _increasing;
};

// Default output stream operator, using rendering mode EXPANDED_STRING.
std::ostream& operator<<(std::ostream& os, const String& bs);

extern int Bstr_eq(const String* s1, const String* s2);
extern int Bstr_cmp(const String* s1, const String* s2);

// A data_chunk_t specifies a length-delimited constant string. It is
// often used for substrings of other String's to avoid memory copy,
// which would be necessary if String were used. Unlike String,
// the string should not be deallocated on destruction.
//
// "BroConstString" might be a better name here.

struct data_chunk_t {
	int length;
	const char* data;
};

extern String* concatenate(std::vector<data_chunk_t>& v);
extern String* concatenate(String::Vec& v);
extern String* concatenate(String::CVec& v);
extern void delete_strings(std::vector<const String*>& v);

} // namespace zeek

using BroString [[deprecated("Remove in v4.1. Use zeek::String instead.")]] = zeek::String;
using BroStringLenCmp [[deprecated("Remove in v4.1. Use zeek::StringLenCmp instead.")]] = zeek::StringLenCmp;
using byte_vec [[deprecated("Remove in v4.1. Use zeek::byte_vec instead.")]] = zeek::byte_vec;
using data_chunk_t [[deprecated("Remove in v4.1. Use zeek::data_chunk_t instead.")]] = zeek::data_chunk_t;
