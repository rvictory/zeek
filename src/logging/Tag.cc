// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

const logging::Tag logging::Tag::Error;

logging::Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(log_mgr->GetTagType(), type, subtype)
	{
	}

logging::Tag& logging::Tag::operator=(const logging::Tag& other)
	{
	::Tag::operator=(other);
	return *this;
	}

logging::Tag& logging::Tag::operator=(const logging::Tag&& other) noexcept
	{
	::Tag::operator=(other);
	return *this;
	}

const zeek::EnumValPtr& logging::Tag::AsVal() const
	{
	return ::Tag::AsVal(log_mgr->GetTagType());
	}

zeek::EnumVal* logging::Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

logging::Tag::Tag(zeek::EnumValPtr val)
	: ::Tag(std::move(val))
	{ }

logging::Tag::Tag(zeek::EnumVal* val)
	: ::Tag({zeek::NewRef{}, val})
	{ }
