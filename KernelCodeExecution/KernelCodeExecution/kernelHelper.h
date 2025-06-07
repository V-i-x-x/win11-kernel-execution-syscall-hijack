#pragma once
#define ASSERT_SZ( x, y ) static_assert(sizeof(x) == y, "incorrect size for " #x);