#include "test_harness.h"

#include "sp/core/AddressSpace.h"

using namespace sp::core;

namespace {

AddressSpace make_space()
{
    std::vector<SectionRange> sections;

    SectionRange text;
    text.name = ".text";
    text.rva = 0x1000;
    text.virtual_size = 0x2000;
    text.raw_offset = 0x400;
    text.raw_size = 0x2000;
    text.executable = true;
    text.readable = true;
    sections.push_back(text);

    // Virtual size exceeds raw size: the tail has no bytes on disk.
    SectionRange data;
    data.name = ".data";
    data.rva = 0x4000;
    data.virtual_size = 0x2000;
    data.raw_offset = 0x2400;
    data.raw_size = 0x200;
    data.writable = true;
    data.readable = true;
    sections.push_back(data);

    return AddressSpace(0x140000000, std::move(sections));
}

} // namespace

void test_address_space()
{
    const AddressSpace space = make_space();

    SP_TEST("address space: va and rva round trip");
    {
        SP_CHECK_EQ(space.to_va(0x1000), VA{ 0x140001000 });
        SP_CHECK(space.to_rva(0x140001000).has_value());
        SP_CHECK_EQ(*space.to_rva(0x140001000), RVA{ 0x1000 });

        // Below the image base is not a valid address.
        SP_CHECK(!space.to_rva(0x1000).has_value());
    }

    SP_TEST("address space: section lookup");
    {
        const SectionRange* text = space.section_containing(0x140001500);
        SP_CHECK(text != nullptr && text->name == ".text");

        // Gap between sections is unmapped.
        SP_CHECK(space.section_containing(0x140003500) == nullptr);
        SP_CHECK(space.is_executable(0x140001000));
        SP_CHECK(!space.is_executable(0x140004000));
    }

    SP_TEST("address space: file offset absent for virtual-only tail");
    {
        SP_CHECK(space.to_file_offset(0x140001000).has_value());
        SP_CHECK_EQ(*space.to_file_offset(0x140001000), FileOffset{ 0x400 });

        // 0x4000 + 0x200 is past .data's raw size, so there are no bytes on disk.
        SP_CHECK(!space.to_file_offset(0x140004300).has_value());
    }
}
