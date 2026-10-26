# the filter cache on disk

three files. `cf.filters` holds the filters, `cf.filters.idx` is an offset array
so a height maps to a byte range by arithmetic, and `cf.filters.fh` is the
filter header the producer verified. the first is not koinu's invention and the
other two are.

## cf.filters

a 4-byte tag `KWF1` (`4b574631`), then one record per block in height order:

    32 bytes      block hash, internal byte order
    CompactSize   filter length
    n bytes       the BIP158 basic filter

after the tag that is byte for byte dogecoin core's block filter index, which
writes `fltr?????.dat` under `indexes/blockfilter/basic/`. core's writer is one
line, `blockfilterindex.cpp`:

    fileout << filter.GetBlockHash() << filter.GetEncodedFilter();

`GetBlockHash()` is a uint256, so 32 raw bytes, and `GetEncodedFilter()` is a
`std::vector<unsigned char>`, which serializes as CompactSize then the bytes.
koinu reads and writes exactly that.

checked against a real one rather than inferred from the source. `fltr00000.dat`
from a node running the bip157/158 backport, against this cache with the tag
dropped:

    Core fltr00000.dat          |  koinu cf.filters (tag stripped)
    1a91e3dace36e2be3b   4b  |  82bc68038f6034c059   4b
    82bc68038f6034c059   4b  |  ea5380659e02a68c07   4b
    ea5380659e02a68c07   4b  |  76f80a8a81e6f6669d   4b

    compared 14894 records: 14894 identical, 0 differing

the one-record stagger is the whole difference in coverage: core indexes from
genesis and koinu's first record is height 1.

three things still differ at the file level and none of them touch a record.
core splits at 16 MiB (`MAX_FLTR_FILE_SIZE`) across a numbered sequence where
koinu uses one file, core finds a filter through a leveldb index where koinu
uses the flat `.idx` below, and koinu puts a 4-byte tag in front.

so a node operator's `fltr?????.dat` concatenated in order is a koinu cache
missing its tag, and a koinu cache with the first four bytes removed is a core
record stream. nothing has to be converted, and that is the point: the filters
themselves are BIP158 and the container is core's.

one caveat on concatenating. core pre-allocates in 1 MiB chunks and truncates a
file only when it rolls over to the next, so every file but the last ends on a
record boundary and the last one does not. on the node this was read from, the
last file is `fltr00115.dat`:

    size 6291456, trailing zeros: 436931
    30387 whole records, ending at byte 5854511; 436945 bytes of pre-allocation after

note the two numbers disagree by 14. there are non-zero bytes past the last
whole record, so trimming at the last non-zero byte is wrong and leaves a
fragment that parses as a 32-byte hash and a nonsense length. parse forward and
cut after the last record that is entirely present.

## cf.filters.idx

8-byte record count, little endian, then one little-endian uint64 per record
holding that record's byte offset into `cf.filters`. so

    idx offset for height h = 8 + (h - base) * 8

and reading two of them gives the byte span of everything between. that is what
lets a cache sit on object storage and be sliced with range requests and no
server logic, which is `tools/cfpull.sh`. core has no equivalent because it
never needed one: a leveldb index answers the same question locally and cannot
be range-requested over https.

the index is derived and is rebuilt from the cache whenever it is missing or
does not match, so it is never authoritative and losing it costs only a pass.

## cf.filters.fh

the producer's verified tip, so a later delta sync cannot have history quietly
rewritten under it. two versions, told apart by the tag.

    KWFH   4 + 8 + 32 = 44      tag, record count (8 LE), filter header
    KWFI   4 + 8 + 32 + 32 = 76 the same, then the chain base

the base is the filter header of the block *before* the first cached filter.
written because the first sync is the only moment it is known, and without it a
cache that has to drop a reorganised tail cannot work out what its new tip's
header is, which left deleting the whole file as the only answer.

koinu refuses a cache it cannot tie to a verified chain, so the sidecar is
required rather than an optimisation, and a slice pulled with `cfpull.sh`
arrives without one. `kw cfbase` writes it:

    tools/cfpull.sh <BASE_URL> 6400001 150 slice.filters
    kw cfbase --filters slice.filters --filters-base 6400001

the base it records is the compiled-in anchor at 6400000, not anything the
mirror said, which is the whole reason the height is constrained: a slice
starting one block after an anchor hangs from a header the binary already
carries, and one starting anywhere else hangs from nothing and is refused.

    kw: this release carries no filter anchor at height 6400049, so a slice
        starting at 6400050 has nothing to hang from.
    kw: the nearest usable --filters-base is 6400001

writing the sidecar does not make the filters true. it records the chain the
bytes on disk produce, and what tests them is the check below.

## checking any of this yourself

the cache is not trusted because of where it came from. check it against the
anchors the release compiles in:

    kwd --filters cf.filters --socket SOCK --node HOST
    kw cfcheck --daemon SOCK --since 6400000 --with-filters

which walks the filters up from the anchor below and refuses the first one that
does not reproduce its own header.
