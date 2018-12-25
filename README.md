# dmd5

## Example

Just call `MD5Digest`:

```
uses
  dmd5;

...

var
  Data: PByte;
  Size: SizeUInt;
  Digest: TMD5Digest;

...

  // Compute MD5 digest of Size bytes at Data
  MD5Digest(Data, Size, Digest);
```

## MD5 of stream-like data

If the data is not stored as continuous memory block you can alternatively use  `MD5Init`, `MD5Update` and `MD5Final` (which are pascal implementations of functions from RFC-1321 with the same names).

```
var
  Context: TMD5Context;
  Digest: TMD5Digest;
begin
  MD5Init(Context);
  while {there is data} do begin
    // ... read next data block to memory
    // Pass next part of data
    MD5Update(Context, Data, Size);
  end;
  MD5Final(Context, Digest);
  // now Digest contains MD5 digest of the data
  // ...
end;
```

## Convert MD5 digest to string

```
function MD5DigestToString(const Digest: TMD5Digest): AnsiString;
var
  B: Byte;
begin
  Result := '';
  for B in Digest do
    Result := Result + LowerCase(HexStr(B, 2));
end;
```
