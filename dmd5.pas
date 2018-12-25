// RFC-1321 https://www.ietf.org/rfc/rfc1321.txt
{$MODE FPC}
{$MODESWITCH OUT}
{$MODESWITCH RESULT}
unit dmd5;

interface

//
//  MD5Digest
//
//      Computes MD5 digest of the data.
//
//  Parameters:
//
//      Data: start of input data, may be nil
//      Size: size of input data
//      DataEnd: end of data, that is DataEnd-Data=Size
//
//  Returns:
//
//      Digest: MD5 digest of the data
//
type
  TMD5Digest = array[0 .. 16 - 1] of Byte;
procedure MD5Digest(Data: PByte; Size: SizeUInt; var Digest: TMD5Digest);
procedure MD5Digest(Data, DataEnd: PByte; var Digest: TMD5Digest);

//
//  MD5Init
//
//      Initializes Context variable.
//
//  MD5Update
//
//      Consumes next part of data.
//
//  MD5Final
//
//      Finalizes Context variable and returns MD5 digest of data consumed by
//      MD5Update.
//
//  Usage:
//
//      Computes MD5 digest of stream-like data. Semantics of these functions
//      are equivalent to those defined in RFC-1321.
//
//      Typical use:
//
//      var
//        Context: TMD5Context;
//        Digest: TMD5Digest;
//      begin
//        MD5Init(Context);
//        while {there is data} do begin
//          // ... read next data block to memory
//          // Pass next part of data
//          MD5Update(Context, Data, Size);
//        end;
//        MD5Final(Context, Digest);
//        // now Digest contains MD5 digest of the data
//        // ...
//      end;
//
type
  TMD5Context = record
    State: array[0 .. 4 - 1] of Cardinal; // state (ABCD)
    Count: QWord; // number of bits, modulo 2^64, lsb 1st
    Buffer: array[0 .. 64 - 1] of Byte;   // input buffer
  end;
procedure MD5Init(out Context: TMD5Context);
procedure MD5Update(var Context: TMD5Context; Data: PByte; Size: SizeUInt);
procedure MD5Update(var Context: TMD5Context; Data, DataEnd: PByte);
procedure MD5Final(var Context: TMD5Context; out Digest: TMD5Digest);

implementation

type
  TMD5State = array[0 .. 3] of Cardinal;
  PMD5State = ^TMD5State;

function AuxF(X, Y, Z: Cardinal): Cardinal; inline;
begin
  Result := (X and Y) or ((not X) and Z);
end;

function AuxG(X, Y, Z: Cardinal): Cardinal; inline;
begin
  Result := (X and Z) or (Y and not Z);
end;

function AuxH(X, Y, Z: Cardinal): Cardinal; inline;
begin
  Result := X xor Y xor Z;
end;

function AuxI(X, Y, Z: Cardinal): Cardinal; inline;
begin
  Result := Y xor (X or not Z);
end;

//
//  RotateLeft
//
//      Circularly shifting X left by S bit positions
//
function RotateLeft(X: Cardinal; S: Byte): Cardinal; inline;
begin
  Result := (X shl S) or (X shr (32 - S));
end;

const
  T: array[0..63] of Cardinal = (
    $D76AA478, $E8C7B756, $242070DB, $C1BDCEEE,
    $F57C0FAF, $4787C62A, $A8304613, $FD469501,
    $698098D8, $8B44F7AF, $FFFF5BB1, $895CD7BE,
    $6B901122, $FD987193, $A679438E, $49B40821,
    $F61E2562, $C040B340, $265E5A51, $E9B6C7AA,
    $D62F105D, $02441453, $D8A1E681, $E7D3FBC8,
    $21E1CDE6, $C33707D6, $F4D50D87, $455A14ED,
    $A9E3E905, $FCEFA3F8, $676F02D9, $8D2A4C8A,
    $FFFA3942, $8771F681, $6D9D6122, $FDE5380C,
    $A4BEEA44, $4BDECFA9, $F6BB4B60, $BEBFBC70,
    $289B7EC6, $EAA127FA, $D4EF3085, $04881D05,
    $D9D4D039, $E6DB99E5, $1FA27CF8, $C4AC5665,
    $F4292244, $432AFF97, $AB9423A7, $FC93A039,
    $655B59C3, $8F0CCC92, $FFEFF47D, $85845DD1,
    $6FA87E4F, $FE2CE6E0, $A3014314, $4E0811A1,
    $F7537E82, $BD3AF235, $2AD7D2BB, $EB86D391
  );
procedure MD5Transform(Block: PByte; var State: TMD5State);
var
  I: Cardinal;
  Saved: TMD5State;
begin
  // Save State
  Saved := State;
  // Round 1
  for I := 0 to 3 do begin
    State[0] := State[1] + RotateLeft(State[0] + AuxF(State[1], State[2], State[3]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[I * 4 + 0] + T[I * 4 + 0]), 7);
    State[3] := State[0] + RotateLeft(State[3] + AuxF(State[0], State[1], State[2]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[I * 4 + 1] + T[I * 4 + 1]), 12);
    State[2] := State[3] + RotateLeft(State[2] + AuxF(State[3], State[0], State[1]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[I * 4 + 2] + T[I * 4 + 2]), 17);
    State[1] := State[2] + RotateLeft(State[1] + AuxF(State[2], State[3], State[0]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[I * 4 + 3] + T[I * 4 + 3]), 22);
  end;
  // Round 2
  for I := 0 to 3 do begin
    State[0] := State[1] + RotateLeft(State[0] + AuxG(State[1], State[2], State[3]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 20 + 1)  and 15] + T[16 + I * 4 + 0]), 5);
    State[3] := State[0] + RotateLeft(State[3] + AuxG(State[0], State[1], State[2]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 20 + 6)  and 15] + T[16 + I * 4 + 1]), 9);
    State[2] := State[3] + RotateLeft(State[2] + AuxG(State[3], State[0], State[1]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 20 + 11) and 15] + T[16 + I * 4 + 2]), 14);
    State[1] := State[2] + RotateLeft(State[1] + AuxG(State[2], State[3], State[0]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 20 + 16) and 15] + T[16 + I * 4 + 3]), 20);
  end;
  // Round 3
  for I := 0 to 3 do begin
    State[0] := State[1] + RotateLeft(State[0] + AuxH(State[1], State[2], State[3]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 12 + 5)  and 15] + T[32 + I * 4 + 0]), 4);
    State[3] := State[0] + RotateLeft(State[3] + AuxH(State[0], State[1], State[2]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 12 + 8)  and 15] + T[32 + I * 4 + 1]), 11);
    State[2] := State[3] + RotateLeft(State[2] + AuxH(State[3], State[0], State[1]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 12 + 11) and 15] + T[32 + I * 4 + 2]), 16);
    State[1] := State[2] + RotateLeft(State[1] + AuxH(State[2], State[3], State[0]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 12 + 14) and 15] + T[32 + I * 4 + 3]), 23);
  end;
  // Round 4
  for I := 0 to 3 do begin
    State[0] := State[1] + RotateLeft(State[0] + AuxI(State[1], State[2], State[3]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 28 + 0)  and 15] + T[48 + I * 4 + 0]), 6);
    State[3] := State[0] + RotateLeft(State[3] + AuxI(State[0], State[1], State[2]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 28 + 7)  and 15] + T[48 + I * 4 + 1]), 10);
    State[2] := State[3] + RotateLeft(State[2] + AuxI(State[3], State[0], State[1]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 28 + 14) and 15] + T[48 + I * 4 + 2]), 15);
    State[1] := State[2] + RotateLeft(State[1] + AuxI(State[2], State[3], State[0]) + {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(PCardinal(Block)[(I * 28 + 21) and 15] + T[48 + I * 4 + 3]), 21);
  end;
  // Increment each registers by the value it had before this block was started
  Inc(State[0], Saved[0]);
  Inc(State[1], Saved[1]);
  Inc(State[2], Saved[2]);
  Inc(State[3], Saved[3]);
end;

procedure MD5Init_(out State: TMD5State);
begin
  // Load magic initialization constants.
  State[0] := $67452301;
  State[1] := $efcdab89;
  State[2] := $98badcfe;
  State[3] := $10325476;
end;

procedure MD5Final_(Block: PByte;
                    Rest: SizeUInt;
                    var Digest: TMD5Digest;
                    Bits: QWord);
begin
  Block[Rest] := $80;
  if Rest < 56 then begin
    FillChar(Block[Rest + 1], 55 - Rest, 0);
  end else begin
    FillChar(Block[Rest + 1], 63 - Rest, 0);
    MD5Transform(@Block[0], TMD5State(Digest));
    FillChar(Block[0], 56, 0);
  end;
  // number of bits
  PCardinal(@Block[0])[14] := {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}(Bits and $FFFFFFFF);
  PCardinal(@Block[0])[15] := {$IFDEF ENDIAN_BIG}SwapEndian{$ENDIF}((Bits shr 32) and $FFFFFFFF);
  MD5Transform(@Block[0], TMD5State(Digest));
  {$IFDEF ENDIAN_BIG}
  TMD5State(Digest)[0] := SwapEndian(TMD5State(Digest)[0]);
  TMD5State(Digest)[1] := SwapEndian(TMD5State(Digest)[1]);
  TMD5State(Digest)[2] := SwapEndian(TMD5State(Digest)[2]);
  TMD5State(Digest)[3] := SwapEndian(TMD5State(Digest)[3]);
  {$ENDIF}
end;

procedure MD5Digest(Data, DataEnd: PByte; var Digest: TMD5Digest);
var
  Len: SizeUInt;
  Temp: array[0 .. 64 - 1] of Byte;
begin
  if Data = nil then
    DataEnd := nil;
  Len := DataEnd - Data;
  MD5Init_(TMD5State(Digest));
  while Data + 64 < DataEnd do begin
    MD5Transform(Data, TMD5State(Digest));
    Inc(Data, 64);
  end;
  if Data <> nil then
    Move(Data^, Temp[0], DataEnd - Data);
  MD5Final_(@Temp[0], DataEnd - Data, Digest, Len shl 3);
  // Zeroize sensitive information.
  Len := 0;
  FillChar(Temp[0], SizeOf(Temp), 0);
end;

procedure MD5Digest(Data: PByte; Size: SizeUInt; var Digest: TMD5Digest);
begin
  MD5Digest(Data, Data + Size, Digest);
end;

procedure MD5Init(out Context: TMD5Context);
begin
  MD5Init_(TMD5State(Context.State));
  Context.Count := 0;
end;

procedure MD5Update(var Context: TMD5Context; Data, DataEnd: PByte);
begin
  MD5Update(Context, Data, DataEnd - Data);
end;

procedure MD5Update(var Context: TMD5Context; Data: PByte; Size: SizeUInt);
var
  I, Index, PartLen: Cardinal;
begin
  Index := (Context.Count shr 3) and $3F;
  Inc(Context.Count, Size shl 3);
  PartLen := 64 - Index;
  if Size >= PartLen then begin
    Move(Data^, Context.Buffer[Index], PartLen);
    MD5Transform(@Context.Buffer[0], TMD5State(Context.State));
    I := PartLen;
    while I + 63 < Size do begin
      MD5Transform(@Data[I], TMD5State(Context.State));
      Inc(I, 64);
    end;
    Index := 0;
  end else
    I := 0;
  Move(Data[I], Context.Buffer[Index], Size - I);
end;

procedure MD5Final(var Context: TMD5Context; out Digest: TMD5Digest);
begin
  Digest := TMD5Digest(Context.State);
  MD5Final_(@Context.Buffer[0], (Context.Count shr 3) and $3F, Digest, Context.Count);
  // Zeroize sensitive information.
  FillChar(Context, SizeOf(Context), 0);
end;

end.
